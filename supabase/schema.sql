-- CUBEFIGHT account storage and friends.
-- Run in the Supabase SQL Editor as the project owner.

-- Disable the removed gifting feature in projects that used the previous schema.
drop function if exists public.cf_gift(text,text,text,integer);
drop table if exists public.cf_gift_catalog;

create table if not exists public.cf_player_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  friend_code text not null unique check (friend_code ~ '^[A-HJ-NP-Z2-9]{8}$'),
  display_name text not null default '',
  save_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.cf_friendships (
  user_id uuid not null references public.cf_player_profiles(user_id) on delete cascade,
  friend_id uuid not null references public.cf_player_profiles(user_id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, friend_id),
  constraint cf_friendships_no_self check (user_id <> friend_id)
);


create or replace function public.cf_generate_friend_code()
returns text
language plpgsql
volatile
security definer
set search_path = public, pg_temp
as $$
declare
  v_alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  v_code text;
  v_bytes bytea;
  i integer;
begin
  loop
    v_bytes := decode(substr(replace(gen_random_uuid()::text,'-',''),1,10),'hex');
    v_code := '';
    for i in 0..4 loop
      v_code := v_code || substr(v_alphabet,(get_byte(v_bytes,i) % 32)+1,1);
    end loop;
    -- Two more independently random characters make an 8-character, 40-bit code.
    v_bytes := decode(substr(replace(gen_random_uuid()::text,'-',''),1,6),'hex');
    v_code := v_code || substr(v_alphabet,(get_byte(v_bytes,0) % 32)+1,1)
                     || substr(v_alphabet,(get_byte(v_bytes,1) % 32)+1,1)
                     || substr(v_alphabet,(get_byte(v_bytes,2) % 32)+1,1);
    exit when not exists(select 1 from public.cf_player_profiles p where p.friend_code=v_code);
  end loop;
  return v_code;
end;
$$;

create or replace function public.cf_require_gmail()
returns trigger
language plpgsql
security definer
set search_path = auth, pg_temp
as $$
begin
  if new.email is null or lower(new.email) !~ '^[^@[:space:]]+@gmail\.com$' then
    raise exception 'CUBEFIGHT accounts require a @gmail.com address.' using errcode='23514';
  end if;
  return new;
end;
$$;

drop trigger if exists cf_require_gmail_before_write on auth.users;
create trigger cf_require_gmail_before_write
before insert or update of email on auth.users
for each row execute function public.cf_require_gmail();

create or replace function public.cf_create_profile_for_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  insert into public.cf_player_profiles(user_id,friend_code)
  values(new.id,public.cf_generate_friend_code())
  on conflict(user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists cf_create_profile_after_signup on auth.users;
create trigger cf_create_profile_after_signup
after insert on auth.users
for each row execute function public.cf_create_profile_for_user();

-- Backfill Gmail users who were already registered before this schema was installed.
insert into public.cf_player_profiles(user_id,friend_code)
select u.id,public.cf_generate_friend_code()
from auth.users u
where u.email is not null
  and lower(u.email) ~ '^[^@[:space:]]+@gmail\.com$'
  and not exists(select 1 from public.cf_player_profiles p where p.user_id=u.id)
on conflict(user_id) do nothing;

alter table public.cf_player_profiles enable row level security;
alter table public.cf_friendships enable row level security;

drop policy if exists cf_profile_read_own on public.cf_player_profiles;
create policy cf_profile_read_own on public.cf_player_profiles
for select to authenticated using (user_id=auth.uid());

drop policy if exists cf_profile_update_own on public.cf_player_profiles;
create policy cf_profile_update_own on public.cf_player_profiles
for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());

-- Clients can read their own profile and update only the save JSON, never the code or owner ID.
revoke all on public.cf_player_profiles from anon, authenticated;
grant select(user_id,friend_code,save_data) on public.cf_player_profiles to authenticated;
grant update(save_data) on public.cf_player_profiles to authenticated;
revoke all on public.cf_friendships from anon, authenticated;

create or replace function public.cf_list_friends()
returns table(friend_code text,display_name text)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select p.friend_code,
         coalesce(nullif(p.display_name,''),nullif(p.save_data->>'cf_name',''),'Друг') as display_name
  from public.cf_friendships f
  join public.cf_player_profiles p on p.user_id=f.friend_id
  where f.user_id=auth.uid()
  order by display_name,p.friend_code;
$$;

create or replace function public.cf_add_friend_by_code(p_friend_code text)
returns table(friend_code text,display_name text)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_me uuid := auth.uid();
  v_friend uuid;
begin
  if v_me is null then raise exception 'AUTH_REQUIRED'; end if;
  if p_friend_code is null or upper(trim(p_friend_code)) !~ '^[A-HJ-NP-Z2-9]{8}$' then
    raise exception 'INVALID_FRIEND_CODE';
  end if;
  select p.user_id into v_friend from public.cf_player_profiles p
   where p.friend_code=upper(trim(p_friend_code));
  if v_friend is null then raise exception 'FRIEND_NOT_FOUND'; end if;
  if v_friend=v_me then raise exception 'CANNOT_ADD_SELF'; end if;
  if (select count(*) from public.cf_friendships f where f.user_id=v_me)>=100 then
    raise exception 'FRIEND_LIMIT_REACHED';
  end if;
  insert into public.cf_friendships(user_id,friend_id) values(v_me,v_friend) on conflict do nothing;
  insert into public.cf_friendships(user_id,friend_id) values(v_friend,v_me) on conflict do nothing;
  return query
    select p.friend_code,coalesce(nullif(p.display_name,''),nullif(p.save_data->>'cf_name',''),'Друг')
    from public.cf_player_profiles p where p.user_id=v_friend;
end;
$$;

create or replace function public.cf_remove_friend_by_code(p_friend_code text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_me uuid := auth.uid();
  v_friend uuid;
begin
  if v_me is null then raise exception 'AUTH_REQUIRED'; end if;
  select p.user_id into v_friend from public.cf_player_profiles p
   where p.friend_code=upper(trim(p_friend_code));
  if v_friend is null then return false; end if;
  delete from public.cf_friendships where (user_id=v_me and friend_id=v_friend) or (user_id=v_friend and friend_id=v_me);
  return true;
end;
$$;


revoke all on function public.cf_generate_friend_code() from public,anon,authenticated;
revoke all on function public.cf_require_gmail() from public,anon,authenticated;
revoke all on function public.cf_create_profile_for_user() from public,anon,authenticated;
revoke all on function public.cf_list_friends() from public,anon;
revoke all on function public.cf_add_friend_by_code(text) from public,anon;
revoke all on function public.cf_remove_friend_by_code(text) from public,anon;
grant execute on function public.cf_list_friends() to authenticated;
grant execute on function public.cf_add_friend_by_code(text) to authenticated;
grant execute on function public.cf_remove_friend_by_code(text) to authenticated;
