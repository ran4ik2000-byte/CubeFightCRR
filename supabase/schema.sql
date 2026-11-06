-- CUBEFIGHT account storage and friends.
-- Run in the Supabase SQL Editor as the project owner.

-- Disable the removed gifting feature in projects that used the previous schema.
drop function if exists public.cf_gift(text,text,text,integer);
drop table if exists public.cf_gift_catalog;

create table if not exists public.cf_player_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  friend_code text not null unique check (friend_code ~ '^[A-HJ-NP-Z2-9]{8}$'),
  display_name text not null default '',
  display_name_changed_at timestamptz,
  save_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.cf_player_profiles
  add column if not exists display_name_changed_at timestamptz;

-- Keep nicknames case-insensitively unique; preserve the oldest name if old rows collide.
with ranked_names as (
  select user_id, row_number() over (partition by lower(display_name) order by created_at, user_id) as rn
  from public.cf_player_profiles
  where display_name <> ''
)
update public.cf_player_profiles p set display_name=''
from ranked_names r where p.user_id=r.user_id and r.rn>1;
create unique index if not exists cf_player_profiles_display_name_ci_uidx
  on public.cf_player_profiles (lower(display_name)) where display_name <> '';

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
declare
  v_display_name text := btrim(coalesce(new.raw_user_meta_data->>'display_name',''));
begin
  if v_display_name !~ '^[[:alnum:]_-]{3,8}$' then
    raise exception 'NICKNAME_INVALID: use 3-8 letters, digits, _ or -.' using errcode='23514';
  end if;
  insert into public.cf_player_profiles(user_id,friend_code,display_name)
  values(new.id,public.cf_generate_friend_code(),v_display_name)
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
grant select(user_id,friend_code,display_name,save_data) on public.cf_player_profiles to authenticated;
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

create or replace function public.cf_change_display_name(p_new_name text)
returns jsonb
language plpgsql
volatile
security definer
set search_path = public, pg_temp
as $$
declare
  v_user uuid := auth.uid();
  v_profile public.cf_player_profiles%rowtype;
  v_new_name text := btrim(coalesce(p_new_name,''));
  v_next_change timestamptz;
begin
  if v_user is null then raise exception 'AUTH_REQUIRED'; end if;
  if v_new_name !~ '^[[:alnum:]_-]{3,8}$' then raise exception 'NICKNAME_INVALID'; end if;
  select * into v_profile from public.cf_player_profiles where user_id=v_user for update;
  if not found then raise exception 'PROFILE_NOT_FOUND'; end if;
  if lower(v_profile.display_name)=lower(v_new_name) then raise exception 'NICKNAME_UNCHANGED'; end if;
  if v_profile.display_name_changed_at is not null then
    v_next_change := v_profile.display_name_changed_at + interval '3 days';
    if now() < v_next_change then raise exception 'NICKNAME_COOLDOWN'; end if;
  end if;
  begin
    update public.cf_player_profiles
       set display_name=v_new_name, display_name_changed_at=now(), updated_at=now()
     where user_id=v_user;
  exception when unique_violation then
    raise exception 'NICKNAME_TAKEN' using errcode='23505';
  end;
  return jsonb_build_object('display_name',v_new_name,'next_change_at',now()+interval '3 days');
end;
$$;

create or replace function public.cf_leaderboard()
returns table(rank bigint,nickname text,waves integer,coins integer,play_time_seconds bigint)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select row_number() over (
           order by scores.waves desc, scores.coins desc, scores.play_time_seconds desc,
                    scores.nickname asc, scores.user_id asc
         ) as rank,
         scores.nickname, scores.waves, scores.coins, scores.play_time_seconds
  from (
    select p.user_id,
           coalesce(nullif(p.display_name,''),'P'||left(p.friend_code,7)) as nickname,
           case when p.save_data->>'cf_best' ~ '^[0-9]{1,9}$' then (p.save_data->>'cf_best')::integer else 0 end as waves,
           case when p.save_data->'cf'->>'coins' ~ '^[0-9]{1,9}$' then (p.save_data->'cf'->>'coins')::integer else 0 end as coins,
           case when p.save_data->>'cf_playtime_seconds' ~ '^[0-9]{1,12}$' then (p.save_data->>'cf_playtime_seconds')::bigint else 0 end as play_time_seconds
    from public.cf_player_profiles p
  ) scores;
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
revoke all on function public.cf_leaderboard() from public,anon;
revoke all on function public.cf_change_display_name(text) from public,anon;
revoke all on function public.cf_add_friend_by_code(text) from public,anon;
revoke all on function public.cf_remove_friend_by_code(text) from public,anon;
grant execute on function public.cf_list_friends() to authenticated;
grant execute on function public.cf_leaderboard() to authenticated;
grant execute on function public.cf_change_display_name(text) to authenticated;
grant execute on function public.cf_add_friend_by_code(text) to authenticated;
grant execute on function public.cf_remove_friend_by_code(text) to authenticated;
