-- CUBEFIGHT account storage and safe friend transfers.
-- Run once in the Supabase SQL Editor as the project owner.

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

create table if not exists public.cf_gift_catalog (
  item_id text primary key,
  category text not null check (category in ('gear','food','util')),
  bucket text not null
);

-- Current game equipment identifiers: swords w1-w102 and armor a1-a15.
-- The starting wooden sword s0 is deliberately not giftable.
insert into public.cf_gift_catalog(item_id,category,bucket)
select 'w'||n,'gear','own' from generate_series(1,102) as n
union all
select 'a'||n,'gear','own' from generate_series(1,15) as n
union all
select 'f'||n,'food','fd' from generate_series(1,16) as n
union all
select 'pearl','util','pl'
union all select 'bomb','util','bm'
union all select 'orb','util','ob'
union all select 'heal','util','hl'
union all select 'fire','util','rg'
union all select 'scroll','util','sc'
union all select 'time','util','ts'
union all select 'dome','util','dm'
on conflict (item_id) do update set category=excluded.category,bucket=excluded.bucket;

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
alter table public.cf_gift_catalog enable row level security;

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
revoke all on public.cf_gift_catalog from anon, authenticated;

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

create or replace function public.cf_gift(p_friend_code text,p_kind text,p_item_id text,p_amount integer)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_me uuid := auth.uid();
  v_friend uuid;
  v_kind text := lower(coalesce(p_kind,''));
  v_bucket text;
  v_category text;
  v_src_data jsonb;
  v_dst_data jsonb;
  v_src_game jsonb;
  v_dst_game jsonb;
  v_src_container jsonb;
  v_dst_container jsonb;
  v_src_qty integer;
  v_dst_qty integer;
begin
  if v_me is null then raise exception 'AUTH_REQUIRED'; end if;
  if p_amount is null or p_amount<1 or p_amount>1000000 then raise exception 'INVALID_AMOUNT'; end if;
  select p.user_id into v_friend from public.cf_player_profiles p
   where p.friend_code=upper(trim(p_friend_code));
  if v_friend is null then raise exception 'FRIEND_NOT_FOUND'; end if;
  if v_friend=v_me then raise exception 'CANNOT_GIFT_SELF'; end if;
  if not exists(select 1 from public.cf_friendships f where f.user_id=v_me and f.friend_id=v_friend) then
    raise exception 'NOT_FRIENDS';
  end if;
  -- Lock both account rows in deterministic order so simultaneous gifts cannot duplicate balances.
  perform p.user_id from public.cf_player_profiles p
   where p.user_id in (v_me,v_friend) order by p.user_id for update;
  select p.save_data into v_src_data from public.cf_player_profiles p where p.user_id=v_me;
  select p.save_data into v_dst_data from public.cf_player_profiles p where p.user_id=v_friend;
  v_src_data:=coalesce(v_src_data,'{}'::jsonb);v_dst_data:=coalesce(v_dst_data,'{}'::jsonb);
  v_src_game:=coalesce(v_src_data->'cf','{}'::jsonb);v_dst_game:=coalesce(v_dst_data->'cf','{}'::jsonb);

  if v_kind='coins' then
    v_src_qty:=coalesce(nullif(v_src_game->>'coins','')::integer,0);
    v_dst_qty:=coalesce(nullif(v_dst_game->>'coins','')::integer,0);
    if v_src_qty<p_amount then raise exception 'NOT_ENOUGH_COINS'; end if;
    if v_dst_qty>2147483647-p_amount then raise exception 'BALANCE_LIMIT'; end if;
    v_src_game:=jsonb_set(v_src_game,'{coins}',to_jsonb(v_src_qty-p_amount),true);
    v_dst_game:=jsonb_set(v_dst_game,'{coins}',to_jsonb(v_dst_qty+p_amount),true);
  elsif v_kind='item' then
    select c.category,c.bucket into v_category,v_bucket from public.cf_gift_catalog c where c.item_id=p_item_id;
    if v_bucket is null then raise exception 'ITEM_NOT_GIFTABLE'; end if;
    if v_category='gear' and (v_src_game->>'eq'=p_item_id or v_src_game->>'ea'=p_item_id or v_src_game->>'e2'=p_item_id) then
      raise exception 'UNEQUIP_ITEM_FIRST';
    end if;
    if v_category in ('gear','food') then
      v_src_container:=coalesce(v_src_game->v_bucket,'{}'::jsonb);
      v_dst_container:=coalesce(v_dst_game->v_bucket,'{}'::jsonb);
      v_src_qty:=coalesce(nullif(v_src_container->>p_item_id,'')::integer,0);
      v_dst_qty:=coalesce(nullif(v_dst_container->>p_item_id,'')::integer,0);
      if v_src_qty<p_amount then raise exception 'NOT_ENOUGH_ITEMS'; end if;
      if v_dst_qty>1000000-p_amount then raise exception 'ITEM_LIMIT'; end if;
      if v_src_qty=p_amount then v_src_container:=v_src_container-p_item_id;
      else v_src_container:=jsonb_set(v_src_container,array[p_item_id],to_jsonb(v_src_qty-p_amount),true); end if;
      v_dst_container:=jsonb_set(v_dst_container,array[p_item_id],to_jsonb(v_dst_qty+p_amount),true);
      v_src_game:=jsonb_set(v_src_game,array[v_bucket],v_src_container,true);
      v_dst_game:=jsonb_set(v_dst_game,array[v_bucket],v_dst_container,true);
    else
      v_src_qty:=coalesce(nullif(v_src_game->>v_bucket,'')::integer,0);
      v_dst_qty:=coalesce(nullif(v_dst_game->>v_bucket,'')::integer,0);
      if v_src_qty<p_amount then raise exception 'NOT_ENOUGH_ITEMS'; end if;
      if v_dst_qty>1000000-p_amount then raise exception 'ITEM_LIMIT'; end if;
      v_src_game:=jsonb_set(v_src_game,array[v_bucket],to_jsonb(v_src_qty-p_amount),true);
      v_dst_game:=jsonb_set(v_dst_game,array[v_bucket],to_jsonb(v_dst_qty+p_amount),true);
    end if;
  else
    raise exception 'INVALID_GIFT_KIND';
  end if;

  update public.cf_player_profiles set save_data=jsonb_set(v_src_data,'{cf}',v_src_game,true),updated_at=now() where user_id=v_me;
  update public.cf_player_profiles set save_data=jsonb_set(v_dst_data,'{cf}',v_dst_game,true),updated_at=now() where user_id=v_friend;
  return jsonb_build_object('ok',true,'save',v_src_game);
end;
$$;

revoke all on function public.cf_generate_friend_code() from public,anon,authenticated;
revoke all on function public.cf_require_gmail() from public,anon,authenticated;
revoke all on function public.cf_create_profile_for_user() from public,anon,authenticated;
revoke all on function public.cf_list_friends() from public,anon;
revoke all on function public.cf_add_friend_by_code(text) from public,anon;
revoke all on function public.cf_remove_friend_by_code(text) from public,anon;
revoke all on function public.cf_gift(text,text,text,integer) from public,anon;
grant execute on function public.cf_list_friends() to authenticated;
grant execute on function public.cf_add_friend_by_code(text) to authenticated;
grant execute on function public.cf_remove_friend_by_code(text) to authenticated;
grant execute on function public.cf_gift(text,text,text,integer) to authenticated;
