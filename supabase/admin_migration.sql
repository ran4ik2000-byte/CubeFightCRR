-- Run after the existing CUBEFIGHT schema in Supabase SQL Editor.
-- The Worker uses the Supabase service-role secret; never place that key in browser code.

alter table public.cf_player_profiles
  add column if not exists account_blocked boolean not null default false,
  add column if not exists local_game_blocked boolean not null default false;

-- Player clients can read their own local-game flag, but cannot change either moderation flag.
revoke all on public.cf_player_profiles from anon, authenticated;
grant select(user_id,friend_code,display_name,save_data,local_game_blocked) on public.cf_player_profiles to authenticated;
grant update(save_data) on public.cf_player_profiles to authenticated;

create table if not exists public.cf_admin_settings (
  id boolean primary key default true check (id),
  password_hash text,
  password_salt text,
  session_version bigint not null default 1,
  shop_prices jsonb not null default '{"50":19,"70":25,"100":35,"150":49,"170":55,"200":63,"250":75,"300":89,"500":139,"800":209,"1000":249,"1500":359,"2000":459,"2500":549,"3000":629}'::jsonb,
  telegram_url text not null default 'https://t.me/CUBEFIGHTCR',
  updated_at timestamptz not null default now()
);
insert into public.cf_admin_settings(id) values(true) on conflict(id) do nothing;
alter table public.cf_admin_settings enable row level security;

create table if not exists public.cf_admin_item_catalog (
  item_id text primary key,
  display_name text not null,
  kind text not null check (kind in ('weapon','armor','food','utility')),
  rarity text not null,
  damage numeric,
  armor numeric,
  food integer,
  utility_key text,
  quantity integer not null default 1 check (quantity between 1 and 1000),
  icon_url text not null
);
alter table public.cf_admin_item_catalog enable row level security;

create table if not exists public.cf_admin_audit (
  id bigint generated always as identity primary key,
  action text not null,
  target_user_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.cf_admin_audit enable row level security;

create table if not exists public.cf_admin_login_attempts (
  ip_hash text primary key,
  failures integer not null default 0,
  window_started_at timestamptz not null default now(),
  blocked_until timestamptz
);
alter table public.cf_admin_login_attempts enable row level security;

create or replace function public.cf_admin_login_guard(p_ip_hash text, p_event text)
returns boolean language plpgsql volatile security definer
set search_path = public, pg_temp
as $$
declare v public.cf_admin_login_attempts%rowtype;
begin
  if p_ip_hash is null or p_ip_hash !~ '^[a-f0-9]{64}$' or p_event not in ('check','failure','success') then
    raise exception 'INVALID_LOGIN_GUARD_INPUT';
  end if;
  insert into public.cf_admin_login_attempts(ip_hash) values(p_ip_hash) on conflict(ip_hash) do nothing;
  select * into v from public.cf_admin_login_attempts where ip_hash=p_ip_hash for update;
  if p_event='success' then
    delete from public.cf_admin_login_attempts where ip_hash=p_ip_hash;
    return true;
  end if;
  if p_event='check' then return v.blocked_until is null or v.blocked_until<=now(); end if;
  if v.blocked_until is not null and v.blocked_until>now() then return false; end if;
  if v.window_started_at<now()-interval '15 minutes' then
    v.failures:=0; v.window_started_at:=now(); v.blocked_until:=null;
  end if;
  v.failures:=v.failures+1;
  if v.failures>=5 then v.blocked_until:=now()+interval '15 minutes'; end if;
  update public.cf_admin_login_attempts set failures=v.failures,window_started_at=v.window_started_at,blocked_until=v.blocked_until where ip_hash=p_ip_hash;
  return v.blocked_until is null or v.blocked_until<=now();
end;
$$;

create or replace function public.cf_admin_adjust_coins(p_user_id uuid, p_delta integer)
returns integer language plpgsql volatile security definer
set search_path = public, pg_temp
as $$
declare v_save jsonb; v_cf jsonb; v_raw text; v_now bigint; v_next bigint;
begin
  if p_user_id is null or p_delta is null or abs(p_delta::bigint)>1000000000 then raise exception 'INVALID_ADJUSTMENT'; end if;
  select save_data into v_save from public.cf_player_profiles where user_id=p_user_id for update;
  if not found then raise exception 'PROFILE_NOT_FOUND'; end if;
  v_cf:=case when jsonb_typeof(v_save->'cf')='object' then v_save->'cf' else '{}'::jsonb end;
  v_raw:=v_cf->>'coins';
  v_now:=case when v_raw ~ '^[0-9]{1,10}$' then least(2000000000,v_raw::bigint) else 0 end;
  v_next:=greatest(0,least(2000000000,v_now+p_delta::bigint));
  v_cf:=jsonb_set(v_cf,'{coins}',to_jsonb(v_next),true);
  update public.cf_player_profiles set save_data=jsonb_set(coalesce(v_save,'{}'::jsonb),'{cf}',v_cf,true),updated_at=now() where user_id=p_user_id;
  return v_next::integer;
end;
$$;

create or replace function public.cf_admin_grant_item(p_user_id uuid, p_item_id text, p_count integer)
returns jsonb language plpgsql volatile security definer
set search_path = public, pg_temp
as $$
declare v_item public.cf_admin_item_catalog%rowtype; v_save jsonb; v_cf jsonb; v_bucket jsonb; v_raw text; v_now bigint; v_next bigint; v_delta integer;
begin
  if p_user_id is null or p_count is null or p_count<1 or p_count>1000 then raise exception 'INVALID_ITEM_COUNT'; end if;
  select * into v_item from public.cf_admin_item_catalog where item_id=p_item_id;
  if not found then raise exception 'UNKNOWN_ITEM'; end if;
  select save_data into v_save from public.cf_player_profiles where user_id=p_user_id for update;
  if not found then raise exception 'PROFILE_NOT_FOUND'; end if;
  v_cf:=case when jsonb_typeof(v_save->'cf')='object' then v_save->'cf' else '{}'::jsonb end;
  if v_item.kind in ('weapon','armor') then
    v_bucket:=case when jsonb_typeof(v_cf->'own')='object' then v_cf->'own' else '{}'::jsonb end;
    v_raw:=v_bucket->>v_item.item_id;
    v_now:=case when v_raw ~ '^[0-9]{1,10}$' then least(2000000000,v_raw::bigint) else 0 end;
    v_next:=least(2000000000,v_now+p_count::bigint);
    v_cf:=jsonb_set(v_cf,'{own}',jsonb_set(v_bucket,array[v_item.item_id],to_jsonb(v_next),true),true);
  elsif v_item.kind='food' then
    v_bucket:=case when jsonb_typeof(v_cf->'fd')='object' then v_cf->'fd' else '{}'::jsonb end;
    v_raw:=v_bucket->>v_item.item_id;
    v_now:=case when v_raw ~ '^[0-9]{1,10}$' then least(2000000000,v_raw::bigint) else 0 end;
    v_next:=least(2000000000,v_now+p_count::bigint);
    v_cf:=jsonb_set(v_cf,'{fd}',jsonb_set(v_bucket,array[v_item.item_id],to_jsonb(v_next),true),true);
  else
    if v_item.utility_key is null or v_item.utility_key !~ '^(pl|bm|ob|hl|rg|sc|ts|dm)$' then raise exception 'INVALID_UTILITY_KEY'; end if;
    v_raw:=v_cf->>v_item.utility_key;
    v_now:=case when v_raw ~ '^[0-9]{1,10}$' then least(2000000000,v_raw::bigint) else 0 end;
    v_delta:=v_item.quantity*p_count;
    v_next:=least(2000000000,v_now+v_delta::bigint);
    v_cf:=jsonb_set(v_cf,array[v_item.utility_key],to_jsonb(v_next),true);
  end if;
  update public.cf_player_profiles set save_data=jsonb_set(coalesce(v_save,'{}'::jsonb),'{cf}',v_cf,true),updated_at=now() where user_id=p_user_id;
  return jsonb_build_object('item_id',v_item.item_id,'count',p_count,'bundle_quantity',v_item.quantity);
end;
$$;

revoke all on public.cf_admin_settings,public.cf_admin_item_catalog,public.cf_admin_audit,public.cf_admin_login_attempts from public,anon,authenticated;
grant select,insert,update,delete on public.cf_admin_settings,public.cf_admin_item_catalog,public.cf_admin_audit,public.cf_admin_login_attempts to service_role;
grant usage,select on sequence public.cf_admin_audit_id_seq to service_role;
revoke all on function public.cf_admin_login_guard(text,text) from public,anon,authenticated;
revoke all on function public.cf_admin_adjust_coins(uuid,integer) from public,anon,authenticated;
revoke all on function public.cf_admin_grant_item(uuid,text,integer) from public,anon,authenticated;
grant execute on function public.cf_admin_login_guard(text,text) to service_role;
grant execute on function public.cf_admin_adjust_coins(uuid,integer) to service_role;
grant execute on function public.cf_admin_grant_item(uuid,text,integer) to service_role;

-- Seed the catalog generated from the attached game's ITEM/FOODS/UTIL arrays.
insert into public.cf_admin_item_catalog(item_id,display_name,kind,rarity,damage,armor,food,utility_key,quantity,icon_url) values
('s0','Деревянный меч','weapon','c',2,NULL,NULL,NULL,1,'/catalog-icons/4e7e760c2da1dccd98be.png'),
('w1','Железный меч','weapon','c',3,NULL,NULL,NULL,1,'/catalog-icons/c760c77c2a236b82297a.png'),
('w2','Сапфировый меч','weapon','c',3.5,NULL,NULL,NULL,1,'/catalog-icons/084bb3ff989dae38af04.png'),
('w3','Аметистовый меч','weapon','c',4,NULL,NULL,NULL,1,'/catalog-icons/6bf7929c616e1d926d1d.png'),
('w4','Меч Бездны','weapon','c',4.5,NULL,NULL,NULL,1,'/catalog-icons/61aa74b551b130ad3d06.png'),
('w5','Бронзовый клинок','weapon','c',5,NULL,NULL,NULL,1,'/catalog-icons/b042216321182ad5589c.png'),
('w6','Стальной меч','weapon','c',5.5,NULL,NULL,NULL,1,'/catalog-icons/61c9ab71937ef886ad44.png'),
('w7','Серебряный меч','weapon','c',6,NULL,NULL,NULL,1,'/catalog-icons/b5e329e21350ac2424f1.png'),
('w8','Рыцарский меч','weapon','c',6.5,NULL,NULL,NULL,1,'/catalog-icons/4e8ef70146387cd03f1b.png'),
('w9','Меч стражи','weapon','c',7,NULL,NULL,NULL,1,'/catalog-icons/cc3cf5e5a26aeb431c71.png'),
('w10','Изумрудный меч','weapon','c',7.5,NULL,NULL,NULL,1,'/catalog-icons/cebc1c4f8f68dd09094d.png'),
('w11','Солнечный меч','weapon','r',8,NULL,NULL,NULL,1,'/catalog-icons/0fbedfa99defbd1de31c.png'),
('w12','Лунный клинок','weapon','r',8.1,NULL,NULL,NULL,1,'/catalog-icons/707cab77b0fd9fe4654f.png'),
('w13','Клинок ветра','weapon','r',8.5,NULL,NULL,NULL,1,'/catalog-icons/b0e956d42ad90b3f3a80.png'),
('w14','Огненный меч','weapon','r',9.5,NULL,NULL,NULL,1,'/catalog-icons/7927089d2fcd88be8fee.png'),
('w15','Ледяной меч','weapon','r',10,NULL,NULL,NULL,1,'/catalog-icons/001a51fb850d0272a1bc.png'),
('w16','Меч грома','weapon','r',10.5,NULL,NULL,NULL,1,'/catalog-icons/51df4666ec53e862a12d.png'),
('w17','Теневой клинок','weapon','r',7.9,NULL,NULL,NULL,1,'/catalog-icons/aebb1448bb5b2ef176c6.png'),
('w18','Меч драконьего пламени','weapon','r',11.5,NULL,NULL,NULL,1,'/catalog-icons/bce5877b54d2b39f2aaa.png'),
('w19','Клинок Титана','weapon','r',18.6,NULL,NULL,NULL,1,'/catalog-icons/2172d495aa5393711459.png'),
('w20','Меч Вечности','weapon','r',12.5,NULL,NULL,NULL,1,'/catalog-icons/4f1728b9b416393ddfac.png'),
('w21','Меч рыцаря-феникса','weapon','e',13,NULL,NULL,NULL,1,'/catalog-icons/e72eb0572efc7a5e80f9.png'),
('w22','Клинок пустынного гиганта','weapon','e',20.9,NULL,NULL,NULL,1,'/catalog-icons/f109408480d807afa5f5.png'),
('w23','Меч лесного духа','weapon','e',14,NULL,NULL,NULL,1,'/catalog-icons/b5610a999f1bd8e766c1.png'),
('w24','Обсидиановый меч','weapon','e',14.5,NULL,NULL,NULL,1,'/catalog-icons/b1ab249250bc7135303d.png'),
('w25','Клинок Звездопада','weapon','e',15,NULL,NULL,NULL,1,'/catalog-icons/5efc49edcb249a7785de.png'),
('w26','Меч ледяного дракона','weapon','e',15.5,NULL,NULL,NULL,1,'/catalog-icons/1454fab5b0085ed5cc24.png'),
('w27','Кровавый клинок','weapon','e',16,NULL,NULL,NULL,1,'/catalog-icons/d07419957be011c12d0f.png'),
('w28','Меч древних королей','weapon','e',25.6,NULL,NULL,NULL,1,'/catalog-icons/e634eac6a5fba7ba6fd2.png'),
('w29','Сияющий меч','weapon','m',17,NULL,NULL,NULL,1,'/catalog-icons/0805830e4c6145fb1b0c.png'),
('w30','Клинок Бури','weapon','m',17.5,NULL,NULL,NULL,1,'/catalog-icons/1794a581573007ae1163.png'),
('w31','Меч Хаоса','weapon','m',18.9,NULL,NULL,NULL,1,'/catalog-icons/9e688b3ae9f5caf98768.png'),
('w32','Клинок Титанов Льда','weapon','m',28.7,NULL,NULL,NULL,1,'/catalog-icons/a89327bebfbfd37f2ea7.png'),
('w33','Золотой меч Императора','weapon','m',29.4,NULL,NULL,NULL,1,'/catalog-icons/e7eef55165a75b7bee67.png'),
('w34','Меч Пустоты','weapon','m',19.5,NULL,NULL,NULL,1,'/catalog-icons/4a6477df17e42092b269.png'),
('w35','Клинок Бесконечности','weapon','m',20,NULL,NULL,NULL,1,'/catalog-icons/05a1328934f1a366967f.png'),
('w36','Призрачный клинок','weapon','l',18.9,NULL,NULL,NULL,1,'/catalog-icons/6194423a929602482fee.png'),
('w37','Меч Звёздного Шторма','weapon','l',21,NULL,NULL,NULL,1,'/catalog-icons/498afe248e094aeb3e98.png'),
('w38','Клинок Света','weapon','l',21.5,NULL,NULL,NULL,1,'/catalog-icons/1535800435cb896db107.png'),
('w39','Меч Вечного Огня','weapon','l',22,NULL,NULL,NULL,1,'/catalog-icons/938e63950c84efe4af6a.png'),
('w40','Клинок Бога Войны','weapon','l',34.9,NULL,NULL,NULL,1,'/catalog-icons/3f4f2a24a38892bc7b88.png'),
('w41','Ржавый меч','weapon','c',3.8,NULL,NULL,NULL,1,'/catalog-icons/1f37a982c066e89d53ad.png'),
('w42','Охотничий клинок','weapon','c',3.7,NULL,NULL,NULL,1,'/catalog-icons/0db4972dad091e21b6f9.png'),
('w43','Кухонный тесак','weapon','c',6.3,NULL,NULL,NULL,1,'/catalog-icons/b7e9aa607a93353d9944.png'),
('w44','Меч наёмника','weapon','r',9,NULL,NULL,NULL,1,'/catalog-icons/0ccf2064ed5afa5ed3b4.png'),
('w45','Клинок пирата','weapon','r',9.9,NULL,NULL,NULL,1,'/catalog-icons/c751def2f3755f4e4c3a.png'),
('w46','Катана','weapon','r',10.1,NULL,NULL,NULL,1,'/catalog-icons/c60fb35e01a922352fcc.png'),
('w47','Зазубренный меч','weapon','r',11.9,NULL,NULL,NULL,1,'/catalog-icons/7e5c168cab10867d5007.png'),
('w48','Меч дуэлянта','weapon','r',11.2,NULL,NULL,NULL,1,'/catalog-icons/f0e5b7d01954f9a2bfed.png'),
('w49','Клинок вампира','weapon','e',13.4,NULL,NULL,NULL,1,'/catalog-icons/bad34ceb17fc91f06937.png'),
('w50','Токсичный меч','weapon','e',14.3,NULL,NULL,NULL,1,'/catalog-icons/5b7aaca7b142e5b33a8e.png'),
('w51','Хрустальный меч','weapon','e',15.2,NULL,NULL,NULL,1,'/catalog-icons/b069808c2fa2d1e6fa0a.png'),
('w52','Меч песчаной бури','weapon','e',16.7,NULL,NULL,NULL,1,'/catalog-icons/66137dc02afd33cd7bc8.png'),
('w53','Клинок магмы','weapon','e',16.6,NULL,NULL,NULL,1,'/catalog-icons/8d93e718ff693d6b8ad3.png'),
('w54','Меч Падшего Ангела','weapon','m',17.6,NULL,NULL,NULL,1,'/catalog-icons/e048a48102b6e03f1054.png'),
('w55','Клинок Некроманта','weapon','m',18.6,NULL,NULL,NULL,1,'/catalog-icons/7c8d00c4ba71ca74a3fd.png'),
('w56','Меч Эха Бездны','weapon','m',19.4,NULL,NULL,NULL,1,'/catalog-icons/3cf45099118c9c23b07d.png'),
('w57','Реликвия Гладиатора','weapon','m',30.8,NULL,NULL,NULL,1,'/catalog-icons/73c1217352671c00968a.png'),
('w58','Меч Создателя','weapon','l',23.5,NULL,NULL,NULL,1,'/catalog-icons/425b21a7521cc7ade4ce.png'),
('w59','Клинок Рассвета','weapon','l',25,NULL,NULL,NULL,1,'/catalog-icons/f1b11b44ffebf3f9fa75.png'),
('w60','Эскалибур','weapon','l',43.4,NULL,NULL,NULL,1,'/catalog-icons/ce4fc512e72ba10dbfe6.png'),
('w61','Кинжал разбойника','weapon','c',3.3,NULL,NULL,NULL,1,'/catalog-icons/d5e465b72173adb8e111.png'),
('w62','Рапира мушкетёра','weapon','r',9,NULL,NULL,NULL,1,'/catalog-icons/4af80be8a715a3851298.png'),
('w63','Сабля кочевника','weapon','r',10.7,NULL,NULL,NULL,1,'/catalog-icons/d1db92f75bcab3749b8d.png'),
('w64','Нодачи','weapon','e',14.1,NULL,NULL,NULL,1,'/catalog-icons/4312cb06afa3ceea7ca9.png'),
('w65','Кинжал ассасина','weapon','e',9.9,NULL,NULL,NULL,1,'/catalog-icons/98fc26ac46c752c4ce8f.png'),
('w66','Двуручный меч','weapon','e',25.1,NULL,NULL,NULL,1,'/catalog-icons/d71c750298ab39e1b7a6.png'),
('w67','Кристальная рапира','weapon','m',18.2,NULL,NULL,NULL,1,'/catalog-icons/a7bf2afc5b7387178d32.png'),
('w68','Катана Грозы','weapon','m',18.1,NULL,NULL,NULL,1,'/catalog-icons/5ee48cac988f689d7548.png'),
('w69','Кинжал Тени','weapon','m',12.4,NULL,NULL,NULL,1,'/catalog-icons/41deee65644a16c92781.png'),
('w70','Ледяная катана','weapon','l',24,NULL,NULL,NULL,1,'/catalog-icons/2bb152d7e8a93963f261.png'),
('w71','Пылающий двуручник','weapon','l',41.1,NULL,NULL,NULL,1,'/catalog-icons/b87e6114123f4ecb77d3.png'),
('w72','Кинжал новичка','weapon','c',3,NULL,NULL,NULL,1,'/catalog-icons/1cd36a94a7db95af4544.png'),
('w73','Сабля ученика','weapon','c',5.3,NULL,NULL,NULL,1,'/catalog-icons/f90a4ffcab244cc84954.png'),
('w74','Меч охранника','weapon','c',5.8,NULL,NULL,NULL,1,'/catalog-icons/4b0dca13077df8f8df86.png'),
('w75','Рапира фехтовальщика','weapon','r',8.3,NULL,NULL,NULL,1,'/catalog-icons/4c32114798f7f7d7dc74.png'),
('w76','Сабля янычара','weapon','r',10.5,NULL,NULL,NULL,1,'/catalog-icons/5ddfbf61a8c0434b2a27.png'),
('w77','Двуручный палаш','weapon','r',17.8,NULL,NULL,NULL,1,'/catalog-icons/c293990a7880024d5b37.png'),
('w78','Кинжал Огня','weapon','r',8.5,NULL,NULL,NULL,1,'/catalog-icons/73a19b709cbc46c00afe.png'),
('w79','Ледяной клинок','weapon','r',12,NULL,NULL,NULL,1,'/catalog-icons/3d03d33a27d90eae153a.png'),
('w80','Катана пламени','weapon','e',14.6,NULL,NULL,NULL,1,'/catalog-icons/d7044bfe5541e85313a8.png'),
('w81','Рапира Грозы','weapon','e',13.8,NULL,NULL,NULL,1,'/catalog-icons/5d4d4565efe4fd4a64be.png'),
('w82','Сабля вампира','weapon','e',16.8,NULL,NULL,NULL,1,'/catalog-icons/0925f822dd90a7c9d679.png'),
('w83','Катана Изумруда','weapon','e',15,NULL,NULL,NULL,1,'/catalog-icons/993eca53d7158e437e67.png'),
('w84','Хрустальный двуручник','weapon','e',26.4,NULL,NULL,NULL,1,'/catalog-icons/5d238ed583429b170535.png'),
('w85','Кинжал Пустоты','weapon','m',13,NULL,NULL,NULL,1,'/catalog-icons/42257be6c8b9de241dbc.png'),
('w86','Двуручник Бездны','weapon','m',30.7,NULL,NULL,NULL,1,'/catalog-icons/f0a49e780de98f9f23bb.png'),
('w87','Рапира Звездопада','weapon','m',17.3,NULL,NULL,NULL,1,'/catalog-icons/c161bfbfed605d64bc48.png'),
('w88','Сабля Солнечная','weapon','m',20.2,NULL,NULL,NULL,1,'/catalog-icons/287b00ee8445f465f989.png'),
('w89','Катана Лунного Света','weapon','l',23.3,NULL,NULL,NULL,1,'/catalog-icons/13e631ca42af0800a23d.png'),
('w90','Двуручник Вечного Льда','weapon','l',40.3,NULL,NULL,NULL,1,'/catalog-icons/40d7bcf57cfd504714da.png'),
('w91','Меч Кровавой Луны','weapon','l',27.5,NULL,NULL,NULL,1,'/catalog-icons/f41a990780df166177f8.png'),
('w92','Медный гладиус','weapon','c',5.4,NULL,NULL,NULL,1,'/catalog-icons/4f5675a6fae7ff8f1bf5.png'),
('w93','Костяной меч','weapon','c',6.1,NULL,NULL,NULL,1,'/catalog-icons/45f0692cfb65bda27872.png'),
('w94','Меч странника','weapon','r',9.2,NULL,NULL,NULL,1,'/catalog-icons/8f5b3efe3886bdc35004.png'),
('w95','Сабля Бури','weapon','r',11.6,NULL,NULL,NULL,1,'/catalog-icons/d32eac861bd40202e502.png'),
('w96','Токсичный Кинжал','weapon','e',9.5,NULL,NULL,NULL,1,'/catalog-icons/0a8e167328029961bddb.png'),
('w97','Меч Крови Дракона','weapon','e',16.8,NULL,NULL,NULL,1,'/catalog-icons/391607f15f94cb01787a.png'),
('w98','Меч Огненного Вулкана','weapon','m',19.6,NULL,NULL,NULL,1,'/catalog-icons/5107842f8b3dc40919e3.png'),
('w99','Двуручник Тёмного Рыцаря','weapon','m',31.3,NULL,NULL,NULL,1,'/catalog-icons/1a85d5e334d5f43314e8.png'),
('w100','Рапира Бесконечности','weapon','l',23.5,NULL,NULL,NULL,1,'/catalog-icons/fb82ea5eb50e6c89a109.png'),
('w101','Меч Пустоты Миров','weapon','l',28.5,NULL,NULL,NULL,1,'/catalog-icons/9fbe83f0bee9afd41dee.png'),
('w102','Клинок Абсолюта','weapon','l',50,NULL,NULL,NULL,1,'/catalog-icons/87d5f8fadd81029d7684.png'),
('a1','Кожаная броня','armor','c',NULL,0.1,NULL,NULL,1,'/catalog-icons/d517543a37f1f1745c62.png'),
('a2','Кольчуга','armor','r',NULL,0.2,NULL,NULL,1,'/catalog-icons/2161f5e720e39d32073a.png'),
('a3','Алмазная броня','armor','e',NULL,0.32,NULL,NULL,1,'/catalog-icons/ddf03b99f6b8ad524ee9.png'),
('a4','Незеритовая броня','armor','m',NULL,0.45,NULL,NULL,1,'/catalog-icons/8d79f3bf52dfadaddc01.png'),
('a5','Броня Дракона','armor','l',NULL,0.6,NULL,NULL,1,'/catalog-icons/6180c6091d66106deb40.png'),
('a6','Тканевая броня','armor','c',NULL,0.12,NULL,NULL,1,'/catalog-icons/d0c8836d48dc6e235fa1.png'),
('a7','Бронзовая броня','armor','c',NULL,0.195,NULL,NULL,1,'/catalog-icons/d010eff117bf33b73eae.png'),
('a8','Каменная броня','armor','r',NULL,0.27,NULL,NULL,1,'/catalog-icons/4e4a94f936c6c3bae477.png'),
('a9','Медная броня','armor','r',NULL,0.345,NULL,NULL,1,'/catalog-icons/93504a479aa2494ab43b.png'),
('a10','Стальная броня','armor','e',NULL,0.42,NULL,NULL,1,'/catalog-icons/61870340f07d1f172437.png'),
('a11','Золотая броня','armor','e',NULL,0.495,NULL,NULL,1,'/catalog-icons/40db75dc38a887cc03a5.png'),
('a12','Рунная броня','armor','e',NULL,0.57,NULL,NULL,1,'/catalog-icons/d29ba1eea9b30b0f84e9.png'),
('a13','Лавовая броня','armor','m',NULL,0.645,NULL,NULL,1,'/catalog-icons/476132763c7883880fe0.png'),
('a14','Небесная броня','armor','m',NULL,0.72,NULL,NULL,1,'/catalog-icons/d45f033141d6908bf05a.png'),
('a15','Броня Титана','armor','l',NULL,0.795,NULL,NULL,1,'/catalog-icons/a2e06f8ca5fbdac241bf.png'),
('f1','Малина','food','c',NULL,NULL,2,NULL,1,'/catalog-icons/842b864cac6c2dd36a32.png'),
('f2','Долька арбуза','food','c',NULL,NULL,3,NULL,1,'/catalog-icons/65936fb59347d3ec0518.png'),
('f3','Яблоко','food','c',NULL,NULL,4,NULL,1,'/catalog-icons/d22b7ddb457870e38887.png'),
('f4','Перец','food','r',NULL,NULL,4,NULL,1,'/catalog-icons/fc56d0c092bbd35fd62d.png'),
('f5','Морковь','food','r',NULL,NULL,5,NULL,1,'/catalog-icons/cd3f8346c5c39d87dc65.png'),
('f6','Банан','food','e',NULL,NULL,6,NULL,1,'/catalog-icons/b40f7a358a8b24eeccc2.png'),
('f7','Свекла','food','e',NULL,NULL,6,NULL,1,'/catalog-icons/77fd6e1c1b608ab5a0f0.png'),
('f8','Тыква','food','m',NULL,NULL,8,NULL,1,'/catalog-icons/9f3c25062c442f6a3625.png'),
('f9','Мясо','food','l',NULL,NULL,12,NULL,1,'/catalog-icons/35a24ac23b79181247cb.png'),
('f10','Печенье','food','c',NULL,NULL,3,NULL,1,'/catalog-icons/7381bb94583a104f3d4b.png'),
('f11','Хлеб','food','c',NULL,NULL,5,NULL,1,'/catalog-icons/9ed5a78fa2a7a2ac3432.png'),
('f12','Сыр','food','r',NULL,NULL,6,NULL,1,'/catalog-icons/20cf0c8148c9feb0cae0.png'),
('f13','Пирог','food','r',NULL,NULL,7,NULL,1,'/catalog-icons/1041cf7ac43e2826b46f.png'),
('f14','Торт','food','e',NULL,NULL,9,NULL,1,'/catalog-icons/0bee8804c41e950dd2ca.png'),
('f15','Золотая морковь','food','m',NULL,NULL,10,NULL,1,'/catalog-icons/f6dc69e6463f3beab0cb.png'),
('f16','Золотое яблоко','food','l',NULL,NULL,16,NULL,1,'/catalog-icons/42da9c237a47c6ded0d6.png'),
('u1','Взрывчатка','utility','c',NULL,NULL,NULL,'bm',2,'/catalog-icons/000cafe679f5b2497d21.png'),
('u2','Эндер-жемчуг','utility','c',NULL,NULL,NULL,'pl',1,'/catalog-icons/76113f29d8d4ef555625.png'),
('u3','Взрывчатка','utility','r',NULL,NULL,NULL,'bm',4,'/catalog-icons/000cafe679f5b2497d21.png'),
('u4','Эндер-жемчуг','utility','r',NULL,NULL,NULL,'pl',2,'/catalog-icons/76113f29d8d4ef555625.png'),
('u5','Взрывчатка','utility','e',NULL,NULL,NULL,'bm',6,'/catalog-icons/000cafe679f5b2497d21.png'),
('u6','Эндер-жемчуг','utility','e',NULL,NULL,NULL,'pl',3,'/catalog-icons/76113f29d8d4ef555625.png'),
('u7','Шар смерти','utility','e',NULL,NULL,NULL,'ob',1,'/catalog-icons/0e74c230c7628099c442.png'),
('u8','Взрывчатка','utility','m',NULL,NULL,NULL,'bm',10,'/catalog-icons/000cafe679f5b2497d21.png'),
('u9','Шар смерти','utility','m',NULL,NULL,NULL,'ob',2,'/catalog-icons/0e74c230c7628099c442.png'),
('u10','Эндер-жемчуг','utility','l',NULL,NULL,NULL,'pl',6,'/catalog-icons/76113f29d8d4ef555625.png'),
('u11','Шар смерти','utility','l',NULL,NULL,NULL,'ob',4,'/catalog-icons/0e74c230c7628099c442.png'),
('u12','Зелье исцеления','utility','c',NULL,NULL,NULL,'hl',1,'/catalog-icons/d74367a481c4e1a3f218.png'),
('u13','Зелье исцеления','utility','r',NULL,NULL,NULL,'hl',2,'/catalog-icons/d74367a481c4e1a3f218.png'),
('u14','Зелье исцеления','utility','m',NULL,NULL,NULL,'hl',5,'/catalog-icons/d74367a481c4e1a3f218.png'),
('u15','Свиток молний','utility','c',NULL,NULL,NULL,'sc',2,'/catalog-icons/d39c5ac813aff3c8aeba.png'),
('u16','Свиток молний','utility','r',NULL,NULL,NULL,'sc',3,'/catalog-icons/d39c5ac813aff3c8aeba.png'),
('u17','Свиток молний','utility','l',NULL,NULL,NULL,'sc',10,'/catalog-icons/d39c5ac813aff3c8aeba.png'),
('u18','Зелье огнестойкости','utility','e',NULL,NULL,NULL,'rg',2,'/catalog-icons/9743a5ea1155c7978925.png'),
('u19','Зелье огнестойкости','utility','m',NULL,NULL,NULL,'rg',4,'/catalog-icons/9743a5ea1155c7978925.png'),
('u20','Зелье огнестойкости','utility','l',NULL,NULL,NULL,'rg',8,'/catalog-icons/9743a5ea1155c7978925.png'),
('u21','Стоп-время','utility','e',NULL,NULL,NULL,'ts',1,'/catalog-icons/ed85c969eb45d21f86c8.png'),
('u22','Стоп-время','utility','m',NULL,NULL,NULL,'ts',2,'/catalog-icons/ed85c969eb45d21f86c8.png'),
('u23','Стоп-время','utility','l',NULL,NULL,NULL,'ts',4,'/catalog-icons/ed85c969eb45d21f86c8.png'),
('u24','Защитный купол','utility','e',NULL,NULL,NULL,'dm',1,'/catalog-icons/63ab6d5561ca658eaa30.png'),
('u25','Защитный купол','utility','m',NULL,NULL,NULL,'dm',2,'/catalog-icons/63ab6d5561ca658eaa30.png'),
('u26','Защитный купол','utility','l',NULL,NULL,NULL,'dm',4,'/catalog-icons/63ab6d5561ca658eaa30.png')
on conflict(item_id) do update set display_name=excluded.display_name,kind=excluded.kind,rarity=excluded.rarity,damage=excluded.damage,armor=excluded.armor,food=excluded.food,utility_key=excluded.utility_key,quantity=excluded.quantity,icon_url=excluded.icon_url;
