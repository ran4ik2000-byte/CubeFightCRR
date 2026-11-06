const SESSION_COOKIE = 'cf_admin_session';
const SESSION_TTL = 8 * 60 * 60;
const PASSWORD_ITERATIONS = 100000;
const DEFAULT_PRICES = {50:19,70:25,100:35,150:49,170:55,200:63,250:75,300:89,500:139,800:209,1000:249,1500:359,2000:459,2500:549,3000:629};
const DEFAULT_CASE_PRICES = {weapon:35,armor:40,food:15,utility:65};
const CASE_KEYS = ['weapon','armor','food','utility'];
const encoder = new TextEncoder();

function json(data, status=200, extra={}) {
  return new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store, max-age=0','x-content-type-options':'nosniff',...extra}});
}
function b64url(bytes) {
  let s=''; for (const b of bytes) s+=String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function fromB64url(s) {
  s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='=';
  return Uint8Array.from(atob(s),c=>c.charCodeAt(0));
}
function hex(bytes){return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('')}
function sameBytes(a,b){if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a[i]^b[i];return d===0}
async function hmac(env, text) {
  const key=await crypto.subtle.importKey('raw',encoder.encode(env.ADMIN_SESSION_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(text)));
}
async function signSession(env, version) {
  const payload=b64url(encoder.encode(JSON.stringify({exp:Math.floor(Date.now()/1000)+SESSION_TTL,ver:Number(version)})));
  return payload+'.'+b64url(await hmac(env,payload));
}
async function verifySession(request,env) {
  const cookie=request.headers.get('Cookie')||'';
  const token=cookie.split(';').map(x=>x.trim()).find(x=>x.startsWith(SESSION_COOKIE+'='))?.slice(SESSION_COOKIE.length+1);
  if(!token||!env.ADMIN_SESSION_SECRET)return null;
  const [payload,sig]=token.split('.'); if(!payload||!sig)return null;
  let claim;try{claim=JSON.parse(new TextDecoder().decode(fromB64url(payload)))}catch{return null}
  if(!claim||!Number.isInteger(claim.exp)||claim.exp<=Date.now()/1000||!Number.isInteger(claim.ver))return null;
  const expected=await hmac(env,payload);let actual;try{actual=fromB64url(sig)}catch{return null}
  if(!sameBytes(expected,actual))return null;
  const cfg=await getSettings(env);
  if(!cfg||Number(cfg.session_version)!==claim.ver)return null;
  return {version:claim.ver,settings:cfg};
}
function cookie(value,ttl=SESSION_TTL) { return `${SESSION_COOKIE}=${value}; Path=/api/admin; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Strict`; }
function clearCookie(){return `${SESSION_COOKIE}=; Path=/api/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict`}
function sameOrigin(request) {
  const origin=request.headers.get('Origin');
  return !!origin && origin===new URL(request.url).origin;
}
function requireSecrets(env) {
  if(!env.SUPABASE_URL||!env.SUPABASE_SERVICE_ROLE_KEY||!env.ADMIN_SESSION_SECRET||env.ADMIN_SESSION_SECRET.length<32) throw new Error('SERVER_CONFIG_MISSING');
}
function sbUrl(env,path){return env.SUPABASE_URL.replace(/\/$/,'')+path}
async function sb(env,path,options={}) {
  const headers=new Headers(options.headers||{});
  headers.set('apikey',env.SUPABASE_SERVICE_ROLE_KEY);
  headers.set('authorization','Bearer '+env.SUPABASE_SERVICE_ROLE_KEY);
  if(options.body!==undefined)headers.set('content-type','application/json');
  if(options.returning)headers.set('prefer','return=representation');
  const response=await fetch(sbUrl(env,path),{...options,headers});
  const text=await response.text();
  let data=null;try{data=text?JSON.parse(text):null}catch{data=text}
  if(!response.ok){const message=typeof data==='object'&&data?(data.message||data.msg||data.error||data.hint):String(data||'Supabase request failed');throw new Error('SUPABASE_'+response.status+':'+message)}
  return data;
}
async function getSettings(env) {
  const rows=await sb(env,'/rest/v1/cf_admin_settings?select=id,password_hash,password_salt,session_version,shop_prices,case_prices,telegram_url&id=eq.true');
  return Array.isArray(rows)?rows[0]||null:null;
}
async function patchSettings(env,patch,extraFilter='') {
  const filter='/rest/v1/cf_admin_settings?id=eq.true'+extraFilter;
  return sb(env,filter,{method:'PATCH',body:JSON.stringify(patch),returning:true});
}
async function hashPassword(password,saltText) {
  const salt=saltText?fromB64url(saltText):crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:PASSWORD_ITERATIONS},key,256);
  return {salt:b64url(salt),hash:b64url(new Uint8Array(bits))};
}
async function checkPassword(password,saltText,hashText) {
  if(!saltText||!hashText)return false;
  const candidate=await hashPassword(password,saltText);
  try{return sameBytes(fromB64url(candidate.hash),fromB64url(hashText))}catch{return false}
}
async function loginGuard(env,request,event) {
  const raw=request.headers.get('CF-Connecting-IP')||'unavailable';
  const ipHash=hex(await hmac(env,raw));
  const result=await sb(env,'/rest/v1/rpc/cf_admin_login_guard',{method:'POST',body:JSON.stringify({p_ip_hash:ipHash,p_event:event})});
  return result===true;
}
async function audit(env,action,target,details={}) {
  try{await sb(env,'/rest/v1/cf_admin_audit',{method:'POST',body:JSON.stringify({action,target_user_id:target||null,details}),headers:{prefer:'return=minimal'}})}catch(e){console.error('audit write failed',String(e))}
}
async function parseBody(request){try{return await request.json()}catch{throw new Error('INVALID_JSON')}}
function validId(id){return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)}
function cleanError(error){
  const m=String(error?.message||error);
  if(m==='SERVER_CONFIG_MISSING')return ['Админ-сервер не настроен. Добавьте секреты Worker. ',503];
  if(m.includes('PROFILE_NOT_FOUND'))return ['Профиль игрока не найден.',404];
  if(m.includes('UNKNOWN_ITEM'))return ['Неизвестный предмет. Обновите каталог после миграции.',400];
  if(m.includes('INVALID_ITEM_COUNT')||m.includes('INVALID_ADJUSTMENT'))return ['Проверьте количество или сумму.',400];
  if(m.startsWith('SUPABASE_'))return ['Не удалось выполнить запрос к Supabase. Проверьте миграцию и ключ Worker.',502];
  return ['Внутренняя ошибка панели.',500];
}
async function adminApi(request,env,url) {
  const path=url.pathname,method=request.method;
  requireSecrets(env);
  if(method==='POST'&&!sameOrigin(request))return json({error:'Недопустимый источник запроса.'},403);

  if(path==='/api/admin/login'&&method==='POST'){
    const allowed=await loginGuard(env,request,'check'); if(!allowed)return json({error:'Слишком много попыток. Подождите 15 минут.'},429);
    const body=await parseBody(request),password=String(body.password||'');
    if(!password||password.length>256)return json({error:'Неверный пароль.'},401);
    const cfg=await getSettings(env);if(!cfg)return json({error:'Сначала выполните admin_migration.sql.'},503);
    let valid=false;
    if(cfg.password_hash&&cfg.password_salt)valid=await checkPassword(password,cfg.password_salt,cfg.password_hash);
    else if(env.ADMIN_INITIAL_PASSWORD)valid=password===env.ADMIN_INITIAL_PASSWORD;
    if(!valid){const stillAllowed=await loginGuard(env,request,'failure');return json({error:stillAllowed?'Неверный пароль.':'Слишком много попыток. Подождите 15 минут.'},stillAllowed?401:429)}
    await loginGuard(env,request,'success');
    let ver=Number(cfg.session_version)||1;
    if(!cfg.password_hash||!cfg.password_salt){
      if(!env.ADMIN_INITIAL_PASSWORD)return json({error:'Установите ADMIN_INITIAL_PASSWORD в секретах Worker.'},503);
      const hashed=await hashPassword(password);
      const updated=await patchSettings(env,{password_hash:hashed.hash,password_salt:hashed.salt,updated_at:new Date().toISOString()},'&password_hash=is.null');
      if(Array.isArray(updated)&&updated.length)ver=Number(updated[0].session_version)||ver;
      const latest=await getSettings(env);ver=Number(latest?.session_version)||ver;
    }
    const token=await signSession(env,ver);
    return json({ok:true},200,{ 'set-cookie':cookie(token) });
  }
  if(path==='/api/admin/logout'&&method==='POST')return json({ok:true},200,{'set-cookie':clearCookie()});
  if(path==='/api/admin/session'&&method==='GET'){
    const session=await verifySession(request,env);return session?json({ok:true}):json({ok:false},401);
  }
  const session=await verifySession(request,env);
  if(!session)return json({error:'Требуется вход.'},401);

  if(path==='/api/admin/catalog'&&method==='GET'){
    const rows=await sb(env,'/rest/v1/cf_admin_item_catalog?select=item_id,display_name,kind,rarity,damage,armor,food,utility_key,quantity,icon_url&order=kind.asc,display_name.asc');
    return json(rows);
  }
  if(path==='/api/admin/users'&&method==='GET'){
    const offset=Math.max(0,Math.min(100000,Number(url.searchParams.get('offset'))||0));
    const limit=Math.max(1,Math.min(200,Number(url.searchParams.get('limit'))||100));
    const rows=await sb(env,'/rest/v1/rpc/cf_admin_list_users',{method:'POST',body:JSON.stringify({p_offset:offset,p_limit:limit+1})});
    const page=Array.isArray(rows)?rows:[];const hasMore=page.length>limit;
    return json({users:page.slice(0,limit).map(p=>({id:p.user_id,email:p.email||'',nickname:p.display_name||p.save_data?.cf_name||'Игрок',coins:Number(p.save_data?.cf?.coins)||0,accountBlocked:!!p.account_blocked,localGameBlocked:!!p.local_game_blocked,createdAt:p.created_at})),hasMore,nextOffset:offset+limit});
  }
  if(path==='/api/admin/audit'&&method==='GET'){
    const limit=Math.max(1,Math.min(100,Number(url.searchParams.get('limit'))||50));
    const rows=await sb(env,`/rest/v1/cf_admin_audit?select=id,action,target_user_id,details,created_at&order=created_at.desc&limit=${limit}`);
    return json(Array.isArray(rows)?rows:[]);
  }
  const m=path.match(/^\/api\/admin\/users\/([^/]+)\/(account-block|local-block|coins|items)$/);
  if(m&&method==='POST'){
    const id=m[1],action=m[2];if(!validId(id))return json({error:'Некорректный ID пользователя.'},400);
    const body=await parseBody(request);
    if(action==='account-block'){
      if(typeof body.blocked!=='boolean')return json({error:'Ожидается blocked: true/false.'},400);
      const authResponse=await fetch(sbUrl(env,`/auth/v1/admin/users/${id}`),{method:'PUT',headers:{apikey:env.SUPABASE_SERVICE_ROLE_KEY,authorization:'Bearer '+env.SUPABASE_SERVICE_ROLE_KEY,'content-type':'application/json'},body:JSON.stringify({ban_duration:body.blocked?'876000h':'none'})});
      if(!authResponse.ok){await authResponse.text();return json({error:'Supabase Auth не изменил блокировку аккаунта.'},502)}
      await sb(env,`/rest/v1/cf_player_profiles?user_id=eq.${id}`,{method:'PATCH',body:JSON.stringify({account_blocked:body.blocked,updated_at:new Date().toISOString()}),headers:{prefer:'return=minimal'}});
      await audit(env,body.blocked?'account_block':'account_unblock',id);
      return json({ok:true,blocked:body.blocked});
    }
    if(action==='local-block'){
      if(typeof body.blocked!=='boolean')return json({error:'Ожидается blocked: true/false.'},400);
      await sb(env,`/rest/v1/cf_player_profiles?user_id=eq.${id}`,{method:'PATCH',body:JSON.stringify({local_game_blocked:body.blocked,updated_at:new Date().toISOString()}),headers:{prefer:'return=minimal'}});
      await audit(env,body.blocked?'local_block':'local_unblock',id);
      return json({ok:true,blocked:body.blocked});
    }
    if(action==='coins'){
      const delta=Number(body.delta);if(!Number.isInteger(delta)||delta===0||Math.abs(delta)>1000000000)return json({error:'Укажите ненулевую целую сумму до 1 000 000 000.'},400);
      const result=await sb(env,'/rest/v1/rpc/cf_admin_adjust_coins',{method:'POST',body:JSON.stringify({p_user_id:id,p_delta:delta})});
      await audit(env,delta>0?'coins_add':'coins_remove',id,{delta,coins:result});
      return json({ok:true,coins:Number(result)});
    }
    if(action==='items'){
      const itemId=String(body.item_id||''),quantity=Number(body.quantity);if(!/^[a-z0-9_-]{1,32}$/.test(itemId)||!Number.isInteger(quantity)||quantity<1||quantity>1000)return json({error:'Проверьте предмет и количество (1–1000).'},400);
      const result=await sb(env,'/rest/v1/rpc/cf_admin_grant_item',{method:'POST',body:JSON.stringify({p_user_id:id,p_item_id:itemId,p_count:quantity})});
      await audit(env,'item_grant',id,{itemId,quantity});
      return json({ok:true,result});
    }
  }
  if(path==='/api/admin/settings'&&method==='GET')return json({shopPrices:session.settings.shop_prices||DEFAULT_PRICES,casePrices:session.settings.case_prices||DEFAULT_CASE_PRICES,telegramUrl:session.settings.telegram_url||''});
  if(path==='/api/admin/settings'&&method==='POST'){
    const body=await parseBody(request),patch={};
    if(body.shopPrices!==undefined){
      const entries=body.shopPrices&&typeof body.shopPrices==='object'&&!Array.isArray(body.shopPrices)?Object.entries(body.shopPrices):[];
      if(!entries.length||entries.length>50||entries.some(([coins,price])=>!/^\d{1,9}$/.test(coins)||Number(coins)<1||Number(coins)>100000000||!Number.isInteger(Number(price))||Number(price)<0||Number(price)>1000000))return json({error:'Добавьте от 1 до 50 пакетов: монеты 1–100 000 000, цена 0–1 000 000.'},400);
      patch.shop_prices=Object.fromEntries(entries.map(([coins,price])=>[String(Number(coins)),Number(price)]).sort((a,b)=>Number(a[0])-Number(b[0])));
    }
    if(body.casePrices!==undefined){
      const values=body.casePrices;
      if(!values||typeof values!=='object'||Array.isArray(values)||CASE_KEYS.some(k=>!Number.isInteger(Number(values[k]))||Number(values[k])<0||Number(values[k])>1000000))return json({error:'Укажите целую цену каждого кейса от 0 до 1 000 000.'},400);
      patch.case_prices=Object.fromEntries(CASE_KEYS.map(k=>[k,Number(values[k])]));
    }
    if(body.telegramUrl!==undefined){
      try{const u=new URL(String(body.telegramUrl));if(u.protocol!=='https:'||!['t.me','www.t.me','telegram.me','www.telegram.me'].includes(u.hostname.toLowerCase())||u.pathname==='/'||u.username||u.password)throw 0;patch.telegram_url=u.href}catch{return json({error:'Введите ссылку формата https://t.me/имя_канала.'},400)}
    }
    if(!Object.keys(patch).length)return json({error:'Нет изменений.'},400);
    patch.updated_at=new Date().toISOString();await patchSettings(env,patch);await audit(env,'settings_update',null,{fields:Object.keys(patch)});return json({ok:true});
  }
  if(path==='/api/admin/password'&&method==='POST'){
    const body=await parseBody(request),old=String(body.currentPassword||''),next=String(body.newPassword||''),confirm=String(body.confirmPassword||'');
    const cfg=await getSettings(env);if(!cfg?.password_hash||!cfg?.password_salt)return json({error:'Сначала войдите с начальным паролем.'},409);
    if(!(await checkPassword(old,cfg.password_salt,cfg.password_hash)))return json({error:'Текущий пароль неверен.'},401);
    if(next.length<12||next.length>256)return json({error:'Новый пароль должен содержать не менее 12 символов.'},400);
    if(next!==confirm)return json({error:'Новые пароли не совпадают.'},400);
    if(next===old)return json({error:'Новый пароль должен отличаться от текущего.'},400);
    const hashed=await hashPassword(next);const ver=(Number(cfg.session_version)||1)+1;
    await patchSettings(env,{password_hash:hashed.hash,password_salt:hashed.salt,session_version:ver,updated_at:new Date().toISOString()});
    await audit(env,'password_change',null);
    return json({ok:true},200,{'set-cookie':cookie(await signSession(env,ver))});
  }
  return json({error:'Маршрут не найден.'},404);
}

export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    try {
      if(url.pathname==='/api/public-settings'&&request.method==='GET'){
        requireSecrets(env);
        const rows=await sb(env,'/rest/v1/cf_admin_settings?select=shop_prices,case_prices,telegram_url&id=eq.true');
        const row=Array.isArray(rows)?rows[0]:null;
        return json({shopPrices:row?.shop_prices||DEFAULT_PRICES,casePrices:row?.case_prices||DEFAULT_CASE_PRICES,telegramUrl:row?.telegram_url||'https://t.me/CUBEFIGHTCR'});
      }
      if(url.pathname.startsWith('/api/admin/'))return await adminApi(request,env,url);
      if(url.pathname==='/console'||url.pathname==='/console/')return env.ASSETS.fetch(new Request(new URL('/admin.html',request.url),request));
      return env.ASSETS.fetch(request);
    } catch(error) {
      console.error('admin worker error:',String(error?.message||error));
      const [message,status]=cleanError(error);
      return json({error:message},status);
    }
  }
};
