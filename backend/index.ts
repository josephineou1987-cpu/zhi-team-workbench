// All database access stays server-side. Tables deny direct anon/authenticated access.
const ORIGIN='https://josephineou1987-cpu.github.io';
const enc=new TextEncoder();
const hex=(b:ArrayBuffer|Uint8Array)=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const hash=async(s:string)=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const eq=(a:any,b:any):boolean=>JSON.stringify(sort(a))===JSON.stringify(sort(b));
function sort(v:any):any{return Array.isArray(v)?v.map(sort):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sort(v[k])])):v}
const arrays=['tasks','updates','reports','shares','minutes','insights','leaves','assignmentRules'];
const maps=['weeklyPlans','communityChecks'];
const globals=['dutyConfig','roster','ruleNotes'];
const personal=['tasks','updates','reports','insights','leaves'];
function response(body:any,status=200){return new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Headers':'authorization,content-type','Access-Control-Allow-Methods':'GET,POST,PATCH,OPTIONS','Vary':'Origin'}})}
async function rest(path:string,method='GET',body?:any,prefer='return=representation'){
 const secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS')||'{}').default;
 if(!secret)throw new Error('后台密钥尚未配置');
 const headers:Record<string,string>={apikey:secret,'Content-Type':'application/json',Prefer:prefer};
 if(secret.startsWith('eyJ'))headers.Authorization='Bearer '+secret;
 const r=await fetch(Deno.env.get('SUPABASE_URL')+'/rest/v1/'+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
 if(!r.ok){console.error('Database request failed',r.status,path.split('?')[0]);throw new Error('数据库暂不可用，请稍后重试')}
 return r.status===204?null:r.json();
}
function visible(data:any,user:any){const d=structuredClone(data);if(user.role!=='admin')for(const k of personal)d[k]=(d[k]||[]).filter((x:any)=>x.owner===user.name);return d}
function allowed(user:any,op:any,old:any){
 const {collection:k,key,after:a}=op;
 if(user.role==='admin')return true;
 if(personal.includes(k)||k==='shares')return (!old||old.owner===user.name)&&(!a||a.owner===user.name);
 if(k==='communityChecks')return user.name==='杨瑞';
 if(k==='weeklyPlans'&&a){
  const b=old||{priorities:{}};
  if((a.minutes||'')!==(b.minutes||'')||(a.link||'')!==(b.link||''))return false;
  const other=(x:any)=>Object.fromEntries(Object.entries(x?.priorities||{}).filter(([n])=>n!==user.name));
  return eq(other(a),other(b))&&Object.keys(a).every(x=>['priorities','minutes','link','updated'].includes(x));
 }
 return false;
}
function apply(data:any,ops:any[],user:any){
 const d=structuredClone(data);
 for(const op of ops){
  const {collection:k,key,before,after}=op;
  if(typeof key!=='string'||['__proto__','constructor','prototype'].includes(key)||!([...arrays,...maps,...globals].includes(k)))throw Object.assign(new Error('无效数据字段'),{status:400});
  const arr=arrays.includes(k),map=maps.includes(k);
  const old=arr?(d[k]||[]).find((x:any)=>x.id===key)??null:map?d[k]?.[key]??null:d[k]??null;
  if(!allowed(user,op,old))throw Object.assign(new Error('只能修改自己的记录；全员分工由 David 管理'),{status:403});
  if(!eq(old,before)&&!eq(old,after))throw Object.assign(new Error('此记录已在另一设备更新，请刷新后重试'),{status:409});
  if(after!==null&&(personal.includes(k)||k==='shares')&&(typeof after!=='object'||typeof after.owner!=='string'))throw Object.assign(new Error('记录缺少负责人'),{status:400});
  if(arr){if(after!==null&&after.id!==key)throw Object.assign(new Error('记录编号不匹配'),{status:400});d[k]=(d[k]||[]).filter((x:any)=>x.id!==key);if(after!==null)d[k].push(after)}
  else if(map){d[k]??={};if(after===null)delete d[k][key];else d[k][key]=after}
  else if(after===null)delete d[k];else d[k]=after;
 }
 return d;
}
Deno.serve(async(req:Request)=>{
 try{
  if(req.headers.get('Origin')&&req.headers.get('Origin')!==ORIGIN)return response({error:'请求来源无效'},403);
  if(req.method==='OPTIONS')return response({ok:true});
  const path=new URL(req.url).pathname.replace(/^.*\/zhi-workbench/,'');
  if(path==='/health')return response({ok:true});
  let body:any={};if(['POST','PATCH'].includes(req.method)){const raw=await req.text();if(raw.length>1500000)return response({error:'单次保存内容过大'},413);try{body=raw?JSON.parse(raw):{}}catch{return response({error:'无效请求'},400)}}
  if(path==='/auth/login'&&req.method==='POST'){
   const name=String(body.name||'').trim()==='吴权'?'David':String(body.name||'').trim();
   if(typeof body.password!=='string'||body.password.length>128)return response({error:'姓名或密码不正确'},401);
   const bucket=await hash(name+':'+Math.floor(Date.now()/300000));
   if(await rest('rpc/zhi_rate_limit','POST',{p_bucket:bucket})>30)return response({error:'登录尝试过多，请五分钟后重试'},429);
   const [user]=await rest('zhi_accounts?name=eq.'+encodeURIComponent(name)+'&active=eq.true');
   const salt=user?.salt||'00000000000000000000000000000000';
   const key=await crypto.subtle.importKey('raw',enc.encode(body.password),'PBKDF2',false,['deriveBits']);
   const derived=hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:user?.iterations||210000},key,256));
   if(!user||derived!==user.password_hash)return response({error:'姓名或密码不正确'},401);
   const token=hex(crypto.getRandomValues(new Uint8Array(32)));
   await rest('zhi_sessions?expires_at=lt.'+encodeURIComponent(new Date().toISOString()),'DELETE');
   await rest('zhi_sessions','POST',{token_hash:await hash(token),name,expires_at:new Date(Date.now()+8*3600000).toISOString()});
   return response({name,role:user.role,token});
  }
  const token=req.headers.get('Authorization')?.replace(/^Bearer /,'');
  if(!token||!/^[a-f0-9]{64}$/.test(token))return response({error:'请先登录'},401);
  const tokenHash=await hash(token);
  const [session]=await rest('zhi_sessions?token_hash=eq.'+tokenHash+'&expires_at=gt.'+encodeURIComponent(new Date().toISOString()));
  if(!session)return response({error:'登录已过期，请重新登录'},401);
  const [user]=await rest('zhi_accounts?name=eq.'+encodeURIComponent(session.name)+'&active=eq.true&select=name,role');
  if(!user)return response({error:'账号不可用'},401);
  if(path==='/auth/session'&&req.method==='GET')return response(user);
  if(path==='/auth/logout'&&req.method==='POST'){await rest('zhi_sessions?token_hash=eq.'+tokenHash,'DELETE');return response({ok:true})}
  if(path==='/state'&&req.method==='GET'){const [row]=await rest('zhi_state?id=eq.1');return response({data:visible(row.data,user),version:row.version})}
  if(path==='/state'&&req.method==='PATCH'){
   if(!Array.isArray(body.ops)||body.ops.length>500)return response({error:'无效修改请求'},400);
   for(let retry=0;retry<4;retry++){
    const [row]=await rest('zhi_state?id=eq.1');const data=apply(row.data,body.ops,user);
    const rows=await rest('zhi_state?id=eq.1&version=eq.'+row.version,'PATCH',{data,version:row.version+1,updated_at:new Date().toISOString()});
    if(rows.length)return response({data:visible(data,user),version:row.version+1});
   }return response({error:'其他同事正在保存，请稍后重试'},409);
  }
  return response({error:'接口不存在'},404);
 }catch(e:any){return response({error:e.message||'服务暂不可用'},e.status||503)}
});
