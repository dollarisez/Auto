export async function onRequest(context) {
  const { request, env } = context; const url=new URL(request.url); const path=url.pathname.replace(/^\/api\/?/,'');
  const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json;charset=UTF-8'}}); const db=env.DB; if(!db)return json({error:'D1 binding DB belum dikonfigurasi'},500);
  const body=async()=>{try{return await request.json()}catch{return{}}}; const cookie=request.headers.get('Cookie')||''; const token=(cookie.match(/(?:^|;\s*)session=([^;]+)/)||[])[1]; const enc=new TextEncoder();
  async function hmac(data,secret){const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);const sig=await crypto.subtle.sign('HMAC',key,enc.encode(data));return [...new Uint8Array(sig)].map(x=>x.toString(16).padStart(2,'0')).join('')}
  function b64(s){return btoa(unescape(encodeURIComponent(s))).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_')} function ub64(s){return decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/'))))}
  async function hashPassword(password,saltHex){let salt=saltHex?Uint8Array.from(saltHex.match(/../g).map(h=>parseInt(h,16))):crypto.getRandomValues(new Uint8Array(16));const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},key,256);return{salt:[...salt].map(x=>x.toString(16).padStart(2,'0')).join(''),hash:[...new Uint8Array(bits)].map(x=>x.toString(16).padStart(2,'0')).join('')}}
  async function createSession(user){const exp=Date.now()+8*60*60*1000;const payload=b64(JSON.stringify({id:user.id,role:user.role,exp}));const sig=await hmac(payload,env.SESSION_SECRET||'change-me');await db.prepare('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)').bind(payload+'.'+sig,user.id,new Date(exp).toISOString()).run();return payload+'.'+sig}
  async function auth(){if(!token)return null;const p=token.split('.');if(p.length!==2)return null;if(await hmac(p[0],env.SESSION_SECRET||'change-me')!==p[1])return null;let x;try{x=JSON.parse(ub64(p[0]))}catch{return null}if(x.exp<Date.now())return null;return await db.prepare('SELECT id,username,role,active FROM users WHERE id=? AND active=1').bind(x.id).first()}
  async function admin(){const u=await auth();return u&&u.role==='admin'?u:null}
  if(path==='setup'&&request.method==='POST'){
    if(!env.BOOTSTRAP_KEY||request.headers.get('X-Bootstrap-Key')!==env.BOOTSTRAP_KEY)return json({error:'Unauthorized'},401);
    try{
      const count=await db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first();
      if(Number(count.n)>0)return json({error:'Admin sudah dibuat'},409);
      const b=await body();
      if(!b.username||!b.password)return json({error:'Username dan password wajib diisi'},400);
      const hp=await hashPassword(b.password);
      await db.prepare("INSERT INTO users(username,password_hash,password_salt,role,active) VALUES(?,?,?,?,1)").bind(String(b.username).trim(),hp.hash,hp.salt,'admin').run();
      return json({ok:true});
    }catch(e){
      return json({error:'Setup gagal: '+(e?.message||String(e))},500);
    }
  }
  if(path==='login'&&request.method==='POST'){const b=await body();if(!b.username||!b.password)return json({error:'Username dan password wajib diisi'},400);const u=await db.prepare('SELECT id,username,password_hash,password_salt,role,active FROM users WHERE username=?').bind(String(b.username).trim()).first();if(!u||!u.active)return json({error:'Login gagal'},401);const hp=await hashPassword(b.password,u.password_salt);if(hp.hash!==u.password_hash)return json({error:'Login gagal'},401);const t=await createSession(u);return new Response(JSON.stringify({ok:true,user:{username:u.username,role:u.role}}),{headers:{'content-type':'application/json','Set-Cookie':`session=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`}})}
  if(path==='logout'&&request.method==='POST'){if(token)await db.prepare('DELETE FROM sessions WHERE token=?').bind(token).run();return new Response(JSON.stringify({ok:true}),{headers:{'content-type':'application/json','Set-Cookie':'session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'}})}
  if(path==='me'&&request.method==='GET'){const u=await auth();return json({authenticated:!!u,user:u?{username:u.username,role:u.role}:null})}
  if(path==='admin/users'&&request.method==='GET'){if(!await admin())return json({error:'Unauthorized'},401);const r=await db.prepare('SELECT id,username,role,active,created_at FROM users ORDER BY id DESC').all();return json(r.results)}
  if(path==='admin/users'&&request.method==='POST'){if(!await admin())return json({error:'Unauthorized'},401);const b=await body();if(!b.username||!b.password)return json({error:'Username dan password wajib diisi'},400);const hp=await hashPassword(b.password);try{await db.prepare('INSERT INTO users(username,password_hash,password_salt,role,active) VALUES(?,?,?,?,1)').bind(String(b.username).trim(),hp.hash,hp.salt,'user').run()}catch{return json({error:'Username sudah ada atau data tidak valid'},400)}return json({ok:true})}
  if(path.match(/^admin\/users\/\d+\/password$/)&&request.method==='POST'){if(!await admin())return json({error:'Unauthorized'},401);const id=Number(path.split('/')[2]);const b=await body();if(!b.password)return json({error:'Password baru wajib diisi'},400);const hp=await hashPassword(b.password);const target=await db.prepare('SELECT role FROM users WHERE id=?').bind(id).first();if(!target)return json({error:'User tidak ditemukan'},404);await db.prepare('UPDATE users SET password_hash=?,password_salt=? WHERE id=?').bind(hp.hash,hp.salt,id).run();if(id!==(await admin()).id)await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run();return json({ok:true})}
  if(path.match(/^admin\/users\/\d+$/)&&request.method==='DELETE'){if(!await admin())return json({error:'Unauthorized'},401);const id=Number(path.split('/')[2]);await db.prepare("DELETE FROM users WHERE id=? AND role='user'").bind(id).run();return json({ok:true})}
  if(path.match(/^admin\/users\/\d+$/)&&request.method==='PUT'){if(!await admin())return json({error:'Unauthorized'},401);const id=Number(path.split('/')[2]);const b=await body();if(typeof b.active!=='boolean')return json({error:'active wajib boolean'},400);await db.prepare("UPDATE users SET active=? WHERE id=? AND role='user'").bind(b.active?1:0,id).run();return json({ok:true})}
  if(path==='iframe'&&request.method==='GET'){if(!await auth())return json({error:'Unauthorized'},401);const s=await db.prepare('SELECT iframe_url FROM settings WHERE id=1').first();return json({url:s?.iframe_url||''})}
  if(path==='admin/iframe'&&request.method==='PUT'){if(!await admin())return json({error:'Unauthorized'},401);const b=await body();if(!b.url)return json({error:'URL wajib diisi'},400);await db.prepare('UPDATE settings SET iframe_url=?,updated_at=CURRENT_TIMESTAMP WHERE id=1').bind(String(b.url).trim()).run();return json({ok:true})}
  return json({error:'Not found'},404)
}
