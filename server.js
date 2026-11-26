const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto"),zlib=require("zlib");
const PORT=process.env.PORT||3000,DB=process.env.DATABASE_URL,FILE=path.join(__dirname,"data.json");
const BUILTIN=JSON.parse(fs.readFileSync(path.join(__dirname,"problems.json"),"utf8"));
let S={users:{},subs:[],cp:[],hidden:[],admins:{},banned:{},nid:0,det:{},detq:[],secret:crypto.randomBytes(24).toString("hex")},pool=null;

/* ---------- lưu trữ: Postgres nếu có DATABASE_URL, nếu không thì file data.json ---------- */
async function init(){
  if(DB){
    const {Pool}=require("pg");
    pool=new Pool({connectionString:DB,ssl:{rejectUnauthorized:false}});
    await pool.query("create table if not exists kv(k text primary key,v jsonb not null)");
    const r=await pool.query("select v from kv where k='state'");
    if(r.rows[0])S=Object.assign(S,r.rows[0].v);
  }else if(fs.existsSync(FILE))S=Object.assign(S,JSON.parse(fs.readFileSync(FILE,"utf8")));
  await save();
}
let chain=Promise.resolve();
function save(){
  chain=chain.then(async()=>{try{
    if(pool)await pool.query("insert into kv(k,v) values('state',$1) on conflict(k) do update set v=excluded.v",[JSON.stringify(S)]);
    else fs.writeFileSync(FILE,JSON.stringify(S));
  }catch(e){console.error("save lỗi:",e.message)}});
  return chain;
}

/* ---------- đăng nhập ---------- */
const sign=s=>crypto.createHmac("sha256",S.secret).update(s).digest("hex");
const mk=u=>{const t=u+"."+(Date.now()+14*864e5);return Buffer.from(t).toString("base64url")+"."+sign(t)};
function who(req){
  const [b,g]=(req.headers.authorization||"").slice(7).split(".");
  if(!b||!g)return null;
  const t=Buffer.from(b,"base64url").toString(),i=t.lastIndexOf("."),a=sign(t);
  if(g.length!==a.length||!crypto.timingSafeEqual(Buffer.from(g),Buffer.from(a)))return null;
  const u=t.slice(0,i);
  return +t.slice(i+1)>Date.now()&&Object.hasOwn(S.users,u)?u:null;
}
const isBanned=u=>!!u&&Object.hasOwn(S.banned,u);
const REG_MAX=+process.env.REG_PER_HOUR||5,BURST=+process.env.RATE_BURST||100;
const ADMINS=new Set((process.env.ADMIN_USERS||"").split(",").map(x=>x.trim()).filter(Boolean));
const CODE=process.env.ADMIN_CODE||"";
const sha=x=>crypto.createHash("sha256").update(String(x)).digest();
const ctag=()=>sha(CODE+"|"+S.secret).toString("hex").slice(0,16);
const viaCode=u=>!!(CODE&&u&&Object.hasOwn(S.admins,u)&&S.admins[u]===ctag());
const isAdmin=u=>!!u&&(ADMINS.has(u)||viaCode(u));
const HDR={
  "X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer",
  "Strict-Transport-Security":"max-age=15552000","Permissions-Policy":"camera=(), microphone=(), geolocation=()",
  "Content-Security-Policy":"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
};
const hits=new Map();
const cnt=(k,ms)=>{const n=Date.now(),a=(hits.get(k)||[]).filter(t=>n-t<ms);hits.set(k,a);return a.length};
const add=k=>{if(hits.size>2e5)hits.clear();const a=hits.get(k)||[];a.push(Date.now());hits.set(k,a)};
const blocked=new Map();
setInterval(()=>{const n=Date.now();for(const [k,a] of hits)if(!a.length||n-a[a.length-1]>36e5)hits.delete(k);for(const [k,t] of blocked)if(t<n)blocked.delete(k)},6e4).unref();
const ipOf=req=>{const h=req.headers;return String(h["cf-connecting-ip"]||h["true-client-ip"]||(h["x-forwarded-for"]||"").split(",")[0]||req.socket.remoteAddress||"?").trim()};
const hp=(p,salt)=>crypto.scryptSync(p,salt,32).toString("hex");
const DUMMY=hp("dummy","0000");
function pwOk(p,x){
  const a=Buffer.from(hp(p,x?x.salt:"0000")),b=Buffer.from(x?x.h:DUMMY);
  return crypto.timingSafeEqual(a,b)&&!!x;
}
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const h=s=>esc(s).replace(/\n/g,"<br>");

/* ---------- chấm bài: biên dịch g++ thật qua Judge0 CE, dự phòng Wandbox ---------- */
const JUDGE0=process.env.JUDGE0_URL||"https://ce.judge0.com";
const JAUTH=process.env.JUDGE0_TOKEN?{[process.env.JUDGE0_HEADER||"X-Auth-Token"]:process.env.JUDGE0_TOKEN}:{};  // mật khẩu của Judge0 tự dựng
const POLL0=process.env.JUDGE0_URL?150:350;    // máy chấm riêng trả kết quả nhanh nên hỏi sớm hơn
const CPU=+process.env.CPU_LIMIT||3;           // giây CPU tối đa cho mỗi test
let useLim=true;                               // tự tắt nếu Judge0 từ chối giới hạn riêng
const subBody=(code,input)=>({source_code:code,language_id:54,stdin:input,...(useLim?{cpu_time_limit:CPU,wall_time_limit:CPU*2+2,memory_limit:262144}:{})});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function post(url,body,tries=3){
  for(let k=0;k<tries;k++){
    const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json",...(url.startsWith(JUDGE0)?JAUTH:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
    if((r.status===429||r.status>=500)&&k<tries-1){await sleep(1500*(k+1));continue}
    return r;
  }
  throw new Error("busy");
}
async function runJudge0(code,input){
  const t0=Date.now();
  const r=await post(JUDGE0+"/submissions?base64_encoded=false",subBody(code,input));
  const c=await r.json().catch(()=>({}));
  if(!r.ok&&useLim&&(r.status===422||r.status===400)){useLim=false;console.error("Judge0 từ chối giới hạn riêng, bỏ giới hạn:",JSON.stringify(c).slice(0,120));return runJudge0(code,input)}
  if(!r.ok||!c.token)throw new Error("judge0 tạo bài "+r.status+" "+JSON.stringify(c).slice(0,150));
  for(let n=0;n<40;n++){
    await sleep(Math.min(1000,POLL0+n*150));
    const g=await fetch(JUDGE0+"/submissions/"+c.token+"?base64_encoded=false",{headers:JAUTH,signal:AbortSignal.timeout(20000)});
    if(!g.ok){if(g.status===429)await sleep(1500);continue}
    const d=await g.json();
    if(d.status&&d.status.id>2)return verdict(d,t0);
  }
  throw new Error("judge0 quá thời gian chờ");
}
function verdict(d,t0){
  const id=d.status?d.status.id:0,ms=Math.max(1,Math.round((parseFloat(d.time)||0)*1000)||Date.now()-t0);
  if(id===6)return{v:"CE",msg:d.compile_output||"Lỗi biên dịch",ms};
  if(id===5)return{v:"TLE",ms};
  if(id>=7&&id<=12)return{v:"RTE",msg:String(d.stderr||d.message||d.status.description||""),ms};
  if(id===3||id===4)return{out:d.stdout||"",ms};
  throw new Error("judge0 status "+id);
}
/* gửi nhiều test trong 1 yêu cầu gộp: ít lượt gọi hơn nên ít bị giới hạn tốc độ */
async function runBatch(code,inputs){
  const t0=Date.now();
  const r=await post(JUDGE0+"/submissions/batch?base64_encoded=false",{submissions:inputs.map(i=>subBody(code,i))},4);
  const toks=await r.json().catch(()=>null);
  if(!r.ok&&useLim&&(r.status===422||r.status===400)){useLim=false;console.error("Judge0 từ chối giới hạn riêng (batch), bỏ giới hạn:",JSON.stringify(toks).slice(0,120));return runBatch(code,inputs)}
  if(!r.ok||!Array.isArray(toks)||toks.some(t=>!t.token))throw new Error("batch "+r.status);
  const tk=toks.map(t=>t.token);
  for(let n=0;n<45;n++){
    await sleep(Math.min(1500,POLL0+150+n*200));
    const g=await fetch(JUDGE0+"/submissions/batch?base64_encoded=false&fields=token,stdout,stderr,compile_output,status,time,message&tokens="+tk.join(","),{headers:JAUTH});
    if(!g.ok){console.error("batch hỏi kết quả",g.status,(await g.text()).slice(0,150));continue}
    const d=await g.json(),by={};
    if(!d.submissions||!d.submissions.every(x=>x.status&&x.status.id>2))continue;
    d.submissions.forEach(x=>by[x.token]=x);
    return tk.map(t=>verdict(by[t],t0));
  }
  throw new Error("batch timeout");
}
async function runWandbox(code,input){
  const t0=Date.now();
  const r=await post("https://wandbox.org/api/compile.json",{code,compiler:"gcc-head",stdin:input,"compiler-option-raw":"-std=c++17\n-O2"},2);
  if(!r.ok)throw new Error("wandbox "+r.status+" "+(await r.text()).slice(0,150));
  const d=await r.json(),ms=Math.max(1,Date.now()-t0);
  if(d.program_output==null&&d.compiler_error)return{v:"CE",msg:d.compiler_error,ms};
  if(d.signal)return{v:/kill|time/i.test(d.signal)?"TLE":"RTE",msg:d.signal+"\n"+(d.program_error||""),ms};
  if(d.status&&String(d.status)!=="0")return{v:"RTE",msg:d.program_error||"Exit code "+d.status,ms};
  return{out:d.program_output||"",ms};
}
async function runCpp(code,input){
  try{return await runJudge0(code,input)}
  catch(e){console.error("judge0:",e.message);return await runWandbox(code,input)}
}
const norm=s=>s.split("\n").map(x=>x.trimEnd()).join("\n").trim();
function chunks(p){
  const c=[];let cur=[],size=0;
  p.T.forEach((t,k)=>{if(cur.length&&(cur.length>=10||size+t[0].length>300000)){c.push(cur);cur=[];size=0}cur.push(k);size+=t[0].length});
  if(cur.length)c.push(cur);return c;
}
/* ---- trình chấm riêng (service minioj-runner trên Render): nhanh, biên dịch g++ thật ---- */
const RUNNER_URL=(process.env.RUNNER_URL||"").replace(/\/+$/,""),RUNNER_TOKEN=process.env.RUNNER_TOKEN||"";
let runnerOkAt=0;
async function runOwn(p,code){
  if(Date.now()-runnerOkAt>20000){   // hỏi nhanh xem service đã thức chưa; nếu đang ngủ thì bỏ qua ngay (và việc hỏi cũng đánh thức nó)
    const h=await fetch(RUNNER_URL+"/healthz",{signal:AbortSignal.timeout(4000)});
    const j=await h.json().catch(()=>({}));
    if(!h.ok||!j.ready)throw new Error("runner chưa sẵn sàng");
    runnerOkAt=Date.now();
  }
  const wait=Math.min(120000,20000+p.T.length*(CPU*1000+1000));
  const r=await fetch(RUNNER_URL+"/judge",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+RUNNER_TOKEN},
    body:JSON.stringify({code,inputs:p.T.map(t=>t[0]+"\n"),cpu:CPU}),signal:AbortSignal.timeout(wait)});
  if(!r.ok){runnerOkAt=0;throw new Error("runner "+r.status)}
  runnerOkAt=Date.now();
  const d=await r.json();
  if(d.ce)return [{v:"CE",msg:d.msg||"Lỗi biên dịch",ms:1}];
  if(!Array.isArray(d.results)||d.results.length!==p.T.length)throw new Error("runner trả dữ liệu sai");
  return d.results.map(x=>({...x,ms:Math.max(1,Math.round(x.ms||1))}));
}
async function judge(p,code){
  let outs=null;
  if(RUNNER_URL&&RUNNER_TOKEN){try{outs=await runOwn(p,code)}catch(e){console.error("trình chấm riêng lỗi, chuyển sang Judge0:",e.message)}}
  if(!outs){outs=new Array(p.T.length);let batchOk=true;
  for(const c of chunks(p)){
    if(batchOk){
      try{const rs=await runBatch(code,c.map(k=>p.T[k][0]+"\n"));c.forEach((k,j)=>outs[k]=rs[j])}
      catch(e){console.error("batch:",e.message);batchOk=false}
    }
    if(!batchOk)for(const k of c){if(!outs[k]){outs[k]=await runCpp(code,p.T[k][0]+"\n");await sleep(400)}}
    if(outs[c[0]]&&outs[c[0]].v==="CE")break;
  }}
  const r=[];let v="AC",msg="",maxms=0;
  const ce=outs.find(x=>x&&x.v==="CE");
  if(ce){p.T.forEach(()=>r.push("CE"));return{v:"CE",msg:ce.msg,r,okc:0,n:p.T.length,ms:ce.ms}}
  outs.forEach((x,k)=>{
    maxms=Math.max(maxms,x.ms);
    if(x.v){r.push(x.v);if(v==="AC"||v==="WA"){v=x.v;msg=x.msg||""}}
    else if(norm(x.out)===norm(p.T[k][1]))r.push("AC");
    else{r.push("WA");if(v==="AC")v="WA"}
  });
  return{v,msg,r,okc:r.filter(x=>x==="AC").length,n:p.T.length,ms:maxms};
}

/* ---------- API ---------- */
const all=()=>BUILTIN.filter(p=>!S.hidden.includes(p.id)).concat(S.cp);
const pub=p=>({id:p.id,t:p.t,pt:p.pt,tg:p.tg,s:p.s,inp:p.inp,out:p.out,ex:p.ex,c:!!p.u});
const last={};let active=0;
const PAGE=fs.readFileSync(path.join(__dirname,"index.html")),PAGEGZ=zlib.gzipSync(PAGE);
/* ---------- chống tải dồn (k6, ab, wrk, hey…) ---------- */
const BAD_UA=/^(k6|hey|wrk|siege|vegeta|bombardier|autocannon|locust|loadtest)\b|k6\.io|apachebench|gatling|jmeter|artillery/i;
function strike(ip,w){
  for(let i=0;i<w;i++)add("V:"+ip);
  if(cnt("V:"+ip,3e5)>=3&&!(blocked.get(ip)>Date.now())){blocked.set(ip,Date.now()+9e5);console.log("Chặn IP 15 phút:",ip)}
}
const tooMany=(res,ms)=>{res.writeHead(429,{...HDR,"Retry-After":String(Math.ceil(ms/1000)),Connection:"close"});res.end()};
let ipLogs=0;
const srv=http.createServer({maxHeaderSize:8192},async(req,res)=>{
  const send=(c,o)=>{res.writeHead(c,{...HDR,"Cache-Control":"no-store","Content-Type":"application/json; charset=utf-8"});res.end(JSON.stringify(o))};
  const ip=ipOf(req),now=Date.now();
  if(ipLogs++<2)console.log("IP mẫu:",ip,"| cf-connecting-ip:",!!req.headers["cf-connecting-ip"],"| true-client-ip:",!!req.headers["true-client-ip"],"| x-forwarded-for:",req.headers["x-forwarded-for"]||"-");
  const bu=blocked.get(ip);
  if(bu>now)return tooMany(res,bu-now);
  try{
    const full=String(req.url||"/"),url=full.split("?")[0],isApi=url.startsWith("/api/"),ua=String(req.headers["user-agent"]||"");
    if(full.length>2000){res.writeHead(414,{Connection:"close"});return res.end()}
    if(!["GET","POST","HEAD"].includes(req.method)){res.writeHead(405,{Connection:"close"});return res.end()}
    if(BAD_UA.test(ua)||(isApi&&!ua)){strike(ip,3);res.writeHead(403,{Connection:"close"});return res.end()}
    if(url!=="/healthz"){
      if(cnt("W:"+ip,1e4)>=BURST||(isApi&&cnt("G:"+ip,6e4)>=240)){strike(ip,1);return tooMany(res,1e4)}
      add("W:"+ip);if(isApi)add("G:"+ip);
    }
    if((req.method==="GET"||req.method==="HEAD")&&(url==="/"||url==="/index.html")){
      const gz=/\bgzip\b/.test(req.headers["accept-encoding"]||"");
      res.writeHead(200,{...HDR,"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-cache",Vary:"Accept-Encoding",...(gz?{"Content-Encoding":"gzip"}:{})});
      return res.end(req.method==="HEAD"?undefined:(gz?PAGEGZ:PAGE));
    }
    if(url==="/healthz")return send(200,{ok:1});
    if(!isApi)return send(404,{error:"Not found"});
    if(url==="/api/data"){if(cnt("D:"+ip,6e4)>=60)return send(429,{error:"Bạn tải dữ liệu quá nhanh, hãy chậm lại."});add("D:"+ip)}
    if(url==="/api/submit"){if(cnt("S:"+ip,6e4)>=12)return send(429,{error:"Bạn nộp bài quá nhanh, hãy chậm lại."});add("S:"+ip)}
    let b={};
    if(req.method==="POST"){
      const lim=(url==="/api/problem"||url==="/api/submit")?200000:4000;let s="";
      for await(const c of req){s+=c;if(s.length>lim)return send(413,{error:"Dữ liệu quá lớn."})}
      b=JSON.parse(s||"{}");
    }
    const raw=who(req),me=raw&&!isBanned(raw)?raw:null;

    if(url==="/api/data")return send(200,{me,problems:all().map(pub),subs:S.subs.slice(0,3000),users:Object.keys(S.users).filter(u=>isAdmin(me)||!isBanned(u)),admin:isAdmin(me),canLock:viaCode(me)&&!ADMINS.has(me),
      banned:isAdmin(me)?Object.keys(S.banned):[],admins:isAdmin(me)?Object.keys(S.users).filter(isAdmin):[]});

    if(url==="/api/register"||url==="/api/login"){
      const u=String(b.u||""),p=String(b.p||"");
      if(!/^[A-Za-z0-9_]{3,20}$/.test(u)||u.startsWith("__"))return send(400,{error:"Tên đăng nhập không hợp lệ."});
      if(url==="/api/register"){
        if(cnt("R:"+ip,36e5)>=REG_MAX)return send(429,{error:"Mạng của bạn đã tạo quá nhiều tài khoản trong 1 giờ, hãy thử lại sau."});
        if(p.length<8||p.length>100)return send(400,{error:"Mật khẩu cần 8–100 ký tự."});
        if(Object.keys(S.users).length>=2000)return send(503,{error:"Hệ thống đã đủ số tài khoản cho phép."});
        if(Object.hasOwn(S.users,u))return send(409,{error:"Tên đăng nhập đã tồn tại."});
        const salt=crypto.randomBytes(12).toString("hex");S.users[u]={salt,h:hp(p,salt)};add("R:"+ip);await save();
        return send(200,{u,token:mk(u)});
      }
      if(cnt("L:"+ip+":"+u,6e5)>=8||cnt("LI:"+ip,6e5)>=30)return send(429,{error:"Đăng nhập sai quá nhiều lần, hãy thử lại sau 10 phút."});
      const x=Object.hasOwn(S.users,u)?S.users[u]:null;
      if(!pwOk(p,x)){add("L:"+ip+":"+u);add("LI:"+ip);return send(401,{error:"Sai tên đăng nhập hoặc mật khẩu."})}
      if(isBanned(u))return send(403,{error:"Tài khoản này đã bị khóa bởi quản trị viên."});
      return send(200,{u,token:mk(u)});
    }

    if(!me)return raw?send(403,{error:"Tài khoản của bạn đã bị khóa bởi quản trị viên."}):send(401,{error:"Bạn cần đăng nhập."});

    if(url==="/api/sub"){
      const id=+new URL(full,"http://x").searchParams.get("id"),sub=S.subs.find(x=>x.id===id);
      if(!sub)return send(404,{error:"Không tìm thấy bài nộp."});
      if(sub.u!==me&&!isAdmin(me))return send(403,{error:"Bạn chỉ xem được bài nộp của mình."});
      const d=Object.hasOwn(S.det,id)?S.det[id]:null;
      return send(200,{sub,code:d?d.code:null,r:d?d.r:null,msg:d?d.msg:""});
    }
    if(url==="/api/admin/unlock"){
      const k="A:"+ip+":"+me;
      if(cnt(k,9e5)>=5||cnt("AI:"+ip,9e5)>=15)return send(429,{admin:isAdmin(me)});
      if(CODE&&b.code&&crypto.timingSafeEqual(sha(b.code),sha(CODE))){
        S.admins[me]=ctag();await save();return send(200,{admin:true});
      }
      add(k);add("AI:"+ip);return send(200,{admin:isAdmin(me)});
    }
    if(url==="/api/admin/lock"){
      if(Object.hasOwn(S.admins,me)){delete S.admins[me];await save()}
      return send(200,{admin:isAdmin(me)});
    }
    if(url==="/api/admin/ban"||url==="/api/admin/unban"){
      if(!isAdmin(me))return send(403,{error:"Chỉ quản trị viên mới được thực hiện."});
      const u=String(b.u||"");
      if(!Object.hasOwn(S.users,u))return send(404,{error:"Không tìm thấy tài khoản."});
      if(url==="/api/admin/ban"){
        if(u===me)return send(400,{error:"Bạn không thể tự khóa tài khoản của mình."});
        if(isAdmin(u))return send(400,{error:"Không thể khóa tài khoản quản trị viên."});
        S.banned[u]={at:new Date().toISOString(),by:me};
      }else delete S.banned[u];
      await save();return send(200,{ok:1});
    }
    if(url==="/api/problem/delete"){
      if(!isAdmin(me))return send(403,{error:"Chỉ quản trị viên mới được xóa bài."});
      const id=String(b.id||""),i=S.cp.findIndex(p=>p.id===id);
      if(i>=0)S.cp.splice(i,1);
      else if(BUILTIN.some(p=>p.id===id)&&!S.hidden.includes(id))S.hidden.push(id);
      else return send(404,{error:"Không tìm thấy bài."});
      const gone=S.subs.filter(x=>x.p===id).map(x=>x.id);S.subs=S.subs.filter(x=>x.p!==id);gone.forEach(g=>delete S.det[g]);S.detq=S.detq.filter(g=>!gone.includes(g));await save();return send(200,{ok:1});
    }
    if(url==="/api/problem"){
      if(!isAdmin(me))return send(403,{error:"Chỉ quản trị viên mới được đăng bài."});
      const id=String(b.id||""),t=String(b.t||"").trim().slice(0,80);
      if(!/^[a-z0-9]{2,20}$/.test(id))return send(400,{error:"Mã bài gồm 2–20 ký tự: chữ thường không dấu và số."});
      if(all().some(p=>p.id===id))return send(409,{error:"Mã bài đã tồn tại."});
      if(S.cp.length>=200)return send(400,{error:"Đã đạt tối đa 200 bài đăng thêm."});
      const f=k=>String(b[k]||"").trim().slice(0,k==="tests"?40000:5000);
      if(!t||!f("s")||!f("inp")||!f("out"))return send(400,{error:"Hãy điền tên bài, đề bài, dữ liệu vào và kết quả ra."});
      const T=f("tests").split(/\n-{3,}\n/).map(x=>x.split(/\n={3,}\n/).map(y=>y.trim()));
      if(!f("tests")||T.length>30||T.some(x=>x.length!==2||!x[1]))return send(400,{error:"Test chưa đúng định dạng (tối đa 30 test, tổng 40000 ký tự)."});
      S.cp.push({id,t:esc(t),pt:Math.min(100,Math.max(1,+b.pt||10)),tg:f("tg")?f("tg").split(",").map(x=>esc(x.trim())).filter(Boolean).slice(0,5):["Khác"],s:h(f("s")),inp:h(f("inp")),out:h(f("out")),ex:T[0],T,u:me});
      await save();return send(200,{ok:1});
    }

    if(url==="/api/submit"){
      const p=all().find(x=>x.id===b.pid),code=String(b.code||"");
      if(!p)return send(404,{error:"Không tìm thấy bài."});
      if(!code.trim()||code.length>50000)return send(400,{error:"Mã nguồn trống hoặc quá dài (tối đa 50000 ký tự)."});
      if(Date.now()-(last[me]||0)<5000)return send(429,{error:"Bạn nộp quá nhanh, hãy đợi vài giây."});
      if(active>=3)return send(503,{error:"Hệ thống đang chấm nhiều bài, hãy thử lại sau vài giây."});
      last[me]=Date.now();active++;
      let result;
      try{result=await judge(p,code)}catch(e){console.error("judge:",e.message);return send(503,{error:"Máy chủ chấm bài đang bận hoặc lỗi. Thử lại sau ít phút (lần nộp này chưa được tính)."})}finally{active--}
      const sub={id:++S.nid,u:me,p:p.id,v:result.v,ok:result.okc,n:result.n,ms:result.ms,at:new Date().toISOString()};
      S.det[sub.id]={code:code.slice(0,30000),r:result.r,msg:String(result.msg||"").slice(0,2000)};S.detq.push(sub.id);
      while(S.detq.length>150)delete S.det[S.detq.shift()];
      S.subs.unshift(sub);S.subs=S.subs.slice(0,5000);await save();
      return send(200,{result,sub});
    }
    send(404,{error:"Not found"});
  }catch(e){console.error(e);send(400,{error:"Yêu cầu không hợp lệ."})}
});
srv.headersTimeout=15000;srv.requestTimeout=20000;srv.keepAliveTimeout=5000;srv.maxConnections=500;
init().then(()=>srv.listen(PORT,()=>console.log("MiniOJ chạy ở cổng",PORT,DB?"(Postgres)":"(file data.json)","| admin:",[...ADMINS].join(",")||"(không)","| mã admin:",CODE?"đã đặt":"CHƯA ĐẶT","| trình chấm riêng:",RUNNER_URL&&RUNNER_TOKEN?RUNNER_URL:"không (dùng Judge0)")))
  .catch(e=>{console.error("Không khởi động được:",e.message);process.exit(1)});
