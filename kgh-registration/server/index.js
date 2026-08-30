import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'kgh.sqlite');
const ADMIN_KEY = process.env.ADMIN_KEY || 'demo-admin-key-change-me';
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS teams (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 team_id TEXT NOT NULL UNIQUE, team_name TEXT NOT NULL, college TEXT NOT NULL,
 program TEXT NOT NULL, department TEXT NOT NULL, year_level TEXT NOT NULL,
 leader_name TEXT NOT NULL, leader_reg_no TEXT NOT NULL, leader_email TEXT NOT NULL,
 leader_phone TEXT NOT NULL, member2_name TEXT, member2_reg_no TEXT,
 member3_name TEXT, member3_reg_no TEXT, member4_name TEXT, member4_reg_no TEXT,
 consent INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
)`);

const programs = new Set(['B.E.','B.Tech.','B.Sc.','BCA','MCA','MBA','M.E.','M.Tech.','M.Sc.','Other']);
const years = new Set(['1st Year','2nd Year','3rd Year','4th Year','Final Year','Postgraduate — 1st Year','Postgraduate — 2nd Year','Other']);
const insert = db.prepare(`INSERT INTO teams (team_id,team_name,college,program,department,year_level,leader_name,leader_reg_no,leader_email,leader_phone,member2_name,member2_reg_no,member3_name,member3_reg_no,member4_name,member4_reg_no,consent,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

function clean(v,max=200){return String(v??'').trim().replace(/\s+/g,' ').slice(0,max)}
function emailOk(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)}
function phoneOk(v){return /^[0-9+()\-\s]{7,20}$/.test(v)}
function teamId(){for(let i=0;i<100;i++){const id=`KGH-${crypto.randomInt(0,10000).toString().padStart(4,'0')}`;if(!db.prepare('SELECT 1 FROM teams WHERE team_id=?').get(id))return id}throw Error('Team ID generation failed')}
function json(res,status,obj,extra={}){const body=JSON.stringify(obj);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...extra});res.end(body)}
function parseCookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [decodeURIComponent(x.slice(0,i).trim()),decodeURIComponent(x.slice(i+1).trim())]}))}
function token(){return crypto.createHmac('sha256',ADMIN_KEY).update(ADMIN_KEY).digest('hex')}
function authorized(req){return parseCookies(req).kgh_admin===token() || req.headers['x-admin-key']===ADMIN_KEY}
async function body(req){let data='';for await(const chunk of req)data+=chunk;if(data.length>60000)throw Error('Payload too large');return JSON.parse(data||'{}')}
function contentType(file){return {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp'}[path.extname(file)]||'application/octet-stream'}
function serve(res,file){try{const abs=path.resolve(PUBLIC,file);if(!abs.startsWith(PUBLIC))return res.writeHead(403).end();const data=fs.readFileSync(abs);res.writeHead(200,{'Content-Type':contentType(abs),'Cache-Control':'no-cache'});res.end(data)}catch{res.writeHead(404).end('Not found')}}

const server=createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,`http://${req.headers.host||'localhost'}`); const p=url.pathname;
    if(req.method==='POST'&&p==='/api/register'){
      const b=await body(req); const vals={teamName:clean(b.teamName,80),college:clean(b.college,160),program:clean(b.program,40),department:clean(b.department,100),yearLevel:clean(b.yearLevel,80),leaderName:clean(b.leaderName,100),leaderRegNo:clean(b.leaderRegNo,60),leaderEmail:clean(b.leaderEmail,160).toLowerCase(),leaderPhone:clean(b.leaderPhone,25)};
      if(!Object.values(vals).every(Boolean))return json(res,400,{error:'Please complete all required fields.'});
      if(!programs.has(vals.program)||!years.has(vals.yearLevel))return json(res,400,{error:'Please choose valid program and academic level.'});
      if(!emailOk(vals.leaderEmail))return json(res,400,{error:'Please enter a valid email address.'});
      if(!phoneOk(vals.leaderPhone))return json(res,400,{error:'Please enter a valid mobile number.'});
      if(!(b.consent===true||b.consent==='true'))return json(res,400,{error:'Please confirm the declaration before submitting.'});
      const m=[2,3,4].map(n=>({name:clean(b[`member${n}Name`],100),reg:clean(b[`member${n}RegNo`],60)}));
      for(let i=0;i<m.length;i++)if((m[i].name&&!m[i].reg)||(!m[i].name&&m[i].reg))return json(res,400,{error:`Member ${i+2}: provide both name and College ID / Register Number, or leave both blank.`});
      const id=teamId(), now=new Date().toISOString();
      insert.run(id,vals.teamName,vals.college,vals.program,vals.department,vals.yearLevel,vals.leaderName,vals.leaderRegNo,vals.leaderEmail,vals.leaderPhone,m[0].name||null,m[0].reg||null,m[1].name||null,m[1].reg||null,m[2].name||null,m[2].reg||null,1,now);
      return json(res,201,{teamId:id,createdAt:now});
    }
    if(req.method==='POST'&&p==='/api/admin/login'){
      const b=await body(req);if(b.key!==ADMIN_KEY)return json(res,401,{error:'Invalid organizer key.'});
      return json(res,200,{ok:true},{'Set-Cookie':`kgh_admin=${token()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`});
    }
    if(p.startsWith('/api/admin/')){
      if(!authorized(req))return json(res,401,{error:'Unauthorized'});
      if(req.method==='GET'&&p==='/api/admin/stats'){
        const total=db.prepare('SELECT COUNT(*) count FROM teams').get().count;
        const colleges=db.prepare('SELECT COUNT(DISTINCT college) count FROM teams').get().count;
        const today=db.prepare("SELECT COUNT(*) count FROM teams WHERE date(created_at)=date('now')").get().count;
        return json(res,200,{total,colleges,today});
      }
      if(req.method==='GET'&&p==='/api/admin/teams')return json(res,200,db.prepare('SELECT * FROM teams ORDER BY id DESC').all());
      if(req.method==='GET'&&p==='/api/admin/export.csv'){
        const rows=db.prepare('SELECT * FROM teams ORDER BY id ASC').all();
        const headers=['Team ID','Team Name','College','Program','Department','Year','Leader Name','Leader Register No','Leader Email','Leader Phone','Member 2 Name','Member 2 Register No','Member 3 Name','Member 3 Register No','Member 4 Name','Member 4 Register No','Registration Time'];
        const keys=['team_id','team_name','college','program','department','year_level','leader_name','leader_reg_no','leader_email','leader_phone','member2_name','member2_reg_no','member3_name','member3_reg_no','member4_name','member4_reg_no','created_at'];
        const esc=v=>`"${String(v??'').replaceAll('"','""')}"`;
        const csv=[headers.map(esc).join(','),...rows.map(r=>keys.map(k=>esc(r[k])).join(','))].join('\n');
        res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="kravens-gate-heist-registrations.csv"'});return res.end(csv);
      }
    }
    if(req.method==='GET'){
      if(p==='/admin')return serve(res,'admin.html');
      const safe=p==='/'?'index.html':p.slice(1); return serve(res,safe);
    }
    res.writeHead(404).end('Not found');
  }catch(e){console.error(e);json(res,500,{error:'Server error. Please try again.'})}
});
server.listen(PORT,()=>console.log(`KGH registration running on http://localhost:${PORT}`));
