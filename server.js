require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const db = new Database(process.env.DB_PATH || "data.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);`);
const getSetting = db.prepare("SELECT value FROM settings WHERE key=?");
const setSetting = db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
if (!getSetting.get("visibility")) setSetting.run("visibility", "public");
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
 const existing = db.prepare("SELECT id FROM users WHERE username=?").get(process.env.ADMIN_USERNAME);
 if (!existing) db.prepare("INSERT INTO users(username,password,role) VALUES(?,?,?)")
  .run(process.env.ADMIN_USERNAME, bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12), "admin");
}
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:"30kb"}));
app.use(express.urlencoded({extended:false}));
app.use(session({
 store: new SQLiteStore({db:"sessions.sqlite", dir:"./"}),
 secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
 resave:false, saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000}
}));
app.use(rateLimit({windowMs:15*60*1000,limit:120,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(__dirname,"public")));
const log = (u,a)=>db.prepare("INSERT INTO activity(username,action) VALUES(?,?)").run(u,a);
const auth=(req,res,next)=>req.session.user?next():res.status(401).json({error:"سجّل الدخول أولاً"});
const admin=(req,res,next)=>req.session.user?.role==="admin"?next():res.status(403).json({error:"صلاحية المدير مطلوبة"});
app.get("/api/status",(req,res)=>res.json({visibility:getSetting.get("visibility").value,user:req.session.user||null}));
app.post("/api/register",(req,res)=>{
 const {username,password}=req.body||{};
 if(!/^[a-zA-Z0-9_-]{3,24}$/.test(username||"") || (password||"").length<10) return res.status(400).json({error:"اسم المستخدم 3-24 حرفاً وكلمة المرور 10 أحرف على الأقل"});
 try{
  const info=db.prepare("INSERT INTO users(username,password) VALUES(?,?)").run(username,bcrypt.hashSync(password,12));
  req.session.user={id:info.lastInsertRowid,username,role:"user"}; log(username,"إنشاء حساب");
  res.json({ok:true,user:req.session.user});
 }catch(e){res.status(409).json({error:"اسم المستخدم مستخدم بالفعل"});}
});
app.post("/api/login",(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username||"");
 if(!u || !bcrypt.compareSync(req.body.password||"",u.password)) return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:"تعذر بدء الجلسة"});req.session.user={id:u.id,username:u.username,role:u.role};log(u.username,"تسجيل الدخول");res.json({ok:true,user:req.session.user});});
});
app.post("/api/logout",auth,(req,res)=>{req.session.destroy(()=>res.json({ok:true}));});
app.get("/api/admin/users",auth,admin,(req,res)=>res.json(db.prepare("SELECT id,username,role FROM users ORDER BY id").all()));
app.post("/api/admin/visibility",auth,admin,(req,res)=>{
 const v=req.body.visibility;if(!["public","private"].includes(v))return res.status(400).json({error:"قيمة غير صحيحة"});
 setSetting.run("visibility",v);log(req.session.user.username,"تغيير وضع الموقع إلى "+v);res.json({ok:true,visibility:v});
});
app.post("/api/admin/role",auth,admin,(req,res)=>{
 const {id,role}=req.body;if(!["admin","user"].includes(role))return res.status(400).json({error:"دور غير صحيح"});
 db.prepare("UPDATE users SET role=? WHERE id=?").run(role,id);log(req.session.user.username,"تعديل صلاحية مستخدم");res.json({ok:true});
});
app.get("/api/admin/activity",auth,admin,(req,res)=>res.json(db.prepare("SELECT * FROM activity ORDER BY id DESC LIMIT 100").all()));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public/index.html")));
const port=process.env.PORT||3000;
app.listen(port,()=>console.log("Cyber Security Platform listening on "+port));