import asyncio
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, closing
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()
BASE_URL = os.environ["HUB_BASE_URL"].rstrip("/")
CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
SESSION_SECRET = os.environ["SESSION_SECRET"]
OWNER_IDS = {x.strip() for x in os.getenv("OWNER_IDS", "").split(",") if x.strip()}
BOT_KEYS = {k.strip(): v.strip() for k, v in (p.split(":", 1) for p in os.getenv("BOT_KEYS", "").split(",") if ":" in p)
            if re.fullmatch(r"[A-Za-z0-9_-]+", k.strip())}  # ชื่อบอท: ตัวอักษร/ตัวเลข/_/- เท่านั้น
DB_PATH = os.getenv("HUB_DB", "hub.db")
# (ไม่บังคับ) แจ้งเตือนมือถือผ่าน ntfy เมื่อบอทเงียบไป: เว็บกลางอยู่คนละเครื่องกับบอทจึงแจ้งได้แม้ VPS ของบอทล่มทั้งเครื่อง
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "").strip()
NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "").strip()

BOT_ONLINE_SECS = 20      # ไม่ได้ยินจากตัวบอทเกินนี้ = บอทไม่ตอบ
AGENT_ONLINE_SECS = 20    # ไม่ได้ยินจากตัวคุม (supervisor) เกินนี้ = ออฟไลน์
CMD_TTL = 120             # คำสั่งที่รอเกินนี้ถูกทิ้ง กันคำสั่งเด้งทีหลังโดยไม่ตั้งใจ
RESTART_COOLDOWN = 30     # กันกดรีสตาร์ตรัวๆ
OFFLINE_ALERT_SECS = 45   # บอทหายเกินนี้ถึงจะแจ้งเตือนมือถือ
MAX_PENDING = 10          # คิวคำสั่งรอรันต่อบอทสูงสุด


# ------------------------------------------------------------------ ฐานข้อมูล
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


with closing(db()) as _c, _c:
    _c.executescript("""
    CREATE TABLE IF NOT EXISTS allowlist(user_id TEXT PRIMARY KEY, added_by TEXT, added_at INTEGER);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER,
                                     actor TEXT, action TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS agents(bot TEXT PRIMARY KEY, last_seen INTEGER, status TEXT);
    CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY AUTOINCREMENT, bot TEXT, action TEXT,
                                        created_by TEXT, created_at INTEGER, state TEXT DEFAULT 'pending', result TEXT);
    CREATE TABLE IF NOT EXISTS bots_info(bot TEXT PRIMARY KEY, last_seen INTEGER, info TEXT, stat TEXT);
    """)
    _cols = {r["name"] for r in _c.execute("PRAGMA table_info(commands)")}  # อัปเกรดฐานข้อมูลเวอร์ชันเก่าอัตโนมัติ
    for _col, _ddl in (("target", "TEXT DEFAULT 'agent'"), ("args", "TEXT"), ("guild_id", "TEXT"), ("created_name", "TEXT")):
        if _col not in _cols:
            _c.execute(f"ALTER TABLE commands ADD COLUMN {_col} {_ddl}")


def log(actor, action, detail=""):
    with closing(db()) as c, c:
        c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
                  (int(time.time()), str(actor), action, detail))


def valid_id(v: str) -> bool:
    return v.isdigit() and 15 <= len(v) <= 20


def is_allowed(uid: str) -> bool:
    if uid in OWNER_IDS:
        return True
    with closing(db()) as c:
        return c.execute("SELECT 1 FROM allowlist WHERE user_id=?", (uid,)).fetchone() is not None


def add_allowed(actor: str, target: str, via: str):
    if not valid_id(target):
        return False, "ID ต้องเป็นตัวเลข 15-20 หลัก"
    if target in OWNER_IDS:
        return False, "คนนี้เป็นเจ้าของอยู่แล้ว"
    with closing(db()) as c, c:
        cur = c.execute("INSERT OR IGNORE INTO allowlist VALUES(?,?,?)", (target, actor, int(time.time())))
    if cur.rowcount == 0:
        return False, "มี ID นี้ในรายชื่ออยู่แล้ว"
    log(actor, "allow_add", f"{target} via {via}")
    return True, f"เพิ่ม {target} เข้ารายชื่อแล้ว"


def remove_allowed(actor: str, target: str, via: str):
    with closing(db()) as c, c:
        cur = c.execute("DELETE FROM allowlist WHERE user_id=?", (target,))
    if cur.rowcount == 0:
        return False, "ไม่มี ID นี้ในรายชื่อ (เจ้าของใน .env ลบจากเว็บไม่ได้)"
    log(actor, "allow_remove", f"{target} via {via}")
    return True, f"ลบ {target} ออกจากรายชื่อแล้ว"


def bot_name(key: str):
    for name, k in BOT_KEYS.items():
        if k and hmac.compare_digest(key.encode(), k.encode()):
            return name
    return None


# ------------------------------------------------------------------ สถานะบอท
def num(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def jload(s) -> dict:
    try:
        v = json.loads(s or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(num(ts)))


def ago(ts) -> str:
    s = max(0, int(time.time()) - num(ts))
    if s < 60:
        return f"{s} วินาทีที่แล้ว"
    if s < 3600:
        return f"{s // 60} นาทีที่แล้ว"
    if s < 86400:
        return f"{s // 3600} ชั่วโมงที่แล้ว"
    return f"{s // 86400} วันที่แล้ว"


def fmt_dur(sec) -> str:
    d, r = divmod(num(sec), 86400)
    h, r = divmod(r, 3600)
    return (f"{d} วัน " if d else "") + (f"{h} ชม. " if h or d else "") + f"{r // 60} นาที"


def load_rows():
    with closing(db()) as c:
        agents = {r["bot"]: r for r in c.execute("SELECT * FROM agents")}
        infos = {r["bot"]: r for r in c.execute("SELECT * FROM bots_info")}
    return agents, infos


def status_of(name, agents, infos, now):
    """state: online (ตัวบอทส่งสัญญาณ) | agent_only (ตัวคุมอยู่แต่บอทเงียบ) | offline | never"""
    a, b = agents.get(name), infos.get(name)
    bot_on = b is not None and now - num(b["last_seen"]) <= BOT_ONLINE_SECS
    ag_on = a is not None and now - num(a["last_seen"]) <= AGENT_ONLINE_SECS
    state = "online" if bot_on else "agent_only" if ag_on else "offline" if (a is not None or b is not None) else "never"
    return {"name": name, "state": state, "bot_on": bot_on, "agent_on": ag_on,
            "info": jload(b["info"]) if b is not None else {}, "stat": jload(b["stat"]) if b is not None else {},
            "agent": jload(a["status"]) if a is not None else {},
            "bot_seen": num(b["last_seen"]) if b is not None else 0, "agent_seen": num(a["last_seen"]) if a is not None else 0}


def clean_args(spec: dict, raw):
    """ตรวจอาร์กิวเมนต์ที่ฝั่งเว็บอีกชั้น (ตัวบอทตรวจซ้ำอีกครั้ง)"""
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    for a in spec.get("args", []):
        n = a.get("name")
        label = a.get("label", n)
        v = raw.get(n)
        if v in (None, ""):
            if a.get("required"):
                return None, f"ต้องระบุ {label}"
            continue
        if a.get("type") == "int":
            try:
                iv = int(str(v))
            except ValueError:
                return None, f"{label} ต้องเป็นตัวเลข"
            lo, hi = a.get("min"), a.get("max")
            if (lo is not None and iv < lo) or (hi is not None and iv > hi):
                return None, f"{label} ต้องอยู่ระหว่าง {lo} ถึง {hi}"
            out[n] = iv
        else:
            out[n] = str(v).strip()[: num(a.get("max_len")) or 200]
    return out, None


# ------------------------------------------------------------------ แจ้งเตือนมือถือเมื่อบอทเงียบ
async def push(title: str, message: str, priority: int = 4, tags=("rotating_light",)):
    if not NTFY_TOPIC:
        return
    headers = {"Authorization": f"Bearer {NTFY_TOKEN}"} if NTFY_TOKEN else {}
    try:
        async with httpx.AsyncClient(timeout=8) as h:
            await h.post(NTFY_SERVER, headers=headers, json={
                "topic": NTFY_TOPIC, "title": title[:100], "message": message[:500],
                "priority": priority, "tags": list(tags)})
    except httpx.HTTPError:
        pass


async def watchdog():
    seen = {}
    while True:
        await asyncio.sleep(15)
        try:
            now = int(time.time())
            agents, infos = load_rows()
            for name in BOT_KEYS:
                st = status_of(name, agents, infos, now)
                if st["state"] == "never":
                    continue
                ok = st["state"] == "online"
                w = seen.get(name)
                if w is None:
                    seen[name] = {"ok": ok, "since": now, "alerted": False}
                    continue
                if ok != w["ok"]:
                    w["ok"], w["since"] = ok, now
                    if ok and w["alerted"]:
                        w["alerted"] = False
                        await push(f"🟢 {name} กลับมาออนไลน์แล้ว", "บอทเชื่อมต่อกับเว็บกลางได้อีกครั้ง", 3, ("white_check_mark",))
                if not ok and not w["alerted"] and now - w["since"] >= OFFLINE_ALERT_SECS:
                    w["alerted"] = True
                    why = ("ตัวคุมบอทยังอยู่ แต่ตัวบอทไม่ส่งสัญญาณ (ลองกดรีสตาร์ตบอทในเว็บ)" if st["agent_on"]
                           else "ทั้งบอทและตัวคุมเงียบ VPS อาจมีปัญหา (ต้องเช็กที่แผงของผู้ให้เช่า)")
                    await push(f"🔴 {name} ออฟไลน์", why)
        except Exception:  # ตัวเฝ้าห้ามตายเงียบๆ
            pass


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(watchdog()) if NTFY_TOPIC else None
    yield
    if task:
        task.cancel()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax",
                   https_only=BASE_URL.startswith("https"), max_age=12 * 3600)

# ------------------------------------------------------------------ หน้าตา (UI)
CSS = """
:root{--bg:#0b0d12;--panel:#141821;--panel2:#1a1f2b;--line:#262c3a;--text:#e8eaf0;--mute:#8b93a7;--brand:#6c7bff;--brand2:#8a5cff;--ok:#2ecc71;--warn:#f39c12;--bad:#ef5350}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1100px 520px at 85% -10%,#1b2140 0%,transparent 60%),var(--bg);color:var(--text);font-family:"Noto Sans Thai","Sarabun","Segoe UI",system-ui,sans-serif;line-height:1.55}
a{color:inherit;text-decoration:none}
.top{position:sticky;top:0;z-index:5;backdrop-filter:blur(10px);background:rgba(11,13,18,.78);border-bottom:1px solid var(--line)}
.top .in{max-width:1100px;margin:auto;display:flex;align-items:center;gap:18px;padding:12px 18px}
.logo{font-weight:700;letter-spacing:.3px;white-space:nowrap}.logo b{color:var(--brand)}
.nav{display:flex;gap:4px;flex:1}.nav a{padding:6px 12px;border-radius:9px;color:var(--mute)}
.nav a:hover{color:var(--text);background:var(--panel)}.nav a.on{color:var(--text);background:var(--panel2)}
.me{color:var(--mute);font-size:14px;white-space:nowrap}.me a{color:var(--brand)}
main{max-width:1100px;margin:auto;padding:26px 18px 70px}
main.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}
h1{font-size:27px;margin:6px 0 4px}h2{font-size:15px;margin:30px 0 12px;color:var(--mute);font-weight:600;letter-spacing:.4px}
.sub{color:var(--mute);margin:0 0 22px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}
.tile{display:block;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px;transition:.15s}
.tile:hover{transform:translateY(-3px);border-color:var(--brand);box-shadow:0 12px 32px rgba(0,0,0,.4)}
.tile.add{border-style:dashed;background:transparent;display:flex;align-items:center;justify-content:center;color:var(--mute);min-height:170px}
.tile.add:hover{color:var(--text)}
.av{width:48px;height:48px;border-radius:13px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:21px;color:#fff;flex:none}
.tile h3{margin:12px 0 6px;font-size:18px}
.meta{color:var(--mute);font-size:13px;margin-top:8px}
.pill{display:inline-block;padding:2px 11px;border-radius:99px;font-size:12.5px;border:1px solid var(--line);background:var(--panel2);color:var(--mute)}
.pill.online{color:var(--ok);border-color:#1f5a38;background:#10241a}
.pill.agent_only{color:var(--warn);border-color:#6a4a12;background:#2a2010}
.pill.offline{color:var(--bad);border-color:#6a2523;background:#2a1414}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px;margin-bottom:14px}
.head{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.head .grow{flex:1;min-width:210px}
.head h1{margin:0 0 4px}
.stats{display:flex;gap:20px;flex-wrap:wrap;margin-top:8px;color:var(--mute);font-size:13.5px}.stats b{color:var(--text);font-weight:600}
button,.btn{font:inherit;cursor:pointer;border:1px solid var(--line);background:var(--panel2);color:var(--text);padding:8px 15px;border-radius:10px;transition:.12s;display:inline-block}
button:hover,.btn:hover{border-color:var(--brand)}
.pri{background:linear-gradient(135deg,var(--brand),var(--brand2));border:0;color:#fff}
.dan{background:#3a1717;border-color:#6a2523;color:#ffb4b2}
button:disabled{opacity:.4;cursor:not-allowed}
input,select{font:inherit;background:#0e1118;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 12px;min-width:0}
input:focus,select:focus{outline:none;border-color:var(--brand)}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.toolbar select{flex:1;min-width:200px;max-width:460px}
.cmds{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.cmd{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px;display:flex;flex-direction:column;gap:9px}
.cmd h4{margin:0;font-size:15.5px}.cmd p{margin:0;color:var(--mute);font-size:13px;flex:1}
.cmd label{font-size:12.5px;color:var(--mute);display:block;margin-bottom:3px}.cmd input{width:100%}
.out{background:#080a0e;border:1px solid var(--line);border-radius:12px;padding:12px;font-family:ui-monospace,Consolas,monospace;font-size:13px;min-height:56px;max-height:260px;overflow:auto;white-space:pre-wrap;margin-top:14px;color:#cfd5e6}
table{width:100%;border-collapse:collapse}td,th{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;font-size:14px;vertical-align:top}th{color:var(--mute);font-weight:500}
.res{white-space:pre-wrap;word-break:break-word;color:var(--mute);font-size:13px;max-height:110px;overflow:auto;margin-top:2px}
.msg{background:#12261a;border:1px solid #1f5a38;border-radius:12px;padding:10px 14px;margin:12px 0}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#222838;border:1px solid var(--line);padding:10px 18px;border-radius:12px;z-index:9;display:none;max-width:90vw}
.empty{color:var(--mute);padding:6px 2px}.back{color:var(--mute);font-size:14px}.back:hover{color:var(--text)}
.login{text-align:center;max-width:380px;width:100%}.login h1{margin:0 0 6px}.big{padding:11px 22px;font-size:16px}
pre{background:#080a0e;border:1px solid var(--line);border-radius:12px;padding:14px;overflow:auto;font-size:13px}
ol.steps{padding-left:20px}ol.steps li{margin:10px 0}
@media(max-width:640px){.me .nm{display:none}.top .in{gap:10px}}
"""

JS = r"""
const CSRF=__CSRF__, NAME=__NAME__;
const $=s=>document.querySelector(s);
function toast(m){const t=$('#toast');if(!t)return;t.textContent=m;t.style.display='block';clearTimeout(window._tt);window._tt=setTimeout(()=>{t.style.display='none'},3500)}
function syncOnline(){const s=$('#state');if(!s)return;const on=s.dataset.online==='1';document.querySelectorAll('.cmd button').forEach(b=>{if(!b.dataset.busy)b.disabled=!on})}
async function refreshLive(){if(document.hidden)return;try{const r=await fetch(location.href,{credentials:'same-origin',cache:'no-store'});if(!r.ok)return;const d=new DOMParser().parseFromString(await r.text(),'text/html');document.querySelectorAll('[data-live]').forEach(el=>{const n=d.querySelector('[data-live="'+el.dataset.live+'"]');if(n)el.innerHTML=n.innerHTML});syncOnline()}catch(e){}}
if($('[data-live]'))setInterval(refreshLive,5000);
function line(ok,txt){const o=$('#out');if(!o)return;o.textContent='['+new Date().toLocaleTimeString('th-TH')+'] '+(ok?'✅ ':'❌ ')+txt+'\n'+o.textContent}
async function runCmd(btn){
  const card=btn.closest('.cmd'),g=$('#guild'),needG=card.dataset.guild==='1';
  if(needG&&(!g||!g.value)){toast('เลือกเซิร์ฟเวอร์ก่อน');return}
  const gname=g&&g.selectedOptions[0]?g.selectedOptions[0].textContent:'';
  if(card.dataset.danger==='1'&&!confirm('ยืนยันรัน "'+card.dataset.label+'"'+(needG?' ที่ '+gname:'')+' ?'))return;
  const args={};card.querySelectorAll('[data-arg]').forEach(i=>{if(i.value!=='')args[i.dataset.arg]=i.value});
  btn.dataset.busy='1';btn.disabled=true;const old=btn.textContent;btn.textContent='กำลังรัน…';
  try{
    const r=await fetch('/bots/'+NAME+'/run',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({command:card.dataset.name,guild_id:needG?g.value:'',args})});
    const d=await r.json().catch(()=>({message:'ผิดพลาด'}));
    if(!r.ok){line(false,d.message||'สั่งไม่สำเร็จ');toast(d.message||'สั่งไม่สำเร็จ');return}
    for(let i=0;i<100;i++){
      await new Promise(s=>setTimeout(s,1000));
      const rr=await fetch('/bots/'+NAME+'/cmd/'+d.id,{credentials:'same-origin',cache:'no-store'});
      if(!rr.ok)break;const x=await rr.json();
      if(x.state==='done'||x.state==='failed'||x.state==='expired'){line(x.state==='done',card.dataset.label+(needG?' @ '+gname:'')+': '+(x.result||(x.state==='expired'?'หมดเวลา บอทไม่ได้รับคำสั่ง':'')));break}
    }
  }catch(e){toast('เชื่อมต่อเว็บไม่ได้')}
  finally{delete btn.dataset.busy;btn.textContent=old;syncOnline();refreshLive()}
}
try{const g=$('#guild');if(g){const k='guild:'+NAME,v=localStorage.getItem(k);if(v&&[...g.options].some(o=>o.value===v))g.value=v;g.addEventListener('change',()=>{try{localStorage.setItem(k,g.value)}catch(_){}})}}catch(e){}
syncOnline();
"""

NAV = (("bots", "/", "บอท"), ("team", "/team", "ทีม"), ("logs", "/logs", "บันทึก"))
PILL = {"online": "🟢 ออนไลน์", "agent_only": "🟠 บอทไม่ตอบ", "offline": "🔴 ออฟไลน์", "never": "⚪ ยังไม่เคยเชื่อมต่อ"}
E = html.escape


def layout(request: Request, title: str, body: str, active: str = "", status: int = 200, name: str = ""):
    u = request.session.get("user") or {}
    nav = "".join(f'<a class="{"on" if k == active else ""}" href="{h}">{t}</a>' for k, h, t in NAV)
    js = JS.replace("__CSRF__", json.dumps(request.session.get("csrf", ""))).replace("__NAME__", json.dumps(name))
    return HTMLResponse(
        "<!doctype html><html lang=th><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{E(title)} · Control Hub</title><style>{CSS}</style></head><body>"
        f"<header class=top><div class=in><a class=logo href=/>◆ Control <b>Hub</b></a><nav class=nav>{nav}</nav>"
        f"<span class=me><span class=nm>{E(u.get('name', ''))} · </span><a href=/logout>ออกจากระบบ</a></span></div></header>"
        f"<main>{body}</main><div id=toast class=toast></div><script>{js}</script></body></html>", status_code=status)


def login_page(msg: str = "", status: int = 200):
    return HTMLResponse(
        "<!doctype html><html lang=th><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>Control Hub</title><style>{CSS}</style></head><body><main class=center><div class='card login'>"
        "<h1>◆ Control <b style='color:var(--brand)'>Hub</b></h1><p class=sub>แผงควบคุมบอท Discord</p>"
        f"{f'<p class=msg>{E(msg)}</p>' if msg else ''}"
        "<a class='btn pri big' href=/login>เข้าสู่ระบบด้วย Discord</a>"
        "<p class=meta>เฉพาะบัญชีที่เจ้าของอนุญาตเท่านั้น</p></div></main></body></html>", status_code=status)


def hue(name: str) -> int:
    return sum(map(ord, name)) * 37 % 360


def avatar(name: str) -> str:
    h = hue(name)
    return (f'<div class="av" style="background:linear-gradient(135deg,hsl({h} 70% 55%),hsl({(h + 45) % 360} 70% 42%))">'
            f'{E(name[:1].upper())}</div>')


def pill(state: str) -> str:
    return f'<span class="pill {state}">{PILL[state]}</span>'


def tile(name: str, st: dict) -> str:
    info, stat = st["info"], st["stat"]
    meta = []
    if st["state"] == "online":
        meta.append(f"{stat.get('guilds', len(info.get('guilds', [])))} เซิร์ฟเวอร์")
        if stat.get("latency_ms") is not None:
            meta.append(f"{stat['latency_ms']} ms")
    elif st["state"] == "never":
        meta.append("รอการเชื่อมต่อ")
    else:
        meta.append("เห็นล่าสุด " + ago(max(st["bot_seen"], st["agent_seen"])))
    sub = f'<div class="meta">{E(info["name"])}</div>' if info.get("name") else ""
    return (f'<a class="tile" href="/bots/{E(name)}">{avatar(name)}<h3>{E(name)}</h3>{sub}'
            f'<div style="margin-top:10px">{pill(st["state"])}</div><div class="meta">{E(" · ".join(meta))}</div></a>')


def dashboard_live() -> str:
    now = int(time.time())
    agents, infos = load_rows()
    tiles, online = "", 0
    for name in sorted(BOT_KEYS):
        st = status_of(name, agents, infos, now)
        online += st["state"] == "online"
        tiles += tile(name, st)
    tiles += '<a class="tile add" href="/add-bot">＋ เพิ่มบอทตัวใหม่</a>'
    return (f'<div class="toolbar"><span class="pill">บอททั้งหมด {len(BOT_KEYS)}</span>'
            f'<span class="pill online">ออนไลน์ {online}</span></div><div class="grid">{tiles}</div>')


def head_card(name: str, st: dict, csrf: str) -> str:
    info, stat, ag = st["info"], st["stat"], st["agent"]
    stats = []
    if st["state"] == "online":
        stats.append(f"<span><b>{len(info.get('guilds', []))}</b> เซิร์ฟเวอร์</span>")
        if stat.get("latency_ms") is not None:
            stats.append(f"<span>ปิง <b>{stat['latency_ms']}</b> ms</span>")
    elif st["state"] != "never":
        stats.append(f"<span>เห็นล่าสุด {ago(max(st['bot_seen'], st['agent_seen']))}</span>")
    if st["agent_on"] and ag.get("running"):
        stats.append(f"<span>ทำงานมา <b>{fmt_dur(ag.get('uptime'))}</b></span>")
        stats.append(f"<span>ล่มแล้วรีสตาร์ตเอง <b>{num(ag.get('crash_restarts'))}</b> ครั้ง</span>")
    if not st["agent_on"] and st["state"] != "never":
        stats.append("<span>ตัวคุมบอท (supervisor) ออฟไลน์</span>")
    title = "" if st["agent_on"] else " title='ตัวคุมบอท (supervisor.py) ไม่ออนไลน์ จึงสั่งรีสตาร์ตไม่ได้'"
    dn = " <span class=meta>" + E(info["name"]) + "</span>" if info.get("name") else ""
    return (f'<div class="card head">{avatar(name)}<div class="grow"><h1>{E(name)}</h1>{pill(st["state"])}'
            f'{dn}'
            f'<div class="stats">{"".join(stats)}</div></div>'
            f'<form method=post action="/bots/{E(name)}/restart" style="margin:0" '
            f'onsubmit="return confirm(\'รีสตาร์ตบอท {E(name)} ?\')">'
            f'<input type=hidden name=csrf value="{E(csrf)}"><button class=dan{"" if st["agent_on"] else " disabled"}{title}>🔄 รีสตาร์ตบอท</button></form>'
            f'<span id=state data-online="{1 if st["bot_on"] else 0}" hidden></span></div>')


def commands_panel(st: dict) -> str:
    info = st["info"]
    cmds, guilds = info.get("commands") or [], info.get("guilds") or []
    if not cmds:
        return ('<div class="card empty">ยังไม่มีข้อมูลคำสั่งจากบอทตัวนี้ บอทต้องเชื่อมกับเว็บผ่าน <b>hub_client.py</b> '
                'ก่อน (ดูวิธีที่หน้า <a href="/add-bot" style="color:var(--brand)">เพิ่มบอท</a>)</div>')
    opts = "".join(f'<option value="{E(str(g.get("id", "")))}">{E(str(g.get("name", "?")))} ({num(g.get("members"))} คน)</option>'
                   for g in guilds)
    cards = ""
    for c in cmds:
        inputs = ""
        for a in c.get("args", []):
            attrs = ""
            if a.get("type") == "int":
                attrs = f' type=number min="{E(str(a.get("min", "")))}" max="{E(str(a.get("max", "")))}"'
            else:
                attrs = f' type=text maxlength="{num(a.get("max_len")) or 200}"'
            ph = f' placeholder="{E(str(a["default"]))}"' if a.get("default") is not None else ""
            inputs += (f'<div><label>{E(str(a.get("label", a.get("name", ""))))}</label>'
                       f'<input data-arg="{E(str(a.get("name", "")))}"{attrs}{ph}></div>')
        danger = bool(c.get("danger"))
        label = str(c.get("label", c.get("name", "")))
        cards += (f'<div class="cmd" data-name="{E(str(c.get("name", "")))}" data-guild="{1 if c.get("guild", True) else 0}" '
                  f'data-danger="{1 if danger else 0}" data-label="{E(label)}"><h4>{E(label)}</h4>'
                  f'<p>{E(str(c.get("desc", "")))}</p>{inputs}'
                  f'<button class="{"dan" if danger else "pri"}" onclick="runCmd(this)">▶ รัน</button></div>')
    sel = (f'<select id="guild">{opts}</select>' if guilds
           else '<span class="empty">บอทยังไม่ได้อยู่ในเซิร์ฟเวอร์ไหน</span>')
    return (f'<h2>สั่งงาน</h2><div class="toolbar"><span class="meta" style="margin:0">เซิร์ฟเวอร์:</span>{sel}</div>'
            f'<div class="cmds">{cards}</div><div class="out" id="out">ผลลัพธ์ของคำสั่งจะขึ้นที่นี่…</div>')


def history_card(name: str, st: dict) -> str:
    labels = {c.get("name"): c.get("label", c.get("name")) for c in st["info"].get("commands", [])}
    gnames = {str(g.get("id")): g.get("name", "?") for g in st["info"].get("guilds", [])}
    icons = {"pending": "⏳ รอ", "sent": "⏳ กำลังรัน", "done": "✅", "failed": "❌", "expired": "⌛ หมดเวลา"}
    with closing(db()) as c:
        rows = c.execute("SELECT * FROM commands WHERE bot=? ORDER BY id DESC LIMIT 12", (name,)).fetchall()
    if not rows:
        return '<div class="card empty">ยังไม่มีประวัติการสั่งงาน</div>'
    body = ""
    for r in rows:
        act = "🔄 รีสตาร์ตบอท" if r["target"] == "agent" else str(labels.get(r["action"], r["action"]))
        g = gnames.get(str(r["guild_id"] or ""), "")
        res = f'<div class="res">{E((r["result"] or "")[:600])}</div>' if r["result"] else ""
        body += (f'<tr><td style="white-space:nowrap">{when(r["created_at"])}</td><td>{E(r["created_name"] or r["created_by"] or "")}</td>'
                 f'<td>{E(act)}{f" <span class=meta>@ {E(g)}</span>" if g else ""}{res}</td>'
                 f'<td style="white-space:nowrap">{icons.get(r["state"], E(str(r["state"])))}</td></tr>')
    return f'<div class="card"><table><tr><th>เวลา</th><th>ผู้สั่ง</th><th>คำสั่ง</th><th>สถานะ</th></tr>{body}</table></div>'


def guilds_card(st: dict) -> str:
    gs = st["info"].get("guilds") or []
    if not gs:
        return '<div class="card empty">ยังไม่มีข้อมูลเซิร์ฟเวอร์</div>'
    items = "".join(f'<div class="card" style="margin:0;padding:12px 14px"><b>{E(str(g.get("name", "?")))}</b>'
                    f'<div class="meta" style="margin:2px 0 0">{num(g.get("members"))} คน · ID {E(str(g.get("id", "")))}</div></div>'
                    for g in gs)
    return f'<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(220px,1fr))">{items}</div>'


def current_user(request: Request):
    u = request.session.get("user")
    if not u or not is_allowed(u["id"]):  # เช็กทุกครั้ง: ถูกลบจากรายชื่อแล้วเข้าไม่ได้ทันที
        request.session.clear()
        return None
    return u


def csrf_ok(request: Request, token: str) -> bool:
    return hmac.compare_digest(token or "", request.session.get("csrf", ""))


def owner_action(request: Request, csrf: str):
    u = current_user(request)
    if not u:
        raise HTTPException(401)
    if not csrf_ok(request, csrf):
        raise HTTPException(403, "CSRF")
    if u["id"] not in OWNER_IDS:
        raise HTTPException(403, "เฉพาะเจ้าของ")
    return u


def flash_html(request: Request) -> str:
    f = request.session.pop("flash", "")
    return f'<p class="msg">{E(f)}</p>' if f else ""


# ------------------------------------------------------------------ หน้าเว็บ
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not current_user(request):
        return login_page()
    body = (f'<h1>บอทของฉัน</h1><p class="sub">กดที่การ์ดเพื่อเข้าไปสั่งงานบอทแต่ละตัว</p>{flash_html(request)}'
            f'<div data-live="tiles">{dashboard_live()}</div>')
    return layout(request, "บอท", body, "bots")


@app.get("/bots/{name}", response_class=HTMLResponse)
def bot_page(name: str, request: Request):
    if not current_user(request):
        return RedirectResponse("/", 303)
    if name not in BOT_KEYS:
        return layout(request, "ไม่พบบอท", '<p>ไม่พบบอทชื่อนี้</p><a class="btn" href="/">กลับ</a>', "bots", 404)
    agents, infos = load_rows()
    st = status_of(name, agents, infos, int(time.time()))
    n = len(st["info"].get("guilds") or [])
    body = (f'<a class="back" href="/">← บอททั้งหมด</a>{flash_html(request)}'
            f'<div style="margin-top:10px" data-live="head">{head_card(name, st, request.session["csrf"])}</div>'
            f'{commands_panel(st)}'
            f'<h2>ประวัติการสั่งงาน</h2><div data-live="history">{history_card(name, st)}</div>'
            f'<h2>เซิร์ฟเวอร์ที่บอทอยู่ ({n})</h2><div data-live="guilds">{guilds_card(st)}</div>')
    return layout(request, name, body, "bots", name=name)


@app.post("/bots/{name}/restart")
def bot_restart(name: str, request: Request, csrf: str = Form("")):
    """ใครที่อยู่ในรายชื่อก็กดได้ (ไม่ทำลายข้อมูล) ทุกครั้งมีบันทึกว่าใครสั่ง"""
    u = current_user(request)
    if not u:
        raise HTTPException(401)
    if not csrf_ok(request, csrf):
        raise HTTPException(403, "CSRF")
    if name not in BOT_KEYS:
        request.session["flash"] = "ไม่รู้จักบอทนี้"
        return RedirectResponse("/", 303)
    now, queued = int(time.time()), False
    with closing(db()) as c, c:
        a = c.execute("SELECT last_seen FROM agents WHERE bot=?", (name,)).fetchone()
        recent = c.execute("SELECT 1 FROM commands WHERE bot=? AND target='agent' AND action='restart' AND created_at>? "
                           "AND state IN ('pending','sent','done')", (name, now - RESTART_COOLDOWN)).fetchone()
        if not a or now - a["last_seen"] > AGENT_ONLINE_SECS:
            msg = "ตัวคุมบอทออฟไลน์ สั่งรีสตาร์ตไม่ได้ (ถ้าทั้งเครื่อง VPS ค้าง ต้องรีสตาร์ตที่แผงของผู้ให้เช่า)"
        elif recent:
            msg = "เพิ่งสั่งรีสตาร์ตไป รอสักครู่แล้วค่อยลองใหม่"
        else:
            c.execute("INSERT INTO commands(bot,action,created_by,created_at,target,created_name) VALUES(?,?,?,?,?,?)",
                      (name, "restart", u["id"], now, "agent", u["name"]))
            msg, queued = "ส่งคำสั่งรีสตาร์ตแล้ว รอผลสักครู่", True
    if queued:  # เขียน audit นอกธุรกรรมข้างบน ไม่งั้นฐานข้อมูลล็อกตัวเอง
        log(u["id"], "restart_request", name)
    request.session["flash"] = msg
    return RedirectResponse(f"/bots/{name}", 303)


@app.post("/bots/{name}/run")
async def bot_run(name: str, request: Request):
    """สั่งคำสั่งของบอทจากหน้าเว็บ: เข้าคิว แล้วตัวบอทมารับไปรันเอง"""
    u = current_user(request)
    if not u:
        return JSONResponse({"message": "ต้องล็อกอินใหม่"}, 401)
    if not csrf_ok(request, request.headers.get("x-csrf", "")):
        return JSONResponse({"message": "โทเคนไม่ถูกต้อง ลองรีเฟรชหน้า"}, 403)
    if name not in BOT_KEYS:
        return JSONResponse({"message": "ไม่รู้จักบอทนี้"}, 404)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"message": "ข้อมูลไม่ถูกต้อง"}, 400)
    if not isinstance(body, dict):
        return JSONResponse({"message": "ข้อมูลไม่ถูกต้อง"}, 400)
    agents, infos = load_rows()
    st = status_of(name, agents, infos, int(time.time()))
    if not st["bot_on"]:
        return JSONResponse({"message": "บอทไม่ตอบสนอง สั่งงานไม่ได้ (ลองกดรีสตาร์ตบอท)"}, 409)
    cname = str(body.get("command", ""))
    spec = next((c for c in st["info"].get("commands", []) if c.get("name") == cname), None)
    if spec is None:
        return JSONResponse({"message": "บอทตัวนี้ไม่มีคำสั่งนี้"}, 400)
    guild_id = ""
    if spec.get("guild", True):
        guild_id = str(body.get("guild_id") or "")
        if guild_id not in {str(g.get("id")) for g in st["info"].get("guilds", [])}:
            return JSONResponse({"message": "เลือกเซิร์ฟเวอร์ที่บอทอยู่"}, 400)
    args, err = clean_args(spec, body.get("args"))
    if err:
        return JSONResponse({"message": err}, 400)
    now = int(time.time())
    with closing(db()) as c, c:
        busy = c.execute("SELECT COUNT(*) FROM commands WHERE bot=? AND target='bot' AND state IN ('pending','sent')",
                         (name,)).fetchone()[0]
        if busy >= MAX_PENDING:
            return JSONResponse({"message": "มีคำสั่งรอคิวเยอะเกินไป รอสักครู่"}, 429)
        cur = c.execute("INSERT INTO commands(bot,action,created_by,created_at,target,args,guild_id,created_name) "
                        "VALUES(?,?,?,?,?,?,?,?)", (name, cname, u["id"], now, "bot", json.dumps(args), guild_id, u["name"]))
        cid = cur.lastrowid
    log(u["id"], "cmd", f"{name}: {cname} guild={guild_id or '-'} args={json.dumps(args, ensure_ascii=False)}")
    return JSONResponse({"id": cid})


@app.get("/bots/{name}/cmd/{cid}")
def cmd_state(name: str, cid: int, request: Request):
    if not current_user(request):
        return JSONResponse({"message": "ต้องล็อกอินใหม่"}, 401)
    with closing(db()) as c:
        r = c.execute("SELECT state, result, created_at FROM commands WHERE id=? AND bot=?", (cid, name)).fetchone()
    if not r:
        return JSONResponse({"message": "ไม่พบคำสั่ง"}, 404)
    state = r["state"]
    if state in ("pending", "sent") and int(time.time()) - r["created_at"] > CMD_TTL + 30:
        state = "expired"
    return JSONResponse({"state": state, "result": r["result"] or ""})


@app.get("/team", response_class=HTMLResponse)
def team_page(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/", 303)
    owner, csrf = u["id"] in OWNER_IDS, request.session["csrf"]
    with closing(db()) as c:
        allowed = c.execute("SELECT * FROM allowlist ORDER BY added_at").fetchall()
    rows = "".join(f"<tr><td>{E(i)}</td><td>👑 เจ้าของ (.env)</td><td></td></tr>" for i in sorted(OWNER_IDS))
    for r in allowed:
        rm = (f'<form method=post action=/allow/remove style=margin:0><input type=hidden name=csrf value="{E(csrf)}">'
              f'<input type=hidden name=user_id value="{E(r["user_id"])}"><button class=dan>ลบ</button></form>') if owner else ""
        rows += f'<tr><td>{E(r["user_id"])}</td><td>เพิ่มโดย {E(r["added_by"])} · {when(r["added_at"])}</td><td>{rm}</td></tr>'
    add = (f'<form method=post action=/allow/add class=toolbar><input type=hidden name=csrf value="{E(csrf)}">'
           f'<input name=user_id placeholder="Discord User ID" pattern="[0-9]{{15,20}}" required style="flex:1;max-width:360px">'
           f'<button class=pri>เพิ่มคน</button></form>') if owner else '<p class=meta>เฉพาะเจ้าของที่เพิ่ม/ลบรายชื่อได้</p>'
    body = (f'<h1>ทีม</h1><p class="sub">คนที่ล็อกอินเข้าเว็บนี้ได้ (ล็อกอินด้วย Discord ของตัวเอง)</p>{flash_html(request)}'
            f'<div class="card"><table>{rows}</table></div>{add}')
    return layout(request, "ทีม", body, "team")


@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/", 303)
    with closing(db()) as c:
        logs = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    rows = "".join(f'<tr><td style="white-space:nowrap">{when(r["ts"])}</td><td>{E(r["actor"])}</td>'
                   f'<td>{E(r["action"])}</td><td>{E(r["detail"] or "")}</td></tr>' for r in logs)
    body = (f'<h1>บันทึก</h1><p class="sub">ใครทำอะไรบนเว็บนี้ (200 รายการล่าสุด)</p>'
            f'<div class="card"><table><tr><th>เวลา</th><th>ผู้ใช้ (ID)</th><th>การกระทำ</th><th>รายละเอียด</th></tr>{rows}</table></div>')
    return layout(request, "บันทึก", body, "logs")


ADD_BOT_CODE = '''import hub_client
hub = hub_client.HubClient(bot, os.getenv("HUB_URL"), os.getenv("HUB_BOT_KEY"), log=print)

@hub.command("ping", "🏓 Ping", "ทดสอบว่าบอทตอบ")
async def web_ping(guild):
    return f"pong จาก {guild.name}"

# ใน setup_hook ของบอท
asyncio.create_task(hub.run())'''


@app.get("/add-bot", response_class=HTMLResponse)
def add_bot_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/", 303)
    body = ('<a class="back" href="/">← บอททั้งหมด</a><h1 style="margin-top:10px">เพิ่มบอทตัวใหม่</h1>'
            '<p class="sub">ทำครั้งเดียวต่อบอท 1 ตัว</p><div class="card"><ol class="steps">'
            '<li>รัน <code>py setup_keys.py --add ชื่อบอทใหม่</code> จะได้ <code>,ชื่อบอทใหม่:รหัส</code> ให้ต่อท้าย '
            '<code>BOT_KEYS</code> ใน <code>.env</code> ของเว็บ แล้วรีสตาร์ตเว็บ และได้ '
            '<code>HUB_BOT_KEY=</code> ให้ใส่ใน <code>.env</code> ของบอทตัวนั้น พร้อม <code>HUB_URL=</code></li>'
            '<li>วาง <code>hub_client.py</code> และ <code>supervisor.py</code> ไว้โฟลเดอร์เดียวกับบอท</li>'
            '<li>ใส่โค้ดในบอท (ตัวอย่างด้านล่าง) ลงทะเบียนคำสั่งที่อยากให้สั่งจากเว็บได้ด้วย <code>@hub.command</code></li>'
            '<li>เปิดบอทด้วย <code>py supervisor.py</code> แล้วการ์ดของบอทจะโผล่ในหน้าแรก</li></ol></div>'
            f'<pre>{E(ADD_BOT_CODE)}</pre>')
    return layout(request, "เพิ่มบอท", body, "bots")


# ------------------------------------------------------------------ ล็อกอิน Discord
@app.get("/login")
def login(request: Request):
    state = request.session["state"] = secrets.token_urlsafe(24)
    q = urlencode({"client_id": CLIENT_ID, "redirect_uri": f"{BASE_URL}/callback", "response_type": "code",
                   "scope": "identify", "state": state, "prompt": "none"})
    return RedirectResponse(f"https://discord.com/oauth2/authorize?{q}")


@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    expected = request.session.pop("state", "")
    if not code or not expected or not hmac.compare_digest(state, expected):
        return login_page("ล็อกอินไม่สำเร็จ ลองใหม่อีกครั้ง", 400)
    try:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.post("https://discord.com/api/oauth2/token", data={
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "grant_type": "authorization_code",
                "code": code, "redirect_uri": f"{BASE_URL}/callback"})
            r.raise_for_status()
            me = await h.get("https://discord.com/api/users/@me",
                             headers={"Authorization": f"Bearer {r.json()['access_token']}"})
            me.raise_for_status()
            me = me.json()
    except (httpx.HTTPError, KeyError, ValueError):
        return login_page("คุยกับ Discord ไม่สำเร็จ ลองใหม่อีกครั้ง", 502)
    uid, name = str(me["id"]), me.get("global_name") or me.get("username", "?")
    if not is_allowed(uid):
        log(uid, "login_denied", name)
        return login_page("บัญชีนี้ไม่ได้อยู่ในรายชื่อที่เข้าเว็บได้ ติดต่อเจ้าของเว็บเพื่อขอสิทธิ์", 403)
    request.session.clear()
    request.session.update(user={"id": uid, "name": name}, csrf=secrets.token_urlsafe(24))
    log(uid, "login", name)
    return RedirectResponse("/", 303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)


@app.post("/allow/add")
def allow_add(request: Request, user_id: str = Form(""), csrf: str = Form("")):
    u = owner_action(request, csrf)
    request.session["flash"] = add_allowed(u["id"], user_id.strip(), "web")[1]
    return RedirectResponse("/team", 303)


@app.post("/allow/remove")
def allow_remove(request: Request, user_id: str = Form(""), csrf: str = Form("")):
    u = owner_action(request, csrf)
    request.session["flash"] = remove_allowed(u["id"], user_id.strip(), "web")[1]
    return RedirectResponse("/team", 303)


# ------------------------------------------------------------------ API ฝั่งบอท (ยืนยันตัวด้วยกุญแจของบอทแต่ละตัว)
@app.post("/api/bot/allowlist")
async def bot_allowlist(request: Request, x_bot_key: str = Header("")):
    """บอทเรียกมาที่นี่ เว็บเป็นฝ่ายตัดสินสิทธิ์เองจาก OWNER_IDS (ไม่เชื่อสิทธิ์ใน Discord)"""
    bot = bot_name(x_bot_key)
    if not bot:
        raise HTTPException(401)
    body = await request.json()
    actor, action, target = str(body.get("actor_id", "")), body.get("action"), str(body.get("target_id") or "")
    if actor not in OWNER_IDS:
        log(actor, "bot_denied", f"{bot}: {action}")
        return JSONResponse({"message": "เฉพาะเจ้าของเว็บเท่านั้นที่จัดการรายชื่อได้"}, 403)
    if action == "add":
        ok, msg = add_allowed(actor, target, bot)
    elif action == "remove":
        ok, msg = remove_allowed(actor, target, bot)
    elif action == "list":
        with closing(db()) as c:
            ids = sorted(OWNER_IDS) + [r["user_id"] for r in c.execute("SELECT user_id FROM allowlist")]
        ok, msg = True, "ผู้ที่เข้าเว็บได้:\n" + "\n".join(f"<@{i}> ({i})" for i in ids)
    else:
        return JSONResponse({"message": "คำสั่งไม่ถูกต้อง"}, 400)
    return JSONResponse({"message": msg}, 200 if ok else 400)


def take_pending(bot: str, target: str, now: int):
    """หยิบคำสั่งที่รออยู่ของบอท + ล้างคำสั่งที่ค้างเก่า (ทำในธุรกรรมเดียว)"""
    with closing(db()) as c, c:
        c.execute("UPDATE commands SET state='expired' WHERE bot=? AND state='pending' AND created_at<?", (bot, now - CMD_TTL))
        c.execute("UPDATE commands SET state='expired' WHERE bot=? AND state='sent' AND created_at<?", (bot, now - 600))
        rows = c.execute("SELECT * FROM commands WHERE bot=? AND target=? AND state='pending' ORDER BY id",
                         (bot, target)).fetchall()
        c.executemany("UPDATE commands SET state='sent' WHERE id=?", [(r["id"],) for r in rows])
    return rows


def finish_command(bot: str, target: str, body):
    try:
        cid, ok, msg = int(body["id"]), bool(body.get("ok")), str(body.get("message", ""))[:1500]
    except (ValueError, KeyError, TypeError):
        return JSONResponse({"message": "ข้อมูลไม่ถูกต้อง"}, 400)
    with closing(db()) as c, c:
        c.execute("UPDATE commands SET state=?, result=? WHERE id=? AND bot=? AND target=? AND state='sent'",
                  ("done" if ok else "failed", msg, cid, bot, target))
    return JSONResponse({"ok": True})


async def read_json(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


@app.post("/api/bot/poll")
async def bot_poll(request: Request, x_bot_key: str = Header("")):
    """ตัวบอท (hub_client.py) เรียกทุก ~3 วินาที: ส่งสัญญาณชีพ (+ รายชื่อเซิร์ฟเวอร์/คำสั่ง) และรับคำสั่งจากเว็บ"""
    bot = bot_name(x_bot_key)
    if not bot:
        raise HTTPException(401)
    body = await read_json(request)
    now = int(time.time())
    stat = json.dumps(body["stat"]) if isinstance(body.get("stat"), dict) else "{}"
    info = json.dumps(body["info"]) if isinstance(body.get("info"), dict) else None
    if info is not None and len(info) > 500_000:
        info = None
    with closing(db()) as c, c:
        if info is not None:
            c.execute("INSERT INTO bots_info VALUES(?,?,?,?) ON CONFLICT(bot) DO UPDATE SET "
                      "last_seen=excluded.last_seen, info=excluded.info, stat=excluded.stat", (bot, now, info, stat))
        else:
            c.execute("INSERT INTO bots_info VALUES(?,?,?,?) ON CONFLICT(bot) DO UPDATE SET "
                      "last_seen=excluded.last_seen, stat=excluded.stat", (bot, now, "{}", stat))
    rows = take_pending(bot, "bot", now)
    return JSONResponse({"commands": [{"id": r["id"], "name": r["action"], "args": jload(r["args"]),
                                       "guild_id": r["guild_id"] or "",
                                       "by": {"id": r["created_by"], "name": r["created_name"] or ""}} for r in rows]})


@app.post("/api/bot/result")
async def bot_result(request: Request, x_bot_key: str = Header("")):
    bot = bot_name(x_bot_key)
    if not bot:
        raise HTTPException(401)
    return finish_command(bot, "bot", await read_json(request))


@app.post("/api/agent/poll")
async def agent_poll(request: Request, x_bot_key: str = Header("")):
    """ตัวคุมบอท (supervisor.py) เรียกทุก ~5 วินาที: รายงานสถานะ + รับคำสั่งรีสตาร์ต"""
    bot = bot_name(x_bot_key)
    if not bot:
        raise HTTPException(401)
    body = await read_json(request)
    status = body.get("status")
    now = int(time.time())
    with closing(db()) as c, c:
        c.execute("INSERT INTO agents VALUES(?,?,?) ON CONFLICT(bot) DO UPDATE SET "
                  "last_seen=excluded.last_seen, status=excluded.status",
                  (bot, now, json.dumps(status if isinstance(status, dict) else {})[:2000]))
    rows = take_pending(bot, "agent", now)
    return JSONResponse({"commands": [{"id": r["id"], "action": r["action"]} for r in rows]})


@app.post("/api/agent/result")
async def agent_result(request: Request, x_bot_key: str = Header("")):
    bot = bot_name(x_bot_key)
    if not bot:
        raise HTTPException(401)
    return finish_command(bot, "agent", await read_json(request))
