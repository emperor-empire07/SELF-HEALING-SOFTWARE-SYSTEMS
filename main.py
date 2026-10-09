"""Self-healing backend: monitors services, heals them, pushes live events over WebSocket."""
import asyncio, base64, hashlib, hmac, json, os, random, sqlite3, time
import urllib.error, urllib.request
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

STAGES = ["Detect", "Diagnose", "Fix", "Verify"]
SERVICES = {"api": "API gateway", "db": "Database", "cache": "Cache", "queue": "Job queue"}
BUGS = {
    "api": ["Memory leak in request handler", "Unhandled exception on /orders"],
    "db": ["Connection pool exhausted", "Slow query blocking writes"],
    "cache": ["Stale keys served to users", "Eviction loop detected"],
    "queue": ["Worker stuck on a failed job", "Retry storm detected"],
}
state = {k: dict(id=k, name=v, health=100.0, latency=25.0, status="ok", message="") for k, v in SERVICES.items()}
incidents: list[dict] = []   # active
history: list[float] = [100.0] * 60
stats = dict(bugs=0, fixed=0, total_s=0.0)
clients: set[WebSocket] = set()
auto = dict(enabled=True)


# ---------- database (SQLite) and login ----------
DB_PATH = os.getenv("DB_PATH", "incidents.db")
SECRET = os.getenv("SECRET_KEY", "change-me-in-production")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


def run(sql: str, args: tuple = ()):
    c = sqlite3.connect(DB_PATH)
    try:
        rows = c.execute(sql, args).fetchall()
        c.commit()
        return rows
    finally:
        c.close()


def hash_pw(pw: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()


def init_db():
    run("CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, service TEXT, name TEXT, message TEXT, started REAL, seconds REAL)")
    run("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, salt BLOB, hash TEXT)")
    run("CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, url TEXT, heal_url TEXT)")
    for sid, name, url, heal in run("SELECT id, name, url, heal_url FROM sites"):
        sites[sid] = new_site(sid, name, url, heal)
    if not run("SELECT 1 FROM users WHERE username=?", (ADMIN_USER,)):
        salt = os.urandom(16)
        run("INSERT INTO users VALUES (?,?,?)", (ADMIN_USER, salt, hash_pw(ADMIN_PASSWORD, salt)))
    bugs, fixed, total = run("SELECT COUNT(*), COUNT(seconds), COALESCE(SUM(seconds),0) FROM incidents")[0]
    stats.update(bugs=bugs, fixed=fixed, total_s=total)


def make_token(user: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"u": user, "exp": time.time() + 86400}).encode()).decode()
    return f"{body}.{hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()}"


def read_token(token: str):
    try:
        body, sig = token.split(".")
        if hmac.compare_digest(sig, hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()):
            data = json.loads(base64.urlsafe_b64decode(body))
            if data["exp"] > time.time():
                return data["u"]
    except Exception:
        pass
    return None


def current_user(authorization: str = Header(default="")):
    user = read_token(authorization.removeprefix("Bearer "))
    if not user:
        raise HTTPException(401, "Not logged in")
    return user


class Login(BaseModel):
    username: str
    password: str


# ---------- websites ----------
sites: dict[int, dict] = {}


def new_site(sid, name, url, heal_url):
    return dict(id=sid, name=name, url=url, heal_url=heal_url or "", status="checking", code=None, latency=None,
                checked=0.0, checks=0, ups=0, busy=False, inc=None, down_since=0.0)


def public(s):
    return dict(id=s["id"], name=s["name"], url=s["url"], status=s["status"], code=s["code"], latency=s["latency"],
                uptime=(100 * s["ups"] / s["checks"]) if s["checks"] else None, can_heal=bool(s["heal_url"]))


def probe(url, method="GET", timeout=8):
    start = time.time()
    try:
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "self-healing-monitor"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        return None, None
    return code, (time.time() - start) * 1000


async def check_site(s):
    try:
        code, ms = await asyncio.to_thread(probe, s["url"])
        up = code is not None and code < 400
        was = s["status"]
        s.update(code=code, latency=ms, checked=time.time(), status="up" if up else "down")
        s["checks"] += 1
        s["ups"] += up
        if not up and was != "down":
            s["down_since"] = time.time()
            s["inc"] = f"site-{s['id']}-{int(time.time() * 1000)}"
            stats["bugs"] += 1
            reason = f"HTTP {code}" if code else "no response"
            run("INSERT INTO incidents VALUES (?,?,?,?,?,NULL)", (s["inc"], "site", s["name"], f"Website down ({reason})", s["down_since"]))
            extra = ""
            if s["heal_url"]:  # self-healing hook: ask your server to restart the site
                await asyncio.to_thread(probe, s["heal_url"], "POST")
                extra = " Restart request sent."
            await alert("bug", f"Website down: {s['name']}", f"{s['url']} gave {reason}.{extra}")
        elif up and was == "down":
            took = time.time() - s["down_since"]
            stats["fixed"] += 1
            stats["total_s"] += took
            run("UPDATE incidents SET seconds=? WHERE id=?", (took, s["inc"]))
            await alert("good", f"{s['name']} is back online", f"Recovered after {took:.0f} seconds.")
    finally:
        s["busy"] = False


class SiteIn(BaseModel):
    url: str
    name: str = ""
    heal_url: str = ""


def clean_url(u: str) -> str:
    u = u.strip()
    if u and not u.startswith(("http://", "https://")):
        u = "https://" + u
    host = urlparse(u).netloc
    if "." not in host and "localhost" not in host:
        raise HTTPException(400, "Enter a valid web address, for example example.com")
    return u


def snapshot():
    avg = sum(s["health"] for s in state.values()) / len(state)
    mttr = stats["total_s"] / stats["fixed"] if stats["fixed"] else None
    return dict(type="state", services=list(state.values()), incidents=incidents, history=history, sites=[public(s) for s in sites.values()],
                stats=dict(health=avg, bugs=stats["bugs"], fixed=stats["fixed"], mttr=mttr), auto=auto["enabled"])


async def broadcast(msg: dict):
    for ws in list(clients):
        try:
            await ws.send_json(msg)
        except Exception:
            clients.discard(ws)


async def alert(level: str, title: str, body: str):
    await broadcast(dict(type="alert", level=level, title=title, body=body, time=time.time()))


async def apply_fix(service_id: str):
    """Hook for REAL healing: restart a container, roll back a deploy, clear a cache, etc."""
    await asyncio.sleep(1)


async def heal(inc: dict):
    s = state[inc["service"]]
    for i in range(len(STAGES)):
        inc["stage"] = i
        if i == 1:
            s["status"] = "fixing"
        if i == 2:
            await apply_fix(inc["service"])
            s["health"] = max(s["health"], 65)
        await asyncio.sleep(2)
    took = time.time() - inc["started"]
    run("UPDATE incidents SET seconds=? WHERE id=?", (took, inc["id"]))
    stats["fixed"] += 1; stats["total_s"] += took
    s.update(status="ok", health=99.0, latency=25.0, message="")
    incidents.remove(inc)
    await alert("good", f"{s['name']} is healthy again", f"Fixed automatically in {took:.1f} seconds.")


async def inject_bug(service_id: str | None = None):
    free = [k for k, s in state.items() if s["status"] == "ok"]
    if not free:
        await alert("warn", "Already healing", "Wait for the current fixes to finish.")
        return None
    sid = service_id if service_id in free else random.choice(free)
    s, msg = state[sid], random.choice(BUGS[sid])
    s.update(status="bug", message=msg, health=random.uniform(30, 45))
    inc = dict(id=f"inc-{int(time.time()*1000)}", service=sid, name=s["name"], message=msg, stage=0, started=time.time())
    incidents.append(inc); stats["bugs"] += 1
    run("INSERT INTO incidents VALUES (?,?,?,?,?,NULL)", (inc["id"], sid, s["name"], msg, inc["started"]))
    await alert("bug", f"Bug detected in {s['name']}", f"{msg}. Automatic healing started.")
    asyncio.create_task(heal(inc))
    return inc


async def monitor():
    while True:
        for s in state.values():
            if s["status"] == "ok":
                s["health"] = min(100, max(94, s["health"] + random.uniform(-.8, 1.2)))
                s["latency"] = min(60, max(12, s["latency"] + random.uniform(-3, 3)))
            else:
                s["latency"] = min(900, s["latency"] + random.uniform(60, 140))
                if s["status"] == "fixing":
                    s["health"] = min(98, s["health"] + 4)
        if auto["enabled"] and random.random() < 0.04:
            await inject_bug()
        now = time.time()
        for site in list(sites.values()):
            if not site["busy"] and now - site["checked"] > 15:
                site["busy"] = True
                asyncio.create_task(check_site(site))
        history.append(sum(s["health"] for s in state.values()) / len(state)); history.pop(0)
        await broadcast(snapshot())
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    task = asyncio.create_task(monitor())
    yield
    task.cancel()


app = FastAPI(title="Self-Healing API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.post("/api/login")
def login(body: Login):
    r = run("SELECT salt, hash FROM users WHERE username=?", (body.username,))
    if not r or not hmac.compare_digest(hash_pw(body.password, r[0][0]), r[0][1]):
        raise HTTPException(401, "Wrong username or password")
    return {"token": make_token(body.username)}


@app.get("/api/incidents")
def past_incidents(_: str = Depends(current_user)):
    rows = run("SELECT name, message, started, seconds FROM incidents ORDER BY started DESC LIMIT 20")
    return [dict(name=r[0], message=r[1], started=r[2], seconds=r[3]) for r in rows]


@app.get("/api/state")
def get_state(_: str = Depends(current_user)):
    return snapshot()


@app.post("/api/inject")
async def inject(service: str | None = None, _: str = Depends(current_user)):
    return await inject_bug(service)


@app.post("/api/auto/{enabled}")
def set_auto(enabled: bool, _: str = Depends(current_user)):
    auto["enabled"] = enabled
    return auto


@app.post("/api/sites")
def add_site(body: SiteIn, _: str = Depends(current_user)):
    if len(sites) >= 20:
        raise HTTPException(400, "You can monitor up to 20 websites")
    url = clean_url(body.url)
    heal = clean_url(body.heal_url) if body.heal_url.strip() else ""
    if any(s["url"] == url for s in sites.values()):
        raise HTTPException(400, "This website is already added")
    name = body.name.strip() or urlparse(url).netloc
    sid = run("INSERT INTO sites(name, url, heal_url) VALUES (?,?,?) RETURNING id", (name, url, heal))[0][0]
    sites[sid] = new_site(sid, name, url, heal)
    return public(sites[sid])


@app.delete("/api/sites/{sid}")
def remove_site(sid: int, _: str = Depends(current_user)):
    run("DELETE FROM sites WHERE id=?", (sid,))
    sites.pop(sid, None)
    return {"ok": True}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = ""):
    await ws.accept()
    if not read_token(token):
        await ws.close(code=4401)
        return
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)