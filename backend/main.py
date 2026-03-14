"""
VortexChat Backend v3 — FastAPI + WebSockets
pip install fastapi uvicorn python-jose[cryptography] python-multipart
(passlib и bcrypt НЕ нужны — используем встроенный hashlib)
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import json, uuid, os, re, hashlib, secrets

app = FastAPI(title="VortexChat API v3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SECRET   = os.environ.get("SECRET_KEY", "vortex-super-secret-2025")
ALGO     = "HS256"
EXP_DAYS = 7
UPLOAD   = "uploads"
os.makedirs(UPLOAD, exist_ok=True)

# Хеширование паролей без passlib/bcrypt (совместимо с Python 3.14+)
def hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}:{h}"

def verify_pw(password: str, hashed: str) -> bool:
    try:
        salt, h = hashed.split(":", 1)
        return secrets.compare_digest(
            hashlib.sha256((salt + password).encode("utf-8")).hexdigest(), h
        )
    except Exception:
        return False
oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login")

# ── In-memory DB ────────────────────────────────────────────
# { user_id: { id, username, email, password, bio, status, avatar, banner } }
DB_USERS: Dict[str, dict] = {}

# { user_id: [friend_id, ...] }
DB_FRIENDS: Dict[str, List[str]] = {}

# { to_user_id: [from_user_id, ...] }
DB_REQUESTS: Dict[str, List[str]] = {}

# { channel_id: [ {id,author_id,author_name,content,ts} ] }
DB_MSGS: Dict[str, List[dict]] = {}

# Active WebSocket connections { user_id: [WebSocket] }
WS: Dict[str, List[WebSocket]] = {}

# ── Helpers ─────────────────────────────────────────────────
def make_token(uid: str) -> str:
    exp = datetime.utcnow() + timedelta(days=EXP_DAYS)
    return jwt.encode({"sub": uid, "exp": exp}, SECRET, algorithm=ALGO)

async def current_user(token: str = Depends(oauth2)) -> dict:
    try:
        uid = jwt.decode(token, SECRET, algorithms=[ALGO]).get("sub")
        if uid not in DB_USERS:
            raise HTTPException(401, "Неверный токен")
        return DB_USERS[uid]
    except JWTError:
        raise HTTPException(401, "Неверный токен")

def pub(u: dict) -> dict:
    return {k: v for k, v in u.items() if k != "password"}

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    parts = email.split("@")
    if len(parts) != 2:
        return False
    domain = parts[1]
    if "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    local = parts[0]
    if len(local) < 1 or len(local) > 64:
        return False
    return True

async def ws_send(uid: str, data: dict):
    """Отправить сообщение конкретному пользователю по WebSocket"""
    if uid not in WS:
        return
    dead = []
    for sock in WS[uid]:
        try:
            await sock.send_text(json.dumps(data))
        except Exception:
            dead.append(sock)
    for sock in dead:
        WS[uid].remove(sock)

async def ws_broadcast(data: dict, exclude: str = None):
    for uid in list(WS.keys()):
        if uid != exclude:
            await ws_send(uid, data)

# ── AUTH ────────────────────────────────────────────────────
class RegBody(BaseModel):
    username: str
    email: str
    password: str

@app.post("/auth/register")
async def register(body: RegBody):
    name  = body.username.strip()
    email = body.email.strip().lower()
    pw    = body.password

    # Валидации
    if len(name) < 2:
        raise HTTPException(400, "Имя минимум 2 символа")
    if not re.match(r'^[a-zA-Zа-яА-ЯёЁ0-9_]+$', name):
        raise HTTPException(400, "Имя: только буквы, цифры и _")
    if not validate_email(email):
        raise HTTPException(400, "Неверный формат email. Пример: user@gmail.com")
    if len(pw) < 8:
        raise HTTPException(400, "Пароль минимум 8 символов")

    # Уникальность
    for u in DB_USERS.values():
        if u["email"] == email:
            raise HTTPException(400, "Email уже зарегистрирован")
        if u["username"].lower() == name.lower():
            raise HTTPException(400, f"Имя '{name}' уже занято")

    uid = str(uuid.uuid4())
    DB_USERS[uid] = {
        "id": uid, "username": name, "email": email,
        "password": hash_pw(pw), "bio": "",
        "status": "online", "avatar": None,
        "banner": "linear-gradient(135deg,#5a3fd4,#7c5cfc,#f72585)",
        "created_at": datetime.utcnow().isoformat()
    }
    DB_FRIENDS[uid]  = []
    DB_REQUESTS[uid] = []
    return {"access_token": make_token(uid), "token_type": "bearer", "user": pub(DB_USERS[uid])}

@app.post("/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    email = form.username.strip().lower()
    user  = next((u for u in DB_USERS.values() if u["email"] == email), None)
    if not user or not verify_pw(form.password, user["password"]):
        raise HTTPException(401, "Неверный email или пароль")
    # Обновляем статус
    DB_USERS[user["id"]]["status"] = "online"
    return {"access_token": make_token(user["id"]), "token_type": "bearer", "user": pub(user)}

# ── USERS ───────────────────────────────────────────────────
@app.get("/users/me")
async def get_me(u=Depends(current_user)):
    return pub(u)

class UpdateBody(BaseModel):
    username: Optional[str] = None
    bio: Optional[str]      = None
    status: Optional[str]   = None
    banner: Optional[str]   = None

@app.patch("/users/me")
async def update_me(body: UpdateBody, u=Depends(current_user)):
    uid = u["id"]
    if body.username:
        n = body.username.strip()
        # Проверка уникальности
        for other in DB_USERS.values():
            if other["id"] != uid and other["username"].lower() == n.lower():
                raise HTTPException(400, f"Имя '{n}' уже занято")
        DB_USERS[uid]["username"] = n
    if body.bio is not None:
        DB_USERS[uid]["bio"] = body.bio
    if body.status:
        DB_USERS[uid]["status"] = body.status
        await ws_broadcast({"type":"status_update","user_id":uid,"status":body.status}, exclude=uid)
    if body.banner:
        DB_USERS[uid]["banner"] = body.banner
    return pub(DB_USERS[uid])

@app.post("/users/me/avatar")
async def upload_avatar(file: UploadFile = File(...), u=Depends(current_user)):
    ext = file.filename.rsplit(".",1)[-1].lower()
    if ext not in ("jpg","jpeg","png","gif","webp"):
        raise HTTPException(400, "Только jpg/png/gif/webp")
    fname = f"{u['id']}.{ext}"
    path  = os.path.join(UPLOAD, fname)
    with open(path, "wb") as f:
        f.write(await file.read())
    DB_USERS[u["id"]]["avatar"] = f"/uploads/{fname}"
    return {"avatar_url": f"/uploads/{fname}"}

@app.get("/users/search")
async def search_users(q: str, u=Depends(current_user)):
    """Поиск пользователей по точному имени или подстроке"""
    q_lower = q.strip().lower()
    results = []
    for other in DB_USERS.values():
        if other["id"] == u["id"]:
            continue
        if q_lower in other["username"].lower():
            results.append(pub(other))
    return results[:10]

@app.get("/users/exists/{username}")
async def user_exists(username: str, u=Depends(current_user)):
    """Проверить, существует ли пользователь с таким именем"""
    found = next((other for other in DB_USERS.values()
                  if other["username"].lower() == username.strip().lower()
                  and other["id"] != u["id"]), None)
    if found:
        return {"found": True, "user": pub(found)}
    return {"found": False}

# ── FRIENDS ─────────────────────────────────────────────────
@app.post("/friends/request/{username}")
async def send_request(username: str, u=Depends(current_user)):
    target = next((other for other in DB_USERS.values()
                   if other["username"].lower() == username.strip().lower()), None)
    if not target:
        raise HTTPException(404, f"Пользователь '{username}' не найден")
    tid = target["id"]
    uid = u["id"]
    if tid == uid:
        raise HTTPException(400, "Нельзя добавить себя")
    if uid in DB_FRIENDS.get(tid, []):
        raise HTTPException(400, "Вы уже друзья")
    DB_REQUESTS.setdefault(tid, [])
    if uid not in DB_REQUESTS[tid]:
        DB_REQUESTS[tid].append(uid)
    # Реальная доставка через WS если получатель онлайн
    await ws_send(tid, {
        "type": "friend_request",
        "from_id": uid,
        "from_name": u["username"],
        "from_color": "#9b7fff"
    })
    return {"ok": True, "message": f"Заявка отправлена {target['username']}"}

@app.get("/friends/requests/incoming")
async def incoming_requests(u=Depends(current_user)):
    reqs = DB_REQUESTS.get(u["id"], [])
    return [pub(DB_USERS[rid]) for rid in reqs if rid in DB_USERS]

@app.get("/friends/requests/outgoing")
async def outgoing_requests(u=Depends(current_user)):
    uid = u["id"]
    result = []
    for other_id, reqs in DB_REQUESTS.items():
        if uid in reqs and other_id in DB_USERS:
            result.append(pub(DB_USERS[other_id]))
    return result

@app.post("/friends/accept/{requester_id}")
async def accept_request(requester_id: str, u=Depends(current_user)):
    uid = u["id"]
    if requester_id not in DB_REQUESTS.get(uid, []):
        raise HTTPException(400, "Заявка не найдена")
    # Добавляем в друзья обоих
    DB_FRIENDS.setdefault(uid, [])
    DB_FRIENDS.setdefault(requester_id, [])
    if requester_id not in DB_FRIENDS[uid]:
        DB_FRIENDS[uid].append(requester_id)
    if uid not in DB_FRIENDS[requester_id]:
        DB_FRIENDS[requester_id].append(uid)
    # Удаляем заявку
    DB_REQUESTS[uid] = [r for r in DB_REQUESTS[uid] if r != requester_id]
    # Уведомляем отправителя
    await ws_send(requester_id, {
        "type": "friend_accepted",
        "by_id": uid,
        "by_name": u["username"]
    })
    return {"ok": True}

@app.post("/friends/decline/{requester_id}")
async def decline_request(requester_id: str, u=Depends(current_user)):
    uid = u["id"]
    DB_REQUESTS[uid] = [r for r in DB_REQUESTS.get(uid, []) if r != requester_id]
    return {"ok": True}

@app.post("/friends/cancel/{target_id}")
async def cancel_request(target_id: str, u=Depends(current_user)):
    uid = u["id"]
    if target_id in DB_REQUESTS:
        DB_REQUESTS[target_id] = [r for r in DB_REQUESTS[target_id] if r != uid]
    return {"ok": True}

@app.delete("/friends/{friend_id}")
async def remove_friend(friend_id: str, u=Depends(current_user)):
    uid = u["id"]
    DB_FRIENDS[uid]      = [f for f in DB_FRIENDS.get(uid, [])      if f != friend_id]
    DB_FRIENDS[friend_id] = [f for f in DB_FRIENDS.get(friend_id, []) if f != uid]
    return {"ok": True}

@app.get("/friends")
async def get_friends(u=Depends(current_user)):
    ids = DB_FRIENDS.get(u["id"], [])
    result = []
    for fid in ids:
        if fid not in DB_USERS:
            continue
        f = dict(pub(DB_USERS[fid]))
        f["online"] = fid in WS and len(WS[fid]) > 0
        result.append(f)
    return result

# ── MESSAGES ────────────────────────────────────────────────
class MsgBody(BaseModel):
    content: str
    channel_id: str

@app.get("/messages/{channel_id}")
async def get_messages(channel_id: str, limit: int = 50, u=Depends(current_user)):
    msgs = DB_MSGS.get(channel_id, [])
    return msgs[-limit:]

@app.post("/messages/{channel_id}")
async def send_message(channel_id: str, body: MsgBody, u=Depends(current_user)):
    msg = {
        "id": str(uuid.uuid4()),
        "channel_id": channel_id,
        "content": body.content,
        "author_id": u["id"],
        "author_name": u["username"],
        "ts": datetime.utcnow().strftime("%H:%M"),
        "timestamp": datetime.utcnow().isoformat()
    }
    DB_MSGS.setdefault(channel_id, []).append(msg)
    await ws_broadcast({"type": "message", "channel_id": channel_id, "data": msg})
    return msg

@app.delete("/messages/{msg_id}")
async def delete_message(msg_id: str, u=Depends(current_user)):
    for ch_id, msgs in DB_MSGS.items():
        for m in msgs:
            if m["id"] == msg_id:
                if m["author_id"] != u["id"]:
                    raise HTTPException(403, "Не твоё сообщение")
                DB_MSGS[ch_id].remove(m)
                await ws_broadcast({"type":"message_delete","message_id":msg_id,"channel_id":ch_id})
                return {"ok": True}
    raise HTTPException(404, "Сообщение не найдено")

# ── WEBSOCKET ────────────────────────────────────────────────
@app.websocket("/ws/{user_id}")
async def ws_endpoint(sock: WebSocket, user_id: str):
    await sock.accept()
    WS.setdefault(user_id, []).append(sock)
    if user_id in DB_USERS:
        DB_USERS[user_id]["status"] = "online"
        await ws_broadcast({"type":"status_update","user_id":user_id,"status":"online"}, exclude=user_id)
    try:
        while True:
            raw  = await sock.receive_text()
            data = json.loads(raw)
            t    = data.get("type")
            if t in ("offer","answer","ice-candidate"):
                target = data.get("target")
                if target:
                    await ws_send(target, {**data, "from": user_id})
            elif t == "typing":
                await ws_broadcast({"type":"typing","user_id":user_id,"channel_id":data.get("channel_id")}, exclude=user_id)
            elif t == "ping":
                await sock.send_text(json.dumps({"type":"pong"}))
    except WebSocketDisconnect:
        WS[user_id] = [s for s in WS[user_id] if s is not sock]
        if not WS[user_id]:
            del WS[user_id]
            if user_id in DB_USERS:
                DB_USERS[user_id]["status"] = "offline"
            await ws_broadcast({"type":"status_update","user_id":user_id,"status":"offline"})

# ── STATIC & HEALTH ─────────────────────────────────────────
try:
    app.mount("/uploads", StaticFiles(directory=UPLOAD), name="uploads")
except:
    pass

@app.get("/health")
async def health():
    return {
        "ok": True,
        "users": len(DB_USERS),
        "online": len(WS),
        "user_list": [u["username"] for u in DB_USERS.values()]
    }

if __name__ == "__main__":
    import uvicorn
    print("\n" + "═"*50)
    print("  ⚡  VortexChat Backend v3")
    print("  🌐  http://localhost:8000")
    print("  📖  Docs: http://localhost:8000/docs")
    print("  ❤️   Health: http://localhost:8000/health")
    print("═"*50 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)