"""
server/main.py — FastAPI-сервер Secure Telegram Sender.

Улучшения v2:
  - JWT-аутентификация: /register выдаёт токен, /send требует его
  - Защита /register от перезаписи чужого ключа через подпись старым ключом
  - Rate limiting (sliding window, без сторонних зависимостей)
  - Логирование всех действий в server.log
  - Проверка Chat ID через Telegram Bot API при регистрации
"""

import base64
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

import httpx
import jwt
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
from telegram_sender import send_file
from crypto import load_public, verify_signature
from dotenv import load_dotenv
load_dotenv()

# ── Логирование ───────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler("server.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("secure_sender")

# ── Конфигурация ──────────────────────────────────────────────────────────────

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production-use-long-random-string")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 86400  # 24 часа

# ── Приложение ────────────────────────────────────────────────────────────────

app = FastAPI(title="Secure Sender Server", version="2.0")
security = HTTPBearer()

# ── Rate Limiting (sliding window) ────────────────────────────────────────────

_rate_lock = threading.Lock()
_rate_store: dict = defaultdict(list)

RATE_LIMITS = {
    "/register": (5, 60),
    "/send":     (20, 60),
    "/user":     (60, 60),
}

def _check_rate_limit(ip: str, path: str) -> None:
    limit, window = None, None
    for prefix, (lim, win) in RATE_LIMITS.items():
        if path.startswith(prefix):
            limit, window = lim, win
            break
    if limit is None:
        return
    now = time.monotonic()
    key = f"{ip}:{path}"
    with _rate_lock:
        _rate_store[key] = [t for t in _rate_store[key] if now - t < window]
        if len(_rate_store[key]) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Слишком много запросов. Подождите {window} секунд.",
            )
        _rate_store[key].append(now)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    try:
        _check_rate_limit(ip, request.url.path)
    except HTTPException as e:
        log.warning("Rate limit: ip=%s path=%s", ip, request.url.path)
        return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    return await call_next(request)

# ── База данных ───────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "db.sqlite")
_local = threading.local()

def _get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                public_key    TEXT NOT NULL,
                chat_id       TEXT NOT NULL,
                registered_at TEXT NOT NULL
            )
        """)
        _local.conn.execute("""
            CREATE TABLE IF NOT EXISTS send_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                sender     TEXT NOT NULL,
                recipient  TEXT NOT NULL,
                sent_at    TEXT NOT NULL,
                file_size  INTEGER
            )
        """)
        _local.conn.commit()
    return _local.conn

# ── JWT ───────────────────────────────────────────────────────────────────────

def _create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен истёк. Зарегистрируйтесь заново.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Недействительный токен.")

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    return _decode_token(credentials.credentials)

# ── Проверка Chat ID ──────────────────────────────────────────────────────────

async def _verify_chat_id(chat_id: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        log.warning("TELEGRAM_BOT_TOKEN не задан — проверка chat_id пропущена")
        return True
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{token}/getChat",
                params={"chat_id": chat_id},
            )
            return r.json().get("ok", False)
    except Exception as e:
        log.error("Ошибка проверки chat_id %s: %s", chat_id, e)
        return True  # При недоступности Telegram не блокируем

# ── Схемы ─────────────────────────────────────────────────────────────────────

class UserIn(BaseModel):
    username: str
    public_key: str
    chat_id: str
    old_key_signature: str | None = None  # base64, нужна только при перерегистрации

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip().lstrip("@")
        if not v or len(v) > 64:
            raise ValueError("username пустой или слишком длинный")
        if not re.match(r"^[\w\-\.]+$", v):
            raise ValueError("username содержит недопустимые символы")
        return v

    @field_validator("chat_id")
    @classmethod
    def chat_id_valid(cls, v: str) -> str:
        v = v.strip()
        if not v.lstrip("-").isdigit():
            raise ValueError("chat_id должен быть числом")
        return v

    @field_validator("public_key")
    @classmethod
    def pubkey_valid(cls, v: str) -> str:
        if "BEGIN PUBLIC KEY" not in v:
            raise ValueError("Некорректный публичный ключ PEM")
        return v

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/register")
async def register(user: UserIn, request: Request):
    conn = _get_conn()
    ip = request.client.host if request.client else "unknown"

    existing = conn.execute(
        "SELECT public_key FROM users WHERE username=?", (user.username,)
    ).fetchone()

    if existing:
        # Пользователь уже существует — требуем подпись старым ключом
        if not user.old_key_signature:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Пользователь уже существует. Для обновления ключа "
                    "предоставьте old_key_signature — подпись нового публичного "
                    "ключа старым приватным ключом (base64)."
                ),
            )
        try:
            old_pub = load_public(existing["public_key"])
            sig_bytes = base64.b64decode(user.old_key_signature)
            if not verify_signature(old_pub, user.public_key.encode(), sig_bytes):
                raise HTTPException(
                    status_code=403,
                    detail="Подпись старым ключом недействительна. Обновление отклонено.",
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Ошибка проверки подписи: {e}")
        log.info("Re-register: username=%s ip=%s", user.username, ip)
    else:
        log.info("New register: username=%s ip=%s", user.username, ip)

    # Проверка Chat ID через Telegram
    if not await _verify_chat_id(user.chat_id):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Chat ID {user.chat_id} не найден в Telegram. "
                "Убедитесь, что вы написали боту хотя бы одно сообщение."
            ),
        )

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO users "
        "(username, public_key, chat_id, registered_at) VALUES (?,?,?,?)",
        (user.username, user.public_key, user.chat_id, now),
    )
    conn.commit()

    token = _create_token(user.username)
    log.info("Token issued: username=%s", user.username)
    return {
        "status": "ok",
        "username": user.username,
        "token": token,
        "expires_in": JWT_EXPIRE_SECONDS,
    }


@app.get("/user/{username}")
def get_user(username: str):
    row = _get_conn().execute(
        "SELECT public_key, chat_id FROM users WHERE username=?", (username,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return {"public_key": row["public_key"], "chat_id": row["chat_id"]}


@app.post("/send")
async def send_file_api(
    request: Request,
    username: str,
    file: UploadFile = File(...),
    sender: str = Depends(get_current_user),  # JWT обязателен
):
    conn = _get_conn()
    ip = request.client.host if request.client else "unknown"

    row = conn.execute(
        "SELECT chat_id FROM users WHERE username=?", (username,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Получатель не найден")

    content = await file.read()
    file_size = len(content)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        await send_file(tmp_path, row["chat_id"],
                  caption=f"Зашифрованный файл от {sender}")
    finally:
        os.unlink(tmp_path)

    # Логируем без содержимого
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO send_log (sender, recipient, sent_at, file_size) "
        "VALUES (?,?,?,?)",
        (sender, username, now, file_size),
    )
    conn.commit()
    log.info("Sent: from=%s to=%s size=%d ip=%s", sender, username, file_size, ip)

    return {"status": "sent", "from": sender, "to": username, "size": file_size}


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)