import asyncio
import hashlib
import hmac
import mimetypes
import os
import secrets
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_room_id() -> str:
    return secrets.token_urlsafe(8)


def _new_join_key() -> str:
    return secrets.token_urlsafe(24)


@dataclass
class Room:
    room_id: str
    title: str
    join_key_hash: str
    created_at_ms: int
    expires_at_ms: int
    connections: Set[WebSocket] = field(default_factory=set)
    messages: List[Dict[str, Any]] = field(default_factory=list)

    def is_expired(self) -> bool:
        return _now_ms() >= self.expires_at_ms


app = FastAPI()
app.add_middleware(ProxyHeadersMiddleware)
_rooms: Dict[str, Room] = {}
_rooms_lock = asyncio.Lock()

_STATIC_DIR = Path(__file__).parent / "static"
_APP_HTML = _STATIC_DIR / "index.html"
_UPLOAD_DIR = Path(__file__).parent / "uploads"
_DB_PATH = Path(__file__).parent / "chat.db"

ROOM_TTL_MS = 24 * 60 * 60 * 1000
MAX_MESSAGE_LEN = 2000
MAX_HISTORY = 200
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _db_init_sync() -> None:
    conn = _db_connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rooms (
              room_id TEXT PRIMARY KEY,
              title TEXT NOT NULL DEFAULT '临时会话',
              join_key_hash TEXT NOT NULL,
              created_at_ms INTEGER NOT NULL,
              expires_at_ms INTEGER NOT NULL
            );
            """
        )
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(rooms);").fetchall()}
        if "title" not in cols:
            conn.execute("ALTER TABLE rooms ADD COLUMN title TEXT NOT NULL DEFAULT '临时会话';")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              msg_id TEXT NOT NULL,
              room_id TEXT NOT NULL,
              sender_id TEXT NOT NULL,
              sender_name TEXT NOT NULL,
              kind TEXT NOT NULL,
              content TEXT NOT NULL,
              url TEXT NOT NULL,
              ts INTEGER NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_room_ts ON messages(room_id, ts);")
        conn.commit()
    finally:
        conn.close()


async def _run_db(fn, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: fn(*args))


def _db_try_create_room_sync(room_id: str, title: str, join_key_hash: str, created_at_ms: int, expires_at_ms: int) -> bool:
    conn = _db_connect()
    try:
        try:
            conn.execute(
                "INSERT INTO rooms(room_id, title, join_key_hash, created_at_ms, expires_at_ms) VALUES(?,?,?,?,?)",
                (room_id, title, join_key_hash, created_at_ms, expires_at_ms),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    finally:
        conn.close()


def _db_get_room_sync(room_id: str) -> Optional[Dict[str, Any]]:
    conn = _db_connect()
    try:
        row = conn.execute("SELECT * FROM rooms WHERE room_id = ?", (room_id,)).fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def _db_delete_room_sync(room_id: str) -> None:
    conn = _db_connect()
    try:
        conn.execute("DELETE FROM messages WHERE room_id = ?", (room_id,))
        conn.execute("DELETE FROM rooms WHERE room_id = ?", (room_id,))
        conn.commit()
    finally:
        conn.close()


def _db_insert_message_sync(message: Dict[str, Any]) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            """
            INSERT INTO messages(msg_id, room_id, sender_id, sender_name, kind, content, url, ts)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                message.get("msgId") or "",
                message.get("roomId") or "",
                message.get("senderId") or "",
                message.get("senderName") or "",
                message.get("kind") or "text",
                message.get("content") or "",
                message.get("url") or "",
                int(message.get("ts") or 0),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _db_get_recent_messages_sync(room_id: str, limit: int) -> List[Dict[str, Any]]:
    conn = _db_connect()
    try:
        rows = conn.execute(
            "SELECT msg_id, room_id, sender_id, sender_name, kind, content, url, ts FROM messages WHERE room_id = ? ORDER BY ts DESC LIMIT ?",
            (room_id, limit),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in reversed(rows):
            out.append(
                {
                    "type": "message",
                    "msgId": r["msg_id"],
                    "roomId": r["room_id"],
                    "senderId": r["sender_id"],
                    "senderName": r["sender_name"],
                    "kind": r["kind"],
                    "content": r["content"],
                    "url": r["url"],
                    "ts": r["ts"],
                }
            )
        return out
    finally:
        conn.close()


def _db_get_expired_room_ids_sync(now_ms: int) -> List[str]:
    conn = _db_connect()
    try:
        rows = conn.execute("SELECT room_id FROM rooms WHERE expires_at_ms <= ?", (now_ms,)).fetchall()
        return [r["room_id"] for r in rows]
    finally:
        conn.close()


async def _cleanup_loop() -> None:
    while True:
        await asyncio.sleep(30)
        now_ms = _now_ms()
        expired_from_db = await _run_db(_db_get_expired_room_ids_sync, now_ms)
        for rid in expired_from_db:
            async with _rooms_lock:
                room = _rooms.pop(rid, None)
            if room:
                for ws in list(room.connections):
                    try:
                        await ws.close(code=4000)
                    except Exception:
                        pass
            try:
                shutil.rmtree(_UPLOAD_DIR / rid, ignore_errors=True)
            except Exception:
                pass
            await _run_db(_db_delete_room_sync, rid)
        async with _rooms_lock:
            expired_ids = [rid for rid, room in _rooms.items() if room.is_expired()]
            for rid in expired_ids:
                room = _rooms.pop(rid, None)
                if not room:
                    continue
                for ws in list(room.connections):
                    try:
                        await ws.close(code=4000)
                    except Exception:
                        pass
                try:
                    shutil.rmtree(_UPLOAD_DIR / rid, ignore_errors=True)
                except Exception:
                    pass
                await _run_db(_db_delete_room_sync, rid)


@app.on_event("startup")
async def _startup() -> None:
    if not _STATIC_DIR.exists():
        _STATIC_DIR.mkdir(parents=True, exist_ok=True)
    if not _UPLOAD_DIR.exists():
        _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    await _run_db(_db_init_sync)
    asyncio.create_task(_cleanup_loop())


@app.get("/")
async def index() -> FileResponse:
    if not _APP_HTML.exists():
        raise HTTPException(status_code=500, detail="static/index.html not found")
    return FileResponse(_APP_HTML)

@app.head("/")
async def index_head() -> Response:
    return Response(status_code=200)


@app.get("/r/{room_id}")
async def room_page(room_id: str) -> FileResponse:
    if not _APP_HTML.exists():
        raise HTTPException(status_code=500, detail="static/index.html not found")
    return FileResponse(_APP_HTML)

@app.head("/r/{room_id}")
async def room_page_head(room_id: str) -> Response:
    return Response(status_code=200)


class CreateRoomBody(BaseModel):
    title: Optional[str] = None


@app.post("/api/rooms")
async def create_room(request: Request, body: Optional[CreateRoomBody] = None) -> JSONResponse:
    title = ""
    if body and body.title is not None:
        title = str(body.title).strip()
    if not title:
        title = "临时会话"
    if len(title) > 30:
        title = title[:30]

    now = _now_ms()
    expires_at = now + ROOM_TTL_MS

    room_id = ""
    join_key = ""
    join_key_hash = ""
    created = False
    for _ in range(20):
        room_id = _new_room_id()
        join_key = _new_join_key()
        join_key_hash = _sha256_hex(join_key)
        created = await _run_db(_db_try_create_room_sync, room_id, title, join_key_hash, now, expires_at)
        if created:
            break
    if not created:
        raise HTTPException(status_code=500, detail="create room failed")

    async with _rooms_lock:
        _rooms[room_id] = Room(
            room_id=room_id, title=title, join_key_hash=join_key_hash, created_at_ms=now, expires_at_ms=expires_at
        )

    base = str(request.base_url).rstrip("/")
    join_url = f"{base}/r/{room_id}?k={join_key}"
    return JSONResponse(
        {
            "roomId": room_id,
            "title": title,
            "joinUrl": join_url,
            "expiresAtMs": expires_at,
        }
    )


@app.get("/api/rooms/{room_id}")
async def get_room(room_id: str) -> JSONResponse:
    record = await _run_db(_db_get_room_sync, room_id)
    if not record:
        raise HTTPException(status_code=404, detail="room not found")
    if _now_ms() >= int(record["expires_at_ms"]):
        raise HTTPException(status_code=404, detail="room not found")

    async with _rooms_lock:
        room = _rooms.get(room_id)
        online = len(room.connections) if room else 0
    return JSONResponse(
        {
            "roomId": record["room_id"],
            "title": record.get("title") or "临时会话",
            "createdAtMs": int(record["created_at_ms"]),
            "expiresAtMs": int(record["expires_at_ms"]),
            "online": online,
        }
    )


async def _require_room_join(room_id: str, join_key: str) -> Dict[str, Any]:
    record = await _run_db(_db_get_room_sync, room_id)
    if not record:
        raise HTTPException(status_code=404, detail="room not found")
    if _now_ms() >= int(record["expires_at_ms"]):
        raise HTTPException(status_code=404, detail="room not found")
    if not hmac.compare_digest(str(record["join_key_hash"]), _sha256_hex(join_key)):
        raise HTTPException(status_code=401, detail="unauthorized")
    return record


def _image_ext_for_content_type(content_type: str) -> str:
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "image/jpeg":
        return ".jpg"
    if ct == "image/png":
        return ".png"
    if ct == "image/webp":
        return ".webp"
    if ct == "image/gif":
        return ".gif"
    guess = mimetypes.guess_extension(ct)
    if guess:
        return guess
    return ".bin"


@app.post("/api/rooms/{room_id}/images")
async def upload_room_image(room_id: str, request: Request, k: str = "", file: UploadFile = File(...)) -> JSONResponse:
    if not k:
        raise HTTPException(status_code=400, detail="missing k")

    await _require_room_join(room_id, k)

    content_type = (file.content_type or "").lower()
    if not content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="file must be image")

    ext = _image_ext_for_content_type(content_type)
    file_id = secrets.token_urlsafe(16)
    rel_path = f"/u/{room_id}/{file_id}{ext}"
    out_path = (_UPLOAD_DIR / room_id / f"{file_id}{ext}").resolve()
    room_dir = out_path.parent
    if not str(out_path).startswith(str((_UPLOAD_DIR / room_id).resolve())):
        raise HTTPException(status_code=400, detail="invalid path")
    room_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    try:
        with open(out_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="file too large")
                f.write(chunk)
    except HTTPException:
        try:
            if out_path.exists():
                out_path.unlink()
        except Exception:
            pass
        raise
    except Exception:
        try:
            if out_path.exists():
                out_path.unlink()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="upload failed")

    return JSONResponse(
        {
            "roomId": room_id,
            "url": rel_path,
            "contentType": content_type,
            "bytes": written,
        }
    )


@app.get("/u/{room_id}/{name}")
async def get_upload(room_id: str, name: str) -> FileResponse:
    safe_name = os.path.basename(name)
    path = (_UPLOAD_DIR / room_id / safe_name).resolve()
    base = (_UPLOAD_DIR / room_id).resolve()
    if not str(path).startswith(str(base)):
        raise HTTPException(status_code=404, detail="not found")
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(path)


async def _send_json(ws: WebSocket, payload: Dict[str, Any]) -> None:
    await ws.send_json(payload)


async def _broadcast(room: Room, payload: Dict[str, Any]) -> None:
    to_remove: List[WebSocket] = []
    for ws in list(room.connections):
        try:
            await _send_json(ws, payload)
        except Exception:
            to_remove.append(ws)
    for ws in to_remove:
        room.connections.discard(ws)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    room_id = ws.query_params.get("roomId") or ""
    join_key = ws.query_params.get("k") or ""
    client_id = ws.query_params.get("clientId") or ""

    await ws.accept()

    if not room_id or not join_key:
        await ws.close(code=4400)
        return

    if not client_id:
        client_id = uuid.uuid4().hex

    record = await _run_db(_db_get_room_sync, room_id)
    if not record or _now_ms() >= int(record["expires_at_ms"]):
        await ws.close(code=4404)
        return
    if not hmac.compare_digest(str(record["join_key_hash"]), _sha256_hex(join_key)):
        await ws.close(code=4401)
        return

    history = await _run_db(_db_get_recent_messages_sync, room_id, 50)
    async with _rooms_lock:
        room = _rooms.get(room_id)
        if not room:
            room = Room(
                room_id=room_id,
                title=str(record.get("title") or "临时会话"),
                join_key_hash=str(record["join_key_hash"]),
                created_at_ms=int(record["created_at_ms"]),
                expires_at_ms=int(record["expires_at_ms"]),
            )
            _rooms[room_id] = room
        room.connections.add(ws)

    await _send_json(
        ws,
        {
            "type": "joined",
            "roomId": room_id,
            "clientId": client_id,
            "history": history,
        },
    )

    await _broadcast(
        room,
        {
            "type": "presence",
            "event": "join",
            "clientId": client_id,
            "ts": _now_ms(),
        },
    )

    try:
        while True:
            data = await ws.receive_json()
            if not isinstance(data, dict):
                continue

            msg_type = data.get("type")
            if msg_type == "ping":
                await _send_json(ws, {"type": "pong", "ts": _now_ms()})
                continue

            if msg_type != "message":
                continue

            sender_name = str(data.get("senderName") or "").strip()
            if len(sender_name) > 50:
                sender_name = sender_name[:50]

            kind = str(data.get("kind") or "text").strip().lower()
            if kind not in ("text", "image"):
                continue

            content = ""
            url = ""
            if kind == "text":
                content = str(data.get("content") or "").strip()
                if not content:
                    continue
                if len(content) > MAX_MESSAGE_LEN:
                    content = content[:MAX_MESSAGE_LEN]
            else:
                url = str(data.get("url") or "").strip()
                if not url.startswith(f"/u/{room_id}/"):
                    continue

            message = {
                "type": "message",
                "kind": kind,
                "msgId": uuid.uuid4().hex,
                "roomId": room_id,
                "senderId": client_id,
                "senderName": sender_name,
                "content": content,
                "url": url,
                "ts": _now_ms(),
            }
            await _run_db(_db_insert_message_sync, message)
            async with _rooms_lock:
                current_room = _rooms.get(room_id)
                if not current_room or current_room.is_expired():
                    await ws.close(code=4404)
                    return
                room = current_room

            await _broadcast(room, message)
    except WebSocketDisconnect:
        async with _rooms_lock:
            room = _rooms.get(room_id)
            if room:
                room.connections.discard(ws)
        if room:
            await _broadcast(
                room,
                {
                    "type": "presence",
                    "event": "leave",
                    "clientId": client_id,
                    "ts": _now_ms(),
                },
            )
    except Exception:
        async with _rooms_lock:
            room = _rooms.get(room_id)
            if room:
                room.connections.discard(ws)
        try:
            await ws.close(code=1011)
        except Exception:
            pass
