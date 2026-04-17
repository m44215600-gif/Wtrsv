"""
wtr.py — WTR Render Server
Telethon-based listener for @wsotp200bot
Tracks number registration progress, manages OTP replies, reports to CF.
"""

import os
import asyncio
import threading
import time
import re
import hmac
import hashlib
import logging
from typing import Optional
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from telethon import TelegramClient, events
from telethon.sessions import StringSession

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
API_ID       = int(os.environ["TG_API_ID"])
API_HASH     = os.environ["TG_API_HASH"]
SESSION_STR  = os.environ["TG_SESSION"]
BOT_USERNAME = os.environ.get("BOT_USERNAME", "@wsotp200bot")
CF_URL       = os.environ["CF_URL"].rstrip("/")
SHARED_SECRET= os.environ["SHARED_SECRET"]   # same value set in CF env
ADMIN_KEY    = os.environ["ADMIN_KEY"]

OTP_TIMEOUT_SECS = 360   # 6 minutes

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("wtr")

# ─────────────────────────────────────────
# IN-MEMORY TRACKING
# ─────────────────────────────────────────
# Structure per tracked number:
# {
#   "8801616632459": {
#     "progress_count": 0|1|2,
#     "progress1_msg_id": int|None,
#     "progress2_msg_id": int|None,
#     "status": "waiting"|"progress1"|"progress2"|"success"|"failed"|"timeout",
#     "timeout_task": asyncio.Task|None,
#     "registration_id": str        # CF registration row id
#   }
# }
tracking: dict[str, dict] = {}
tracking_lock = asyncio.Lock()

# Telethon client (initialized at startup)
client: Optional[TelegramClient] = None
bot_entity = None

# ─────────────────────────────────────────
# SECURITY HELPERS
# ─────────────────────────────────────────
def verify_admin(key: str):
    if not hmac.compare_digest(key, ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")

def make_callback_sig(payload: str) -> str:
    """HMAC-SHA256 signature for CF callback verification."""
    return hmac.new(SHARED_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

async def post_to_cf(path: str, body: dict):
    """POST result back to CF worker with HMAC signature."""
    import json
    payload_str = json.dumps(body, separators=(",", ":"), sort_keys=True)
    sig = make_callback_sig(payload_str)
    headers = {
        "Content-Type": "application/json",
        "X-WTR-Signature": sig
    }
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{CF_URL}{path}", content=payload_str, headers=headers)
            log.info(f"CF callback {path} → {r.status_code}")
    except Exception as e:
        log.error(f"CF callback failed: {e}")

# ─────────────────────────────────────────
# TIMEOUT HANDLER
# ─────────────────────────────────────────
async def handle_timeout(number: str):
    await asyncio.sleep(OTP_TIMEOUT_SECS)
    async with tracking_lock:
        entry = tracking.get(number)
        if entry and entry["status"] not in ("success", "failed"):
            entry["status"] = "timeout"
            reg_id = entry.get("registration_id")
            log.info(f"Timeout for {number}")
    await post_to_cf("/wtr/callback", {
        "number": number,
        "registration_id": reg_id,
        "event": "timeout"
    })
    async with tracking_lock:
        tracking.pop(number, None)

# ─────────────────────────────────────────
# BOT MESSAGE PARSER
# ─────────────────────────────────────────
def extract_number_from_msg(text: str) -> Optional[str]:
    """
    Extract the phone number from bot messages.
    Bot always puts number at start of line like: 8801616632459 🔵 ...
    """
    if not text:
        return None
    # Match leading digits (phone number) at start of message
    m = re.match(r"^(\d{7,15})", text.strip())
    return m.group(1) if m else None

def classify_message(text: str) -> Optional[str]:
    """
    Returns event type based on bot message content:
    progress / try_later / success / invalid / retry_later / wrong_otp / wrong_format
    """
    if not text:
        return None
    t = text.strip()

    if "🔵" in t and "In Progress" in t:
        return "progress"
    if "🟡" in t and "Try later" in t:
        return "try_later"
    if "🟢" in t and "Success" in t:
        return "success"
    if "💰" in t and "New Reward Notification" in t:
        return "reward"
    if "please submit this number again in" in t.lower():
        return "retry_later"
    if "verification code can only be 6 digits" in t.lower():
        return "wrong_otp_format"
    if "this number is wrong" in t.lower() or "country code is not supported" in t.lower():
        return "invalid_number"
    # Wrong OTP turns progress2 into try_later
    if "🟡" in t:
        return "try_later"
    return None

# ─────────────────────────────────────────
# TELETHON EVENT HANDLER
# ─────────────────────────────────────────
async def on_bot_message(event):
    global bot_entity
    msg  = event.message
    text = msg.text or ""
    msg_id = msg.id

    # Only process messages from the bot
    try:
        sender = await event.get_sender()
        if not sender:
            return
        sender_username = getattr(sender, "username", "") or ""
        if sender_username.lower().replace("@","") != BOT_USERNAME.lower().replace("@",""):
            return
    except Exception:
        return

    event_type = classify_message(text)
    if not event_type:
        return

    number = extract_number_from_msg(text)

    log.info(f"Bot msg → type={event_type} number={number} msg_id={msg_id}")

    # ── Handle reward notification (no number prefix in this message)
    if event_type == "reward":
        # Extract number from reward message body
        m = re.search(r"Number:\s*(\d{7,15})", text)
        if m:
            number = m.group(1)
        if not number:
            return
        async with tracking_lock:
            entry = tracking.get(number)
            reg_id = entry.get("registration_id") if entry else None
            if entry:
                entry["status"] = "success"
                if entry.get("timeout_task"):
                    entry["timeout_task"].cancel()
        await post_to_cf("/wtr/callback", {
            "number": number,
            "registration_id": reg_id,
            "event": "success"
        })
        async with tracking_lock:
            tracking.pop(number, None)
        return

    if not number:
        return

    async with tracking_lock:
        entry = tracking.get(number)
        if not entry:
            # Not a number we're tracking
            return

        reg_id = entry.get("registration_id")

        if event_type == "progress":
            entry["progress_count"] += 1
            count = entry["progress_count"]

            if count == 1:
                entry["progress1_msg_id"] = msg_id
                entry["status"] = "progress1"
                log.info(f"{number} → Progress 1 (checking eligibility)")
                # Don't callback yet — wait for progress 2 or try_later

            elif count == 2:
                entry["progress2_msg_id"] = msg_id
                entry["status"] = "progress2"
                log.info(f"{number} → Progress 2 (OTP sent, need reply)")
                # Start timeout now (OTP window begins)
                if entry.get("timeout_task"):
                    entry["timeout_task"].cancel()
                entry["timeout_task"] = asyncio.create_task(handle_timeout(number))
                # Tell CF we need OTP from user
                await post_to_cf("/wtr/callback", {
                    "number": number,
                    "registration_id": reg_id,
                    "event": "needs_otp"
                })

        elif event_type == "try_later":
            entry["status"] = "failed"
            if entry.get("timeout_task"):
                entry["timeout_task"].cancel()
            fail_reason = "try_later"
            # Check if it was after OTP submit (wrong OTP)
            if entry.get("otp_submitted"):
                fail_reason = "wrong_otp"
            await post_to_cf("/wtr/callback", {
                "number": number,
                "registration_id": reg_id,
                "event": "failed",
                "reason": fail_reason
            })
            tracking.pop(number, None)

        elif event_type == "retry_later":
            # Dynamic wait — extract seconds
            m = re.search(r"(\d+)\s*second", text, re.IGNORECASE)
            wait_secs = int(m.group(1)) if m else 6
            await post_to_cf("/wtr/callback", {
                "number": number,
                "registration_id": reg_id,
                "event": "retry_later",
                "wait_seconds": wait_secs
            })

        elif event_type == "wrong_otp_format":
            await post_to_cf("/wtr/callback", {
                "number": number,
                "registration_id": reg_id,
                "event": "wrong_otp_format"
            })

        elif event_type == "invalid_number":
            entry["status"] = "failed"
            if entry.get("timeout_task"):
                entry["timeout_task"].cancel()
            await post_to_cf("/wtr/callback", {
                "number": number,
                "registration_id": reg_id,
                "event": "invalid_number"
            })
            tracking.pop(number, None)

# ─────────────────────────────────────────
# FASTAPI LIFESPAN
# ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global client, bot_entity
    log.info("Starting Telethon client...")
    client = TelegramClient(StringSession(SESSION_STR), API_ID, API_HASH)
    await client.start()
    bot_entity = await client.get_entity(BOT_USERNAME)
    client.add_event_handler(on_bot_message, events.NewMessage())
    log.info(f"Telethon connected. Listening for {BOT_USERNAME}...")
    yield
    log.info("Shutting down Telethon...")
    await client.disconnect()

app = FastAPI(title="wtr.py", lifespan=lifespan)

# ─────────────────────────────────────────
# REQUEST MODELS
# ─────────────────────────────────────────
class SendNumberReq(BaseModel):
    number: str
    registration_id: str

class SendOtpReq(BaseModel):
    number: str
    otp: str
    registration_id: str

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.get("/ping")
async def ping():
    """Keep-alive endpoint — CF cron hits this every 10 min."""
    return {"status": "ok", "ts": int(time.time())}


@app.post("/send-number")
async def send_number(req: SendNumberReq, x_admin_key: str = Header(...)):
    verify_admin(x_admin_key)

    number = req.number.strip().lstrip("+")
    if not number.isdigit() or len(number) < 7:
        raise HTTPException(status_code=400, detail="Invalid number format")

    async with tracking_lock:
        if number in tracking:
            raise HTTPException(status_code=409, detail="Number already being tracked")

        tracking[number] = {
            "progress_count": 0,
            "progress1_msg_id": None,
            "progress2_msg_id": None,
            "status": "waiting",
            "timeout_task": None,
            "otp_submitted": False,
            "registration_id": req.registration_id
        }

    try:
        await client.send_message(bot_entity, number)
        log.info(f"Sent {number} to bot")
    except Exception as e:
        async with tracking_lock:
            tracking.pop(number, None)
        raise HTTPException(status_code=500, detail=f"Failed to send to bot: {e}")

    return {"status": "sent", "number": number}


@app.post("/send-otp")
async def send_otp(req: SendOtpReq, x_admin_key: str = Header(...)):
    verify_admin(x_admin_key)

    number = req.number.strip().lstrip("+")
    otp    = req.otp.strip()

    if not otp.isdigit() or len(otp) != 6:
        raise HTTPException(status_code=400, detail="OTP must be exactly 6 digits")

    async with tracking_lock:
        entry = tracking.get(number)
        if not entry:
            raise HTTPException(status_code=404, detail="Number not being tracked")
        if entry["status"] != "progress2":
            raise HTTPException(status_code=409, detail=f"Not in OTP state (status={entry['status']})")
        msg_id = entry["progress2_msg_id"]
        if not msg_id:
            raise HTTPException(status_code=500, detail="Progress2 message ID missing")
        entry["otp_submitted"] = True

    try:
        await client.send_message(bot_entity, otp, reply_to=msg_id)
        log.info(f"OTP {otp} sent for {number} replying to msg {msg_id}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send OTP: {e}")

    return {"status": "otp_sent", "number": number}


@app.get("/status/{number}")
async def get_status(number: str, x_admin_key: str = Header(...)):
    verify_admin(x_admin_key)
    number = number.strip().lstrip("+")
    async with tracking_lock:
        entry = tracking.get(number)
    if not entry:
        return {"number": number, "status": "not_tracked"}
    return {
        "number": number,
        "status": entry["status"],
        "progress_count": entry["progress_count"],
        "has_progress2_msg": entry["progress2_msg_id"] is not None
    }


@app.get("/health")
async def health():
    connected = client.is_connected() if client else False
    return {
        "status": "ok" if connected else "degraded",
        "telethon_connected": connected,
        "tracked_numbers": len(tracking)
    }
