

import os
import pyotp
import socketio
import jwt
import hashlib
import time
import sqlite3
import ipaddress
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from functools import wraps
import asyncio

load_dotenv()

# ============== 보안 설정 ==============
SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(32).hex())
ADMIN_ID = os.getenv("ADMIN_ID", "admin")
ADMIN_PW = os.getenv("ADMIN_PW", "admin123")
ADMIN_2FA_SECRET = os.getenv("ADMIN_2FA_SECRET", pyotp.random_base32())
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Rate Limiting 설정
RATE_LIMIT_WINDOW = 60  # 1분
RATE_LIMIT_MAX_REQUESTS = 100

# IP 화이트리스트 (관리자용)
ADMIN_IP_WHITELIST = os.getenv("ADMIN_IP_WHITELIST", "").split(",") if os.getenv("ADMIN_IP_WHITELIST") else []

# ============== 데이터베이스 초기화 ==============
def init_database():
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    
    # 사용자 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nickname TEXT UNIQUE NOT NULL,
        room TEXT,
        ip_address TEXT,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 방 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        secret TEXT NOT NULL,
        creator TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        max_users INTEGER DEFAULT 50,
        user_count INTEGER DEFAULT 0
    )''')
    
    # 메시지 로그 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room TEXT NOT NULL,
        sender TEXT NOT NULL,
        message TEXT,
        message_type TEXT DEFAULT 'text',
        file_name TEXT,
        encrypted_content TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 관리자 감사 로그 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 세션 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT UNIQUE NOT NULL,
        user_type TEXT NOT NULL,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # IP 화이트리스트 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS ip_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        description TEXT,
        added_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # 접속자 카운트 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
        ip_address TEXT PRIMARY KEY,
        request_count INTEGER DEFAULT 0,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    conn.commit()
    conn.close()

init_database()

# ============== FastAPI 앱 설정 ==============
app = FastAPI(title="VaultChat Advanced API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*', max_decode_size=10*1024*1024)
socket_app = socketio.ASGIApp(sio, app)

# ============== 서버 데이터 구조 ==============
user_sessions = {}  # { sid: {"nickname": "...", "room": "...", "ip": "...", "user_id": ...} }
admin_tokens = {}   # { token: {"admin_id": "...", "exp": ..., "ip": ...} }
rooms_otp_cache = {}  # { "방이름": {"otp": "...", "expires": ...} }

# ============== 보안 유틸리티 ==============

def hash_password(password: str) -> str:
    """비밀번호 해싱 (SHA-256 + salt)"""
    salt = SECRET_KEY[:16]
    return hashlib.sha256((salt + password + SECRET_KEY).encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """비밀번호 검증"""
    return hash_password(password) == hashed

def generate_jwt_token(admin_id: str, ip_address: str) -> str:
    """JWT 토큰 생성"""
    payload = {
        "admin_id": admin_id,
        "ip": ip_address,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    admin_tokens[token] = {
        "admin_id": admin_id,
        "exp": payload["exp"],
        "ip": ip_address
    }
    return token

def verify_jwt_token(token: str, ip_address: str) -> bool:
    """JWT 토큰 검증"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("ip") != ip_address:
            return False  # IP 불일치
        if token in admin_tokens:
            return True
        return False
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False

def check_rate_limit(ip_address: str) -> bool:
    """Rate Limiting 검사"""
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    
    now = datetime.utcnow()
    c.execute("SELECT request_count, window_start FROM rate_limits WHERE ip_address = ?", (ip_address,))
    result = c.fetchone()
    
    if result:
        count, window_start = result
        window_start_dt = datetime.fromisoformat(window_start)
        
        if (now - window_start_dt).total_seconds() < RATE_LIMIT_WINDOW:
            if count >= RATE_LIMIT_MAX_REQUESTS:
                conn.close()
                return False
            c.execute("UPDATE rate_limits SET request_count = request_count + 1 WHERE ip_address = ?", (ip_address,))
        else:
            c.execute("UPDATE rate_limits SET request_count = 1, window_start = ? WHERE ip_address = ?", (now.isoformat(), ip_address))
    else:
        c.execute("INSERT INTO rate_limits (ip_address, request_count, window_start) VALUES (?, 1, ?)", (ip_address, now.isoformat()))
    
    conn.commit()
    conn.close()
    return True

def check_ip_whitelist(ip_address: str) -> bool:
    """IP 화이트리스트 검사"""
    if not ADMIN_IP_WHITELIST or ADMIN_IP_WHITELIST == ['']:
        return True  # 화이트리스트가 없으면 허용
    
    try:
        client_ip = ipaddress.ip_address(ip_address)
        for allowed_ip in ADMIN_IP_WHITELIST:
            allowed_ip = allowed_ip.strip()
            if not allowed_ip:
                continue
            if '/' in allowed_ip:
                if client_ip in ipaddress.ip_network(allowed_ip):
                    return True
            else:
                if str(client_ip) == allowed_ip:
                    return True
        return False
    except ValueError:
        return False

def log_admin_action(admin_id: str, action: str, target: str = None, details: str = None, ip_address: str = None):
    """관리자 행동 로깅"""
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    c.execute("INSERT INTO admin_logs (admin_id, action, target, details, ip_address) VALUES (?, ?, ?, ?, ?)",
              (admin_id, action, target, details, ip_address))
    conn.commit()
    conn.close()

def get_client_ip(sid: str = None) -> str:
    """클라이언트 IP 가져오기"""
    if sid and sid in user_sessions:
        return user_sessions[sid].get("ip", "unknown")
    return "unknown"

# ============== REST API 엔드포인트 ==============

@app.get("/")
async def root():
    return {"message": "VaultChat Advanced API", "version": "2.0", "status": "running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/admin/login")
async def admin_login(request: Request):
    """관리자 로그인 (2FA 포함)"""
    data = await request.json()
    admin_id = data.get("admin_id", "")
    password = data.get("password", "")
    code_2fa = data.get("code_2fa", "")
    
    ip_address = request.client.host
    
    # Rate Limit 체크
    if not check_rate_limit(ip_address):
        return JSONResponse(status_code=429, content={"error": "너무 많은 요청입니다. 잠시 후 다시 시도하세요."})
    
    # 자격 증명 검증
    if admin_id != ADMIN_ID or password != ADMIN_PW:
        log_admin_action("failed_login", "LOGIN_FAILED", details=f"잘못된 자격 증명", ip_address=ip_address)
        return JSONResponse(status_code=401, content={"error": "잘못된 관리자 정보입니다."})
    
    # 2FA 검증
    totp = pyotp.TOTP(ADMIN_2FA_SECRET)
    if not totp.verify(code_2fa):
        log_admin_action(admin_id, "LOGIN_FAILED", details="잘못된 2FA 코드", ip_address=ip_address)
        return JSONResponse(status_code=401, content={"error": "잘못된 2FA 코드입니다."})
    
    # IP 화이트리스트 체크 (필요시)
    if ADMIN_IP_WHITELIST and not check_ip_whitelist(ip_address):
        log_admin_action(admin_id, "LOGIN_BLOCKED", details=f"IP 미허용: {ip_address}", ip_address=ip_address)
        return JSONResponse(status_code=403, content={"error": "이 IP 주소는 관리자 접속이 허용되지 않습니다."})
    
    # JWT 토큰 생성
    token = generate_jwt_token(admin_id, ip_address)
    log_admin_action(admin_id, "LOGIN_SUCCESS", ip_address=ip_address)
    
    return {
        "success": True,
        "token": token,
        "message": "관리자 로그인 성공",
        "2fa_secret": ADMIN_2FA_SECRET  # 초기 설정 시에만 표시
    }

@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    """관리자 대시보드 통계"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    ip_address = request.client.host
    
    if not token or not verify_jwt_token(token, ip_address):
        return JSONResponse(status_code=401, content={"error": "인증되지 않은 접근입니다."})
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    
    # 통계 수집
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM rooms WHERE is_active = 1")
    active_rooms = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM messages")
    total_messages = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM admin_logs WHERE timestamp > datetime('now', '-24 hours')")
    recent_admin_actions = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM sessions WHERE is_active = 1 AND expires_at > datetime('now')")
    active_sessions = c.fetchone()[0]
    
    conn.close()
    
    return {
        "total_users": total_users,
        "active_rooms": active_rooms,
        "total_messages": total_messages,
        "recent_admin_actions": recent_admin_actions,
        "active_sessions": active_sessions
    }

@app.get("/api/admin/logs")
async def admin_logs(request: Request, limit: int = 50):
    """관리자 감사 로그 조회"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    ip_address = request.client.host
    
    if not token or not verify_jwt_token(token, ip_address):
        return JSONResponse(status_code=401, content={"error": "인증되지 않은 접근입니다."})
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    c.execute("SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = c.fetchall()
    conn.close()
    
    return {"logs": [
        {
            "id": log[0],
            "admin_id": log[1],
            "action": log[2],
            "target": log[3],
            "details": log[4],
            "ip_address": log[5],
            "timestamp": log[6]
        } for log in logs
    ]}

# ============== Socket.IO 이벤트 ==============

@sio.event
async def connect(sid, environ):
    ip_address = environ.get('REMOTE_ADDR', 'unknown')
    user_sessions[sid] = {"ip": ip_address}
    print(f"클라이언트 접속: {sid} from {ip_address}")

@sio.event
async def disconnect(sid):
    if sid in user_sessions:
        info = user_sessions[sid]
        room = info.get('room')
        nick = info.get('nickname')
        
        # DB에서 사용자 정보 업데이트
        if nick:
            conn = sqlite3.connect('vaultchat.db')
            c = conn.cursor()
            c.execute("UPDATE users SET last_active = datetime('now') WHERE nickname = ?", (nick,))
            conn.commit()
            conn.close()
        
        del user_sessions[sid]
        
        # 방에 남은 인원 확인
        if room:
            remaining = [s for s, data in user_sessions.items() if data.get('room') == room]
            if not remaining:
                # 빈 방 처리
                conn = sqlite3.connect('vaultchat.db')
                c = conn.cursor()
                c.execute("UPDATE rooms SET is_active = 0, user_count = 0 WHERE name = ?", (room,))
                conn.commit()
                conn.close()
            else:
                await sio.emit('notification', {'msg': f"'{nick}'님이 나갔습니다.", 'type': 'system'}, room=room)

@sio.event
async def admin_auth(sid, data):
    """관리자 인증 (JWT 토큰)"""
    token = data.get('token', '')
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    if not verify_jwt_token(token, ip_address):
        await sio.emit('admin_auth_fail', {'msg': "유효하지 않은 토큰입니다."}, to=sid)
        return
    
    # 방 목록 및 통계 가져오기
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    
    c.execute("SELECT name, user_count, created_at FROM rooms WHERE is_active = 1")
    rooms = [{"name": r[0], "count": r[1], "created": r[2]} for r in c.fetchall()]
    
    c.execute("SELECT nickname, room, joined_at FROM users ORDER BY joined_at DESC LIMIT 20")
    recent_users = [{"nickname": u[0], "room": u[1], "joined": u[2]} for u in c.fetchall()]
    
    c.execute("SELECT action, admin_id, timestamp FROM admin_logs ORDER BY timestamp DESC LIMIT 10")
    recent_logs = [{"action": l[0], "admin": l[1], "time": l[2]} for l in c.fetchall()]
    
    conn.close()
    
    await sio.emit('admin_auth_success', {
        'rooms': rooms,
        'recent_users': recent_users,
        'recent_logs': recent_logs
    }, to=sid)

@sio.event
async def create_room(sid, data):
    """방 생성"""
    room_name = data.get('room', '').strip()
    creator = data.get('creator', 'Unknown')
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    if not room_name:
        await sio.emit('join_fail', {'msg': "방 이름을 입력해주세요."}, to=sid)
        return
    
    # Rate Limit 체크
    if not check_rate_limit(ip_address):
        await sio.emit('join_fail', {'msg': "너무 많은 요청입니다. 잠시 후 다시 시도하세요."}, to=sid)
        return
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    
    c.execute("SELECT name FROM rooms WHERE name = ? AND is_active = 1", (room_name,))
    if c.fetchone():
        conn.close()
        await sio.emit('join_fail', {'msg': "이미 존재하는 방 이름입니다."}, to=sid)
        return
    
    # 방 생성
    secret = pyotp.random_base32()
    c.execute("INSERT INTO rooms (name, secret, creator, user_count) VALUES (?, ?, ?, 1)",
              (room_name, secret, creator))
    conn.commit()
    conn.close()
    
    await sio.enter_room(sid, room_name)
    user_sessions[sid] = {
        "nickname": creator,
        "room": room_name,
        "ip": ip_address,
        "is_creator": True
    }
    
    # OTP 생성 및 캐싱
    totp = pyotp.TOTP(secret, interval=60)
    rooms_otp_cache[room_name] = {"otp": totp.now(), "expires": time.time() + 60}
    
    await sio.emit('create_success', {'room': room_name, 'otp': rooms_otp_cache[room_name]['otp']}, to=sid)
    await sio.emit('join_success', {'room': room_name}, to=sid)
    await sio.emit('display_otp', {'code': rooms_otp_cache[room_name]['otp'], 'time_left': 60}, room=room_name)
    
    print(f"방 생성: {room_name} by {creator}")

@sio.event
async def join_with_otp(sid, data):
    """OTP로 방 참가"""
    room = data.get('room', '').strip()
    otp_code = data.get('code', '').strip()
    nickname = data.get('nickname', '').strip()
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    # Rate Limit 체크
    if not check_rate_limit(ip_address):
        await sio.emit('join_fail', {'msg': "너무 많은 요청입니다."}, to=sid)
        return
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    
    c.execute("SELECT secret, max_users, user_count FROM rooms WHERE name = ? AND is_active = 1", (room,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        await sio.emit('join_fail', {'msg': "존재하지 않는 방입니다."}, to=sid)
        return
    
    secret, max_users, current_count = result
    
    if current_count >= max_users:
        conn.close()
        await sio.emit('join_fail', {'msg': "방이 가득 찼습니다."}, to=sid)
        return
    
    totp = pyotp.TOTP(secret, interval=60)
    if totp.verify(otp_code):
        await sio.enter_room(sid, room)
        user_sessions[sid] = {
            "nickname": nickname,
            "room": room,
            "ip": ip_address
        }
        
        # 닉네임 중복 체크
        c.execute("SELECT nickname FROM users WHERE nickname = ?", (nickname,))
        if c.fetchone():
            conn.close()
            await sio.emit('nickname_fail', {'msg': "이미 사용 중인 닉네임입니다."}, to=sid)
            await sio.leave_room(sid, room)
            return
        
        # 사용자 등록
        c.execute("INSERT INTO users (nickname, room, ip_address) VALUES (?, ?, ?)",
                  (nickname, room, ip_address))
        c.execute("UPDATE rooms SET user_count = user_count + 1 WHERE name = ?", (room,))
        conn.commit()
        conn.close()
        
        await sio.emit('join_success', {'room': room}, to=sid)
        
        # 현재 방의 OTP 전송
        rooms_otp_cache[room] = {"otp": totp.now(), "expires": time.time() + 60}
        await sio.emit('display_otp', {'code': rooms_otp_cache[room]['otp'], 'time_left': 60}, room=room)
    else:
        conn.close()
        await sio.emit('join_fail', {'msg': "잘못된 OTP 코드입니다."}, to=sid)

@sio.event
async def set_nickname(sid, data):
    """닉네임 설정"""
    nickname = data.get('nickname', '').strip()
    room = data.get('room')
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    if not nickname or len(nickname) < 2 or len(nickname) > 20:
        await sio.emit('nickname_fail', {'msg': "닉네임은 2~20자여야 합니다."}, to=sid)
        return
    
    # 닉네임 유효성 검사
    if not nickname.replace('_', '').replace('-', '').isalnum():
        await sio.emit('nickname_fail', {'msg': "닉네임에는 영문, 숫자, '_', '-'만 사용 가능합니다."}, to=sid)
        return
    
    # 중복 체크
    for s_id, info in user_sessions.items():
        if info.get('nickname') == nickname and s_id != sid:
            await sio.emit('nickname_fail', {'msg': "이미 사용 중인 닉네임입니다."}, to=sid)
            return
    
    user_sessions[sid]["nickname"] = nickname
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (nickname, room, ip_address) VALUES (?, ?, ?)",
              (nickname, room, ip_address))
    conn.commit()
    conn.close()
    
    await sio.emit('nickname_success', to=sid)
    await sio.emit('notification', {
        'msg': f"'{nickname}'님이 입장했습니다.",
        'type': 'system',
        'timestamp': datetime.utcnow().isoformat()
    }, room=room)

@sio.event
async def refresh_otp(sid, data):
    """OTP 갱신"""
    room = data.get('room')
    user = user_sessions.get(sid)
    
    if not room or not user or user.get('room') != room:
        return
    
    now = time.time()
    cached = rooms_otp_cache.get(room, {})
    last_refresh = cached.get('expires', 0) - 60 if cached.get('expires') else 0
    
    # 30초 쿨다운
    if now - last_refresh < 30:
        remaining = int(30 - (now - last_refresh))
        await sio.emit('notification', {'msg': f"갱신 대기 중... ({remaining}초 남음)", 'type': 'system'}, to=sid)
        return
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    c.execute("SELECT secret FROM rooms WHERE name = ?", (room,))
    result = c.fetchone()
    conn.close()
    
    if result:
        totp = pyotp.TOTP(result[0], interval=60)
        new_otp = totp.now()
        rooms_otp_cache[room] = {"otp": new_otp, "expires": now + 60}
        
        await sio.emit('notification', {
            'msg': f"🔑 '{user['nickname']}'님이 OTP를 갱신했습니다.",
            'type': 'system'
        }, room=room)
        await sio.emit('display_otp', {'code': new_otp, 'time_left': 60}, room=room)

@sio.event
async def delete_room_admin(sid, data):
    """관리자: 방 폐쇄"""
    token = data.get('token', '')
    target = data.get('target_room', '')
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    if not verify_jwt_token(token, ip_address):
        await sio.emit('admin_action_result', {'success': False, 'msg': "권한이 없습니다."}, to=sid)
        return
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    admin_id = payload.get('admin_id', 'unknown')
    
    if target:
        # 방 폐쇄 로직
        conn = sqlite3.connect('vaultchat.db')
        c = conn.cursor()
        c.execute("UPDATE rooms SET is_active = 0 WHERE name = ?", (target,))
        c.execute("DELETE FROM users WHERE room = ?", (target,))
        conn.commit()
        conn.close()
        
        # 모든 방 사용자에게 알림
        await sio.emit('room_closed', {
            'msg': "⚠️ 관리자가 방을 폐쇄했습니다.",
            'type': 'system'
        }, room=target)
        
        log_admin_action(admin_id, "ROOM_DELETED", target=target, ip_address=ip_address)
        await sio.emit('admin_action_result', {'success': True, 'msg': f"'{target}' 방이 폐쇄되었습니다."}, to=sid)

@sio.event
async def send_global_notice(sid, data):
    """전역 공지 발송"""
    token = data.get('token', '')
    msg = data.get('msg', '')
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    if not verify_jwt_token(token, ip_address):
        await sio.emit('admin_action_result', {'success': False, 'msg': "권한이 없습니다."}, to=sid)
        return
    
    if msg:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        admin_id = payload.get('admin_id', 'unknown')
        
        await sio.emit('global_notice', {
            'msg': msg,
            'sender': 'ADMIN',
            'timestamp': datetime.utcnow().isoformat()
        })
        
        log_admin_action(admin_id, "GLOBAL_NOTICE", details=msg[:100], ip_address=ip_address)
        await sio.emit('admin_action_result', {'success': True, 'msg': "전역 공지가 발송되었습니다."}, to=sid)

@sio.event
async def kick_user(sid, data):
    """관리자: 강제 퇴장"""
    token = data.get('token', '')
    target_nickname = data.get('target_nickname', '')
    reason = data.get('reason', '')
    ip_address = user_sessions.get(sid, {}).get('ip', 'unknown')
    
    if not verify_jwt_token(token, ip_address):
        await sio.emit('admin_action_result', {'success': False, 'msg': "권한이 없습니다."}, to=sid)
        return
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    admin_id = payload.get('admin_id', 'unknown')
    
    # 대상 사용자 찾기
    target_sid = None
    for s_id, info in user_sessions.items():
        if info.get('nickname') == target_nickname:
            target_sid = s_id
            room = info.get('room')
            break
    
    if target_sid:
        await sio.emit('kicked', {
            'msg': f"관리자에 의해 퇴장되었습니다. 사유: {reason}",
            'type': 'system'
        }, to=target_sid)
        await sio.disconnect(target_sid)
        
        log_admin_action(admin_id, "USER_KICKED", target=target_nickname, details=reason, ip_address=ip_address)
        await sio.emit('admin_action_result', {'success': True, 'msg': f"'{target_nickname}'님이 퇴장되었습니다."}, to=sid)
    else:
        await sio.emit('admin_action_result', {'success': False, 'msg': "사용자를 찾을 수 없습니다."}, to=sid)

@sio.event
async def send_secure_msg(sid, data):
    """암호화된 메시지 전송"""
    info = user_sessions.get(sid)
    if not info:
        return
    
    msg = data.get('msg', '')
    msg_type = data.get('type', 'text')
    file_name = data.get('fileName')
    file_type = data.get('fileType')
    room = info.get('room')
    
    if not room:
        return
    
    ip_address = info.get('ip', 'unknown')
    
    # Rate Limit 체크
    if not check_rate_limit(ip_address):
        await sio.emit('notification', {'msg': "메시지 전송이 제한되었습니다.", 'type': 'system'}, to=sid)
        return
    
    # 메시지 길이 제한
    if msg_type == 'text' and len(msg) > 5000:
        await sio.emit('notification', {'msg': "메시지가 너무 깁니다. (최대 5000자)", 'type': 'system'}, to=sid)
        return
    
    # 메시지 로깅
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (room, sender, message, message_type, file_name, encrypted_content) VALUES (?, ?, ?, ?, ?, ?)",
              (room, info['nickname'], msg[:200] if msg_type == 'text' else None, msg_type, file_name, msg))
    conn.commit()
    conn.close()
    
    await sio.emit('receive_secure_msg', {
        'msg': msg,
        'sender': info['nickname'],
        'type': msg_type,
        'fileName': file_name,
        'fileType': file_type,
        'timestamp': datetime.utcnow().isoformat()
    }, room=room)

@sio.event
async def get_room_info(sid, data):
    """방 정보 조회"""
    room = data.get('room', '')
    
    conn = sqlite3.connect('vaultchat.db')
    c = conn.cursor()
    c.execute("SELECT name, user_count, created_at FROM rooms WHERE name = ? AND is_active = 1", (room,))
    result = c.fetchone()
    
    if result:
        c.execute("SELECT nickname, joined_at FROM users WHERE room = ? ORDER BY joined_at DESC", (room,))
        users = [{"nickname": u[0], "joined": u[1]} for u in c.fetchall()]
        
        await sio.emit('room_info', {
            'name': result[0],
            'user_count': result[1],
            'created': result[2],
            'users': users
        }, to=sid)
    
    conn.close()

# ============== 정리 작업 ==============

async def cleanup_expired_sessions():
    """만료된 세션 정리 (백그라운드 태스크)"""
    while True:
        await asyncio.sleep(3600)  # 1시간마다
        try:
            conn = sqlite3.connect('vaultchat.db')
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE expires_at < datetime('now') OR is_active = 0")
            c.execute("DELETE FROM rate_limits WHERE window_start < datetime('now', '-1 hour')")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"정리 작업 오류: {e}")

# 시작 시 정리 작업 실행
asyncio.create_task(cleanup_expired_sessions())

print("=" * 50)
print("VaultChat Advanced Server Started")
print(f"Admin ID: {ADMIN_ID}")
print(f"Admin 2FA Secret: {ADMIN_2FA_SECRET}")
print("=" * 50)
