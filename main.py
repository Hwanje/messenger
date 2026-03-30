import pyotp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

# 1. Socket.io 및 FastAPI 설정
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()

# CORS 설정 (GitHub Pages 등 외부 접속 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 핵심: Socket.io를 FastAPI 앱에 마운트
socket_app = socketio.ASGIApp(sio, app)

# 데이터 저장소
user_sessions = {}  # { sid: "닉네임" }
rooms_db = {}       # { "방이름": "OTP_Secret" }

@sio.event
async def connect(sid, environ):
    print(f"Connected: {sid}")

@sio.event
async def create_room(sid, data):
    room_name = data.get('room')
    if not room_name: return
    
    # 방 생성 및 시크릿 키 할당
    if room_name not in rooms_db:
        rooms_db[room_name] = pyotp.random_base32()
    
    # 방장 자동 입장
    sio.enter_room(sid, room_name)
    
    # OTP 생성 및 전송
    totp = pyotp.TOTP(rooms_db[room_name], interval=60)
    await sio.emit('display_otp', {'code': totp.now()}, to=sid)
    await sio.emit('join_success', {'room': room_name}, to=sid)

@sio.event
async def join_with_otp(sid, data):
    room = data.get('room')
    otp_code = data.get('code')
    
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        if totp.verify(otp_code):
            sio.enter_room(sid, room)
            await sio.emit('join_success', {'room': room}, to=sid)
        else:
            await sio.emit('join_fail', {'msg': "OTP가 올바르지 않습니다."}, to=sid)
    else:
        await sio.emit('join_fail', {'msg': "방이 존재하지 않습니다."}, to=sid)

@sio.event
async def set_nickname(sid, data):
    nickname = data.get('nickname', '익명')
    room = data.get('room')
    user_sessions[sid] = nickname
    await sio.emit('notification', {'msg': f"'{nickname}'님이 입장했습니다."}, room=room)

@sio.event
async def refresh_otp(sid, data):
    room = data.get('room')
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        new_code = totp.now()
        # 갱신된 코드를 해당 유저에게 다시 전송
        await sio.emit('display_otp', {'code': new_code}, to=sid)
@sio.event
async def send_secure_msg(sid, data):
    nickname = user_sessions.get(sid, "익명")
    room = data.get('room') # 클라이언트가 보낸 방 이름
    
    if room:
        # 핵심: room=room 인자를 넣어 해당 방 멤버 전원에게 전송
        await sio.emit('receive_secure_msg', {
            'msg': data['msg'], 
            'sender': nickname 
        }, room=room)
    else:
        print(f"Error: Room not found for sid {sid}")
        
@sio.event
async def leave_room(sid, data):
    room = data.get('room')
    nickname = user_sessions.get(sid, "익명")
    sio.leave_room(sid, room)
    if sid in user_sessions: del user_sessions[sid]
    await sio.emit('notification', {'msg': f"'{nickname}'님이 퇴장했습니다."}, room=room)
    await sio.emit('leave_success', to=sid)

@app.get("/")
async def health():
    return {"status": "running"}
