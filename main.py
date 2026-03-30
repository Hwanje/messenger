import pyotp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

socket_app = socketio.ASGIApp(sio, app)

user_sessions = {}  # { sid: "닉네임" }
rooms_db = {}       # { "방이름": "OTP_Secret" }

@sio.event
async def connect(sid, environ):
    print(f"Connected: {sid}")

@sio.event
async def create_room(sid, data):
    room_name = data.get('room')
    if not room_name: return
    
    if room_name not in rooms_db:
        rooms_db[room_name] = pyotp.random_base32()
    
    sio.enter_room(sid, room_name)
    totp = pyotp.TOTP(rooms_db[room_name], interval=60)
    
    # 방 생성 성공 알림 (닉네임은 아직 설정 전)
    await sio.emit('display_otp', {'code': totp.now()}, to=sid)
    await sio.emit('join_success', {'room': room_name, 'needs_nickname': True}, to=sid)

@sio.event
async def join_with_otp(sid, data):
    room = data.get('room')
    otp_code = data.get('code')
    
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        if totp.verify(otp_code):
            sio.enter_room(sid, room)
            await sio.emit('join_success', {'room': room, 'needs_nickname': True}, to=sid)
        else:
            await sio.emit('join_fail', {'msg': "OTP가 올바르지 않습니다."}, to=sid)
    else:
        await sio.emit('join_fail', {'msg': "방이 존재하지 않습니다."}, to=sid)

@sio.event
async def set_nickname(sid, data):
    nickname = data.get('nickname', '익명')
    room = data.get('room')
    user_sessions[sid] = nickname
    await sio.emit('notification', {'msg': f"{nickname}님이 대화에 합류했습니다."}, room=room)

@sio.event
async def refresh_otp(sid, data):
    room = data.get('room')
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        # 갱신된 코드를 다시 보냄
        await sio.emit('display_otp', {'code': totp.now()}, to=sid)

@sio.event
async def send_secure_msg(sid, data):
    nickname = user_sessions.get(sid, "익명")
    await sio.emit('receive_secure_msg', {'msg': data['msg'], 'sender': nickname}, room=data['room'])

@sio.event
async def leave_room(sid, data):
    room = data.get('room')
    nickname = user_sessions.get(sid, "익명")
    sio.leave_room(sid, room)
    if sid in user_sessions: del user_sessions[sid]
    await sio.emit('notification', {'msg': f"{nickname}님이 퇴장했습니다."}, room=room)
    await sio.emit('leave_success', to=sid)

@app.get("/")
async def health():
    return {"status": "Live"}
