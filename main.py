import pyotp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

# 1. Socket.io 서버 설정
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()

# 2. CORS 설정 (이게 있어야 외부에서 접속 가능)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. 핵심 수정: Socket.io를 FastAPI 앱에 '마운트' 함
socket_app = socketio.ASGIApp(sio, app)

# 방 정보 저장소
rooms_db = {}

@sio.event
async def connect(sid, environ):
    print(f"Connected: {sid}")

@sio.event
async def create_or_get_otp(sid, data):
    room_name = data['room']
    if room_name not in rooms_db:
        rooms_db[room_name] = pyotp.random_base32()
    
    totp = pyotp.TOTP(rooms_db[room_name], interval=60)
    current_code = totp.now()
    await sio.emit('display_otp', {'code': current_code}, to=sid)

@sio.event
async def join_with_otp(sid, data):
    room = data['room']
    otp_code = data['code']
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        if totp.verify(otp_code):
            sio.enter_room(sid, room)
            await sio.emit('join_success', {'msg': f"'{room}' 보안 입장 완료", 'room': room}, to=sid)
        else:
            await sio.emit('join_fail', {'msg': "OTP가 틀렸습니다."}, to=sid)
    else:
        await sio.emit('join_fail', {'msg': "방이 존재하지 않습니다."}, to=sid)

@sio.event
async def send_secure_msg(sid, data):
    room = data['room']
    await sio.emit('receive_secure_msg', {'msg': data['msg'], 'sender': sid[:5]}, room=room)

@app.get("/")
async def health():
    return {"status": "running"}
