import pyotp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

# Socket.io 및 FastAPI 설정
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()

# CORS 설정 (GitHub Pages 접속 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    nickname = data.get('nickname', '방장')
    
    if not room_name: return
    
    # 방 생성 및 시크릿 키 할당
    if room_name not in rooms_db:
        rooms_db[room_name] = pyotp.random_base32()
    
    # 유저 정보 저장 및 방 입장
    user_sessions[sid] = nickname
    sio.enter_room(sid, room_name)
    
    # OTP 생성 및 전송
    totp = pyotp.TOTP(rooms_db[room_name], interval=60)
    await sio.emit('display_otp', {'code': totp.now()}, to=sid)
    await sio.emit('join_success', {'msg': f"'{room_name}' 방 생성 완료!", 'room': room_name}, to=sid)

@sio.event
async def join_with_otp(sid, data):
    room = data.get('room')
    otp_code = data.get('code')
    nickname = data.get('nickname', '익명')
    
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        if totp.verify(otp_code):
            user_sessions[sid] = nickname
            sio.enter_room(sid, room)
            await sio.emit('join_success', {'msg': f"'{room}' 입장 성공!", 'room': room}, to=sid)
            await sio.emit('notification', {'msg': f"{nickname}님이 입장했습니다."}, room=room)
        else:
            await sio.emit('join_fail', {'msg': "OTP가 올바르지 않습니다."}, to=sid)
    else:
        await sio.emit('join_fail', {'msg': "방이 존재하지 않습니다."}, to=sid)

@sio.event
async def refresh_otp(sid, data):
    room = data.get('room')
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        await sio.emit('display_otp', {'code': totp.now()}, to=sid)

@sio.event
async def send_secure_msg(sid, data):
    nickname = user_sessions.get(sid, "Unknown")
    room = data.get('room')
    # 서버가 닉네임을 붙여서 브로드캐스팅
    await sio.emit('receive_secure_msg', {
        'msg': data['msg'], 
        'sender': nickname 
    }, room=room)

@sio.event
async def leave_room(sid, data):
    room = data.get('room')
    nickname = user_sessions.get(sid, "Unknown")
    sio.leave_room(sid, room)
    await sio.emit('notification', {'msg': f"{nickname}님이 퇴장했습니다."}, room=room)
    await sio.emit('leave_success', to=sid)

@sio.event
async def disconnect(sid):
    if sid in user_sessions:
        del user_sessions[sid]

@app.get("/")
async def health():
    return {"status": "VaultChat Server is Live"}
