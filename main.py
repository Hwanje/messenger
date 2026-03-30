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

user_sessions = {}
rooms_db = {}

@sio.event
async def connect(sid, environ):
    print(f"Connected: {sid}")

@sio.event
async def create_room(sid, data):
    room_name = data.get('room')
    if not room_name: return
    
    # [수정] 방 이름 중복 체크
    if room_name in rooms_db:
        await sio.emit('join_fail', {'msg': "이미 존재하는 방 이름입니다. 다른 이름을 사용하세요."}, to=sid)
        return
    
    # 방 생성 및 시크릿 키 할당
    rooms_db[room_name] = pyotp.random_base32()
    totp = pyotp.TOTP(rooms_db[room_name], interval=60)
    
    # 방장에게 OTP 번호 전송 (아직 입장은 시키지 않음)
    await sio.emit('display_otp', {'code': totp.now()}, to=sid)
    await sio.emit('create_success', {'room': room_name}, to=sid)

@sio.event
async def join_with_otp(sid, data):
    room = data.get('room')
    otp_code = data.get('code')
    
    if room in rooms_db:
        totp = pyotp.TOTP(rooms_db[room], interval=60)
        if totp.verify(otp_code):
            # [보안] OTP 검증 성공 시에만 실제로 방에 입장(enter_room) 시킴
            await sio.enter_room(sid, room)
            await sio.emit('join_success', {'room': room}, to=sid)
            await sio.emit('display_otp', {'code': totp.now()}, to=sid)
        else:
            await sio.emit('join_fail', {'msg': "OTP가 일치하지 않습니다."}, to=sid)
    else:
        await sio.emit('join_fail', {'msg': "존재하지 않는 방입니다."}, to=sid)

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
        await sio.emit('display_otp', {'code': totp.now()}, room=room)

@sio.event
async def send_secure_msg(sid, data):
    nickname = user_sessions.get(sid, "익명")
    room = data.get('room')
    msg = data.get('msg')
    msg_type = data.get('type', 'text') # 텍스트인지 파일인지 구분
    
    if room and msg:
        await sio.emit('receive_secure_msg', {
            'msg': msg, 
            'sender': nickname,
            'type': msg_type,
            'fileName': data.get('fileName'),
            'fileType': data.get('fileType')
        }, room=room)
        
@sio.event
async def leave_room(sid, data):
    room = data.get('room')
    nickname = user_sessions.get(sid, "익명")
    await sio.leave_room(sid, room)
    if sid in user_sessions: del user_sessions[sid]
    await sio.emit('notification', {'msg': f"'{nickname}'님이 퇴장했습니다."}, room=room)
    await sio.emit('leave_success', to=sid)

@app.get("/")
async def health():
    return {"status": "Live"}