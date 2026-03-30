import pyotp
from fastapi import FastAPI
import socketio

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()
socket_app = socketio.ASGIApp(sio, app)

# 방마다 고유한 Secret Key를 가짐 (실제로는 방 생성 시 생성)
ROOM_SECRET = pyotp.random_base32()
totp = pyotp.TOTP(ROOM_SECRET, interval=60) # 60초 동안 유효

@sio.event
async def get_invite_code(sid):
    # 방장이 요청하면 현재 유효한 6자리 코드를 생성해서 전달
    code = totp.now()
    await sio.emit('display_code', {'code': code}, to=sid)

@sio.event
async def join_with_otp(sid, data):
    input_code = data['code']
    room = data['room']
    
    # 사용자가 입력한 코드가 현재 시간 기준으로 유효한지 검증
    if totp.verify(input_code):
        sio.enter_room(sid, room)
        await sio.emit('join_success', {'msg': f"{room}방에 보안 입장했습니다."}, to=sid)
        await sio.emit('notification', {'msg': f"새로운 유저({sid})가 입장했습니다."}, room=room)
    else:
        await sio.emit('join_fail', {'msg': "초대 코드가 만료되었거나 틀렸습니다."}, to=sid)

# 기존의 send_secure_msg 이벤트는 그대로 유지
