from fastapi import FastAPI
import socketio

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()
socket_app = socketio.ASGIApp(sio, app)

@sio.event
async def join_room(sid, data):
    room = data['room']
    sio.enter_room(sid, room)
    print(f"[{room}] 유저 접속: {sid}")
    await sio.emit('notification', {'msg': f"{sid} 님이 입장했습니다."}, room=room)

@sio.event
async def send_secure_msg(sid, data):
    # data['msg']는 이미 브라우저에서 암호화된 바이너리/텍스트 데이터여야 함
    room = data['room']
    await sio.emit('receive_secure_msg', {'msg': data['msg'], 'sender': sid}, room=room)

@app.get("/")
async def index():
    return {"status": "Secure Messaging Server is Running"}
