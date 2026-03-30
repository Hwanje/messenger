from fastapi import FastAPI
import socketio

# Socket.io 서버 설정 (CORS 허용 필수)
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI()
socket_app = socketio.ASGIApp(sio, app)

@sio.event
async def connect(sid, environ):
    print(f"User Connected: {sid}")

@sio.event
async def message(sid, data):
    # 클라이언트에서 암호화된 데이터를 받아 그대로 배달(Relay)만 함
    # 서버는 복호화 키가 없으므로 내용을 읽을 수 없음 (Zero-Knowledge)
    await sio.emit('message', data)

@app.get("/")
async def index():
    return {"status": "Secure Server is Running"}
