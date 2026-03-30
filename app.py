import flet as ft
import socketio
from cryptography.fernet import Fernet

SECRET_KEY = Fernet.generate_key() 
cipher = Fernet(SECRET_KEY)

sio = socketio.Client()

def main(page: ft.Page):
    page.title = "VaultChat - E2EE Messenger"
    page.theme_mode = ft.ThemeMode.DARK
    
    chat_messages = ft.Column(scroll=ft.ScrollMode.ALWAYS, expand=True)
    message_input = ft.TextField(hint_text="비밀 메시지 입력...", expand=True)

    def on_message(data):
        # 서버에서 받은 암호문을 복호화
        try:
            decrypted_msg = cipher.decrypt(data['msg'].encode()).decode()
            chat_messages.controls.append(ft.Text(f"상대방: {decrypted_msg}", color="green"))
        except:
            chat_messages.controls.append(ft.Text("알 수 없는 암호문 수신", color="red"))
        page.update()

    sio.on('receive_secure_msg', on_message)

    def send_click(e):
        # 메시지를 보내기 전 암호화 (서버는 이 내용을 모름)
        encrypted_msg = cipher.encrypt(message_input.value.encode()).decode()
        sio.emit('send_secure_msg', {'msg': encrypted_msg, 'room': 'secret_room'})
        
        chat_messages.controls.append(ft.Text(f"나 (암호화됨): {message_input.value}", color="blue"))
        message_input.value = ""
        page.update()

    page.add(
        ft.Text("Secure Web Messenger", size=20, weight="bold"),
        chat_messages,
        ft.Row([message_input, ft.ElevatedButton("보내기", on_click=send_click)])
    )
    
    # Render 서버 주소를 여기에 넣으세요!
    sio.connect('https://massenger-9oh6.onrender.com/') 

ft.app(target=main)
