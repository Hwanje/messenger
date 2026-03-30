import flet as ft
import socketio
import time

sio = socketio.Client()

def main(page: ft.Page):
    page.title = "VaultChat - OTP Invitation"
    
    # UI 요소들
    code_display = ft.Text("초대 코드: 버튼을 눌러 생성", size=20, weight="bold")
    otp_input = ft.TextField(label="6자리 초대코드 입력", width=200)
    chat_log = ft.Column(scroll=ft.ScrollMode.ALWAYS, expand=True)
    msg_input = ft.TextField(hint_text="메시지...", expand=True)

    # 이벤트 핸들러
    def on_display_code(data):
        code_display.value = f"현재 초대 코드: {data['code']} (60초 유효)"
        page.update()

    def on_join_success(data):
        page.snack_bar = ft.SnackBar(ft.Text(data['msg']))
        page.snack_bar.open = True
        # 입장 성공 시 채팅 UI로 전환 로직 추가 가능
        page.update()

    sio.on('display_code', on_display_code)
    sio.on('join_success', on_join_success)

    # 버튼 클릭 함수
    def generate_code(e):
        sio.emit('get_invite_code')

    def join_room(e):
        sio.emit('join_with_otp', {'code': otp_input.value, 'room': 'secret_room'})

    def send_msg(e):
        sio.emit('send_secure_msg', {'msg': msg_input.value, 'room': 'secret_room'})
        msg_input.value = ""
        page.update()

    # 페이지 레이아웃
    page.add(
        ft.Tabs(
            selected_index=0,
            tabs=[
                ft.Tab(text="방장 (코드생성)", content=ft.Column([
                    code_display, 
                    ft.ElevatedButton("새 코드 생성", on_click=generate_code)
                ])),
                ft.Tab(text="참가 (코드입력)", content=ft.Column([
                    otp_input, 
                    ft.ElevatedButton("입장하기", on_click=join_room)
                ])),
            ]
        ),
        ft.Divider(),
        chat_log,
        ft.Row([msg_input, ft.IconButton(ft.icons.SEND, on_click=send_msg)])
    )

    sio.connect('https://massenger-9oh6.onrender.com/')

ft.app(target=main)
