import tkinter
import customtkinter
from server_handler import SocketClient
from home_view import show_home
def tryConnectToServer():
    try:
        server_addr = server_val.get()
        sck = SocketClient()
        ret = sck.connect_to_server(server_addr)
    except:
        print("couldnt get server address")
    
    if ret:
        app.withdraw()
        show_home(sck)


customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.geometry("500x250")
app.title("Client")

title = customtkinter.CTkLabel(app, text="Connect to server")
title.pack()

server_val = tkinter.StringVar()
server_input = customtkinter.CTkEntry(app, textvariable=server_val)
server_input.pack()

connect_bttn = customtkinter.CTkButton(app, text="connect", command=tryConnectToServer)
connect_bttn.pack()

app.mainloop()

