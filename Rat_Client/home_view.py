import tkinter
import customtkinter
from CTkTable import *
from server_handler import SocketClient


SELECTED_CONNECTION = ""


def show_home(sck):
    home_main(sck)


def get_conn(sck, text_box):
    conn = sck.get_connections()

    if conn == "No connections" or conn == False:
        text_box.insert(customtkinter.END, "No connections\n")
    else:
        text_box.insert(customtkinter.END, "[*]Choose Connection \n")
        for i in range(len(conn)):
            if conn[i] == "":
                continue        
            text_box.insert(customtkinter.END, str(i) + " " + str(conn[i]) + "\n")


def executeCmd(sck, cmd, text_box):
    global SELECTED_CONNECTION
    if "set connection" in cmd:
        conn_id = cmd.split("set connection")[1].strip()
        SELECTED_CONNECTION = conn_id
        text_box.insert(customtkinter.END, ">> " + cmd + "\n")
        text_box.insert(customtkinter.END, "[*] Set Connection " + conn_id + "\n\n") 
        return

    text_box.insert(customtkinter.END, ">> " + cmd + "\n")
    resp = sck.send_command(SELECTED_CONNECTION, cmd)
    text_box.insert(customtkinter.END, str(resp) + "\n\n")
    

def home_main(sck):

    customtkinter.set_appearance_mode("System")
    customtkinter.set_default_color_theme("blue")

    home = customtkinter.CTk()
    home.geometry("1280x720")
    home.title("Client Dashboard")

    bottom_frame = customtkinter.CTkFrame(home)
    bottom_frame.pack(side="bottom", fill="x", padx=10, pady=10)

    input_box = customtkinter.CTkEntry(bottom_frame, width=1000)
    input_box.pack(side="left")

    button = customtkinter.CTkButton(bottom_frame, text="Submit", command=lambda: executeCmd(sck, input_box.get(), text_box))
    button.pack(side="left", padx=10)

    text_box = customtkinter.CTkTextbox(home)
    text_box.pack(side="top", fill="both", expand=True, padx=10, pady=10)

    get_conn(sck, text_box)

    home.mainloop()
