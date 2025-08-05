# ─────────────────────────── client.py ────────────────────────────
import socket, threading, tkinter as tk
from tkinter import scrolledtext, messagebox
ENC = "utf-8"

class Chat:
    def __init__(self):
        self.sock = None
        self.root = tk.Tk()
        self.root.title("LAN Relay Chat")

        # ── top: connection parameters ───────────────────────────
        top = tk.Frame(self.root); top.pack(pady=4)
        self.server_ip = self._entry(top, "Server IP", 0, 0, 15)
        self.port      = self._entry(top, "Port",      0, 2, 6, dflt="9000")
        self.username  = self._entry(top, "Username",  1, 0, 15)
        self.target_ip = self._entry(top, "Target IP", 1, 2, 15)
        self.btn_conn  = tk.Button(top, text="Connect", width=10, command=self.connect)
        self.btn_conn.grid(row=0, column=4, rowspan=2, padx=6)

        # ── middle: chat history ─────────────────────────────────
        self.logbox = scrolledtext.ScrolledText(self.root, width=60, height=20, state=tk.DISABLED)
        self.logbox.pack(padx=10, pady=4)

        # ── bottom: compose ─────────────────────────────────────
        bot = tk.Frame(self.root); bot.pack(pady=4)
        self.entry_msg = tk.Entry(bot, width=45, state=tk.DISABLED)
        self.entry_msg.pack(side=tk.LEFT, padx=4)
        self.btn_send = tk.Button(bot, text="Send", width=10, state=tk.DISABLED, command=self.send)
        self.btn_send.pack(side=tk.LEFT)

    def _entry(self, frame, lbl, r, c, w, dflt=""):
        tk.Label(frame, text=lbl).grid(row=r, column=c)
        e = tk.Entry(frame, width=w); e.grid(row=r, column=c+1); e.insert(0, dflt); return e

    # ── network helpers ─────────────────────────────────────────
    def connect(self):
        host = self.server_ip.get().strip()
        port = int(self.port.get())
        user = self.username.get().strip()
        if not (host and user):
            messagebox.showerror("Missing", "Server IP and Username required"); return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((host, port))            # outbound TCP uses real server IP, never 0.0.0.0 :contentReference[oaicite:2]{index=2}
        except OSError as e:
            messagebox.showerror("Connect error", str(e)); return
        self.sock.sendall(user.encode(ENC))            # handshake
        self._lock_connect_fields()
        threading.Thread(target=self.listen, daemon=True).start()
        self._log(f"[SERVER] connected to {host}:{port}")

    def listen(self):
        while True:
            try:
                data = self.sock.recv(2048).decode(ENC)
                if not data: break
                sender, text = data.split("~", 1)
                self._log(f"[{sender}] {text}")
            except (ValueError, OSError):
                break
        self._log("[SERVER] connection closed")

    def send(self):
        tgt = self.target_ip.get().strip()
        txt = self.entry_msg.get().strip()
        if not (tgt and txt):
            messagebox.showerror("Missing", "Target IP and message required"); return
        try:
            self.sock.sendall(f"{tgt}~{txt}".encode(ENC))
            self._log(f"[Me→{tgt}] {txt}")
            self.entry_msg.delete(0, tk.END)
        except OSError as e:
            messagebox.showerror("Send error", str(e))

    # ── gui helpers ─────────────────────────────────────────────
    def _log(self, line):
        self.logbox.config(state=tk.NORMAL); self.logbox.insert(tk.END, line+"\n")
        self.logbox.config(state=tk.DISABLED); self.logbox.yview(tk.END)
    def _lock_connect_fields(self):
        for w in (self.server_ip, self.port, self.username, self.btn_conn):
            w.config(state=tk.DISABLED)
        self.entry_msg.config(state=tk.NORMAL); self.btn_send.config(state=tk.NORMAL)

if __name__ == "__main__":
    Chat().root.mainloop()



# import socket, threading, tkinter as tk
# from tkinter import scrolledtext, messagebox

# ENCODING   = "utf-8"

# class ChatClient:
#     def __init__(self, root):
#         self.sock = None
#         self.root = root
#         self.root.title("Relay-Chat Client")

#         # ─── Top: connection fields ───────────────────────────────
#         top = tk.Frame(root, pady=5); top.pack()
#         tk.Label(top, text="Server IP").grid(row=0, column=0)
#         tk.Label(top, text="Port").grid(row=0, column=2)
#         tk.Label(top, text="Username").grid(row=1, column=0)
#         tk.Label(top, text="Target IP").grid(row=1, column=2)

#         self.server_ip   = tk.Entry(top, width=15); self.server_ip.grid(row=0, column=1)
#         self.port_entry  = tk.Entry(top, width=6);  self.port_entry .grid(row=0, column=3)
#         self.port_entry.insert(0, "9999")
#         self.username    = tk.Entry(top, width=15); self.username   .grid(row=1, column=1)
#         self.target_ip   = tk.Entry(top, width=15); self.target_ip  .grid(row=1, column=3)

#         self.conn_btn = tk.Button(top, text="Connect", command=self.connect)
#         self.conn_btn.grid(row=0, column=4, rowspan=2, padx=8)

#         # ─── Middle: chat history ─────────────────────────────────
#         self.chat = scrolledtext.ScrolledText(root, width=60, height=20, state=tk.DISABLED)
#         self.chat.pack(padx=10, pady=5)

#         # ─── Bottom: message entry ────────────────────────────────
#         bottom = tk.Frame(root, pady=5); bottom.pack()
#         self.msg_entry = tk.Entry(bottom, width=45); self.msg_entry.pack(side=tk.LEFT, padx=5)
#         tk.Button(bottom, text="Send", width=10, command=self.send).pack(side=tk.LEFT)

#     # ───────── net helpers ───────────────────────────────────────
#     def connect(self):
#         host = self.server_ip.get().strip()
#         port = int(self.port_entry.get())
#         user = self.username.get().strip()

#         if not (host and user):
#             messagebox.showerror("Missing info", "Server IP and username required"); return

#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             self.sock.connect((host, port))
#         except OSError as e:
#             messagebox.showerror("Connect error", str(e)); return

#         # lock widgets
#         for w in (self.server_ip, self.port_entry, self.username, self.conn_btn):
#             w.config(state=tk.DISABLED)
#         self.log(f"[SERVER] connected → {host}:{port}")

#         # initial handshake
#         self.sock.sendall(user.encode(ENCODING))

#         threading.Thread(target=self.listen, daemon=True).start()

#     def listen(self):
#         while True:
#             try:
#                 data = self.sock.recv(2048).decode(ENCODING)
#                 if not data: break
#                 sender, text = data.split("~", 1)
#                 self.log(f"[{sender}] {text}")
#             except (ValueError, OSError):
#                 break
#         self.log("[SERVER] connection closed")

#     def send(self):
#         if not self.sock: return
#         target = self.target_ip.get().strip()
#         text   = self.msg_entry.get().strip()
#         if not (target and text):
#             messagebox.showerror("Missing info", "Target IP and message required"); return
#         pkt = f"{target}~{text}"
#         try:
#             self.sock.sendall(pkt.encode(ENCODING))
#             self.log(f"[Me→{target}] {text}")
#             self.msg_entry.delete(0, tk.END)
#         except OSError as e:
#             messagebox.showerror("Send error", str(e))

#     # ───────── gui helper ────────────────────────────────────────
#     def log(self, line):
#         self.chat.config(state=tk.NORMAL)
#         self.chat.insert(tk.END, line + "\n")
#         self.chat.config(state=tk.DISABLED)
#         self.chat.yview(tk.END)

# if __name__ == "__main__":
#     ChatClient(tk.Tk()).root.mainloop()


# # #Import Modules
# # import socket
# # import threading
# # import os
# # import sys
# # import tkinter as tk
# # from tkinter import scrolledtext
# # from tkinter import messagebox

# # #Host & Port
# # HOST = '127.0.0.1'
# # print(HOST)
# # # set to ip adderes of target computer

# # PORT = 9999

# # DARK_GREY = '#9898FB'
# # MEDIUM_GREY = '#BBBBFF'
# # OCEAN_BLUE = '#C1C1CD'
# # WHITE = "BLACK"
# # FONT = ("Helvetica", 17)
# # BUTTON_FONT = ("Helvetica", 15)
# # SMALL_FONT = ("Helvetica", 13)

# # # Creating a socket object
# # # AF_INET: we are going to use IPv4 addresses
# # # SOCK_STREAM: we are using TCP packets for communication
# # client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# # #Connect Server#
# # def connect():
# #     # try except block
# #     try:
# #         # Connect to the server
# #         client.connect((HOST, PORT))
# #         print("Successfully connected to server")
# #         add_message("[SERVER] Successfully connected to the server")
# #     except:
# #         messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}")

# #     username = username_textbox.get()
# #     if username != '':
# #         client.sendall(username.encode())
# #     else:
# #         messagebox.showerror("Invalid username", "Username cannot be empty")

# #     threading.Thread(target=listen_for_messages_from_server, args=(client, )).start()

# #     username_textbox.config(state=tk.DISABLED)
# #     username_button.config(state=tk.DISABLED)
    
# # #ADD MESSAGE
# # def add_message(message):
# #     message_box.config(state=tk.NORMAL)
# #     message_box.insert(tk.END, message + '\n')
# #     message_box.config(state=tk.DISABLED)
    
# # #Send Message
# # def send_message():
# #     message = message_textbox.get()
# #     if message != '':
# #         client.sendall(message.encode())
# #         message_textbox.delete(0, len(message))
# #     else:
# #         messagebox.showerror("Empty message", "Message cannot be empty")
        
# # #TKINTER
# # root = tk.Tk()
# # root.geometry("600x600")
# # root.title("Gossip..!")
# # root.resizable(False, False)

# # root.grid_rowconfigure(0, weight=1)
# # root.grid_rowconfigure(1, weight=4)
# # root.grid_rowconfigure(2, weight=1)

# # top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
# # top_frame.grid(row=0, column=0, sticky=tk.NSEW)

# # middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
# # middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

# # bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
# # bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

# # username_label = tk.Label(top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
# # username_label.pack(side=tk.LEFT, padx=10)

# # username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
# # username_textbox.pack(side=tk.LEFT)

# # username_button = tk.Button(top_frame, text="connect", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
# # username_button.pack(side=tk.LEFT, padx=15)

# # message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=38)
# # message_textbox.pack(side=tk.LEFT, padx=10)

# # message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
# # message_button.pack(side=tk.LEFT, padx=10)

# # message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26.5)
# # message_box.config(state=tk.DISABLED)
# # message_box.pack(side=tk.TOP)

# # #================Listen for Incomming Message===============#
# # """
# # The incomming message is encoded in utf-8 , which we need to decode to print in the tkinter box.
# # """
# # def listen_for_messages_from_server(client):
# #     while 1:
# #         message = client.recv(2048).decode('utf-8')
# #         if message != '':
# #             username = message.split("~")[0]
# #             content = message.split('~')[1]
# #             add_message(f"[{username}] {content}")
            
# #         else:
# #             print("git testing change")
# #             messagebox.showerror("Error", "Message recevied from client is empty")

# # #Main
# # def main():
# #     root.mainloop()
    
# # if __name__ == '__main__':
# #     main()
