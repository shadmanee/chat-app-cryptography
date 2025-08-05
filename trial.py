import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

# GUI Colors and Fonts
BG_DARK = '#9898FB'
BG_MEDIUM = '#BBBBFF'
BG_BUTTON = '#C1C1CD'
FG_TEXT = 'BLACK'
FONT = ("Helvetica", 16)
SMALL_FONT = ("Helvetica", 12)

# Global socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def receive_messages():
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if message:
                chat_box.config(state=tk.NORMAL)
                chat_box.insert(tk.END, f"{message}\n")
                chat_box.config(state=tk.DISABLED)
                chat_box.see(tk.END)
        except:
            break

def send_message():
    msg = message_entry.get()
    if msg.strip():
        try:
            sock.sendall(msg.encode())
            chat_box.config(state=tk.NORMAL)
            chat_box.insert(tk.END, f"You: {msg}\n")
            chat_box.config(state=tk.DISABLED)
            chat_box.see(tk.END)
            message_entry.delete(0, tk.END)
        except:
            messagebox.showerror("Error", "Could not send message")
    else:
        messagebox.showwarning("Warning", "Cannot send empty message")

def connect():
    global sock
    role = role_var.get()
    port = int(port_entry.get())
    
    if role == "Server":
        sock.bind(("192.168.5.240", port))
        sock.listen(1)
        status_label.config(text="Waiting for client...")
        conn, addr = sock.accept()
        status_label.config(text=f"Connected to {addr[0]}")
        sock = conn
    elif role == "Client":
        server_ip = ip_entry.get().strip()
        try:
            sock.connect((server_ip, port))
            status_label.config(text=f"Connected to server {server_ip}")
        except:
            messagebox.showerror("Error", "Failed to connect to server")
            return
    else:
        messagebox.showerror("Error", "Please select Server or Client")
        return

    # Disable connection options
    connect_btn.config(state=tk.DISABLED)
    ip_entry.config(state=tk.DISABLED)
    port_entry.config(state=tk.DISABLED)
    server_radio.config(state=tk.DISABLED)
    client_radio.config(state=tk.DISABLED)

    # Start receiving thread
    threading.Thread(target=receive_messages, daemon=True).start()

# ========== GUI ==========
root = tk.Tk()
root.title("Simple Wi-Fi TCP Chat")
root.geometry("900x700")
root.resizable(True, True)

# Top Frame - Connection
top_frame = tk.Frame(root, bg=BG_DARK)
top_frame.pack(padx=10, pady=10, fill=tk.X)

role_var = tk.StringVar()
server_radio = tk.Radiobutton(top_frame, text="Server", variable=role_var, value="Server", font=FONT, bg=BG_DARK, fg=FG_TEXT)
client_radio = tk.Radiobutton(top_frame, text="Client", variable=role_var, value="Client", font=FONT, bg=BG_DARK, fg=FG_TEXT)
server_radio.grid(row=0, column=0, padx=5)
client_radio.grid(row=0, column=1, padx=5)

tk.Label(top_frame, text="Server IP:", bg=BG_DARK, font=FONT).grid(row=0, column=2, padx=5)
ip_entry = tk.Entry(top_frame, font=FONT, width=15)
ip_entry.grid(row=0, column=3, padx=5)

tk.Label(top_frame, text="Port:", bg=BG_DARK, font=FONT).grid(row=0, column=4, padx=5)
port_entry = tk.Entry(top_frame, font=FONT, width=5)
port_entry.insert(0, "5000")
port_entry.grid(row=0, column=5, padx=5)

connect_btn = tk.Button(top_frame, text="Connect", font=FONT, bg=BG_BUTTON, command=connect)
connect_btn.grid(row=0, column=6, padx=10)

status_label = tk.Label(root, text="Not connected", font=SMALL_FONT, fg="red")
status_label.pack()

# Middle Frame - Chat
chat_box = scrolledtext.ScrolledText(root, font=SMALL_FONT, state=tk.DISABLED, wrap=tk.WORD)
chat_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Bottom Frame - Send
bottom_frame = tk.Frame(root, bg=BG_DARK)
bottom_frame.pack(padx=10, pady=10, fill=tk.X)

message_entry = tk.Entry(bottom_frame, font=FONT, width=40)
message_entry.pack(side=tk.LEFT, padx=10)

send_btn = tk.Button(bottom_frame, text="Send", font=FONT, bg=BG_BUTTON, command=send_message)
send_btn.pack(side=tk.LEFT)

root.mainloop()
