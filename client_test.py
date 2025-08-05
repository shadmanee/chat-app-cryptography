#!/usr/bin/env python3
import socket, threading, sys

HOST, PORT = "10.222.93.158", 9000     # change host as needed

def listen(sock):
    """Background thread that prints anything the server sends."""
    while True:
        data = sock.recv(1024)
        if not data:
            print("\n[!] Server closed the connection")
            sys.exit()
        # \r ensures we don’t overwrite the user’s prompt
        print("\r" + data.decode().rstrip() + "\n> ", end="")

with socket.create_connection((HOST, PORT)) as s:
    threading.Thread(target=listen, args=(s,), daemon=True).start()
    print("Connected — start typing!  (Ctrl-C or empty line to quit)")

    for line in sys.stdin:              # read user input forever
        if not line.strip():            # blank line to exit
            break
        s.sendall(line.rstrip().encode() + b"\n")


# import socket

# HOST, PORT   = "10.222.93.158", 9000
# BUFFER_SIZE  = 1024

# with socket.create_connection((HOST, PORT)) as s:
#     print("Connected.  Type a message (blank line to quit).")

#     while True:                       # ‼️  Keeps sending in the same session
#         msg = input("> ")
#         if not msg:                   # Empty line → graceful shutdown
#             break

#         s.sendall(msg.encode() + b"\n")          # ‘\n’ is just a delimiter
#         reply = s.recv(BUFFER_SIZE).decode().rstrip()
#         print("Reply:", reply)


# # import socket, sys
# # HOST, PORT = "10.222.93.158", 9000
# # with socket.create_connection((HOST, PORT)) as s:
# #     s.sendall(b"Hello over Python!\n")
# #     print('Reply:', s.recv(1024).decode().strip())