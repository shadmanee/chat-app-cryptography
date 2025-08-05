import socket

HOST, PORT   = "10.222.93.158", 9000
BUFFER_SIZE  = 1024

with socket.create_connection((HOST, PORT)) as s:
    print("Connected.  Type a message (blank line to quit).")

    while True:                       # ‼️  Keeps sending in the same session
        msg = input("> ")
        if not msg:                   # Empty line → graceful shutdown
            break

        s.sendall(msg.encode() + b"\n")          # ‘\n’ is just a delimiter
        reply = s.recv(BUFFER_SIZE).decode().rstrip()
        print("Reply:", reply)

# import socket, sys
# HOST, PORT = "10.222.93.158", 9000
# with socket.create_connection((HOST, PORT)) as s:
#     s.sendall(b"Hello over Python!\n")
#     print('Reply:', s.recv(1024).decode().strip())