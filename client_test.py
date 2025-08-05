import socket, sys
HOST, PORT = "192.168.5.240", 9999
with socket.create_connection((HOST, PORT)) as s:
    s.sendall(b"Hello over Python!\n")
    print('Reply:', s.recv(1024).decode().strip())