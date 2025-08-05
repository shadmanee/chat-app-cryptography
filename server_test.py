import socket, threading
HOST, PORT = '', 9999           # '' binds to all local addresses
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print('Waiting for a connection on port', PORT)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while data := conn.recv(1024):
            print('Received:', data.decode().strip())
            conn.sendall(b'ACK\n')
