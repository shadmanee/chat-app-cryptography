import socket

HOST, PORT   = "", 9000        # Listen on all interfaces
BUFFER_SIZE  = 1024

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[+] Listening on {HOST}:{PORT}")

    conn, addr = srv.accept()         # Blocks until a client connects
    with conn:
        print(f"[+] Connected by {addr}")

        while True:                   # ‼️  Keeps the connection alive
            data = conn.recv(BUFFER_SIZE)
            if not data:              # Empty → the client closed the socket
                print("[!] Client disconnected")
                break

            msg = data.decode().rstrip()
            print(f"[client] {msg}")

            # Optional: echo or send any reply you like
            conn.sendall(b"ACK: " + data)


# import socket, threading
# HOST, PORT = '', 9000           # '' binds to all local addresses
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.bind((HOST, PORT))
#     s.listen()
#     print('Waiting for a connection on port', PORT)
#     conn, addr = s.accept()
#     with conn:
#         print('Connected by', addr)
#         while data := conn.recv(1024):
#             print('Received:', data.decode().strip())
#             conn.sendall(b'ACK\n')
