#!/usr/bin/env python3
import socket
import threading

HOST, PORT   = "", 9000        # 0.0.0.0 = all interfaces
BUFFER_SIZE  = 1024

clients = []                   # active sockets
lock    = threading.Lock()     # protect the list


def handle_client(conn, addr):
    """Receive from one client and fan-out to the rest."""
    with conn:
        print(f"[+] {addr} joined")
        with lock:
            clients.append(conn)

        try:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:            # client closed
                    break

                # Tag with the sender’s address (optional)
                tagged = f"[{addr[0]}:{addr[1]}] ".encode() + data

                # Broadcast to everyone except the sender
                with lock:
                    for peer in clients:
                        if peer is not conn:
                            peer.sendall(tagged)

        finally:
            with lock:
                clients.remove(conn)
            print(f"[-] {addr} left")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        print(f"[+] Listening on {HOST or '0.0.0.0'}:{PORT}")

        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr),
                             daemon=True).start()


if __name__ == "__main__":
    main()

# import socket

# HOST, PORT   = "", 9000        # Listen on all interfaces
# BUFFER_SIZE  = 1024

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
#     srv.bind((HOST, PORT))
#     srv.listen(1)
#     print(f"[+] Listening on {HOST}:{PORT}")

#     conn, addr = srv.accept()         # Blocks until a client connects
#     with conn:
#         print(f"[+] Connected by {addr}")

#         while True:                   # ‼️  Keeps the connection alive
#             data = conn.recv(BUFFER_SIZE)
#             if not data:              # Empty → the client closed the socket
#                 print("[!] Client disconnected")
#                 break

#             msg = data.decode().rstrip()
#             print(f"[client] {msg}")

#             # Optional: echo or send any reply you like
#             conn.sendall(b"ACK: " + data)


# # import socket, threading
# # HOST, PORT = '', 9000           # '' binds to all local addresses
# # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
# #     s.bind((HOST, PORT))
# #     s.listen()
# #     print('Waiting for a connection on port', PORT)
# #     conn, addr = s.accept()
# #     with conn:
# #         print('Connected by', addr)
# #         while data := conn.recv(1024):
# #             print('Received:', data.decode().strip())
# #             conn.sendall(b'ACK\n')
