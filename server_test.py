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