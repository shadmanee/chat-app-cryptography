#!/usr/bin/env python3
# p2p_chat.py
import argparse, socket, threading, sys

BUF = 1024

def recv_loop(sock):
    while True:
        data = sock.recv(BUF)
        if not data:
            print("\n[peer closed]")
            sys.exit(0)
        print("\r" + data.decode().strip())
        print("> ", end="", flush=True)

def chat(sock):
    threading.Thread(target=recv_loop, args=(sock,), daemon=True).start()
    while True:
        try:
            line = input("> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not line.strip():
            break
        sock.sendall(line.encode() + b"\n")

def main():
    ap = argparse.ArgumentParser()
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--listen",  type=int, metavar="PORT")
    grp.add_argument("--connect", metavar="HOST:PORT")
    args = ap.parse_args()

    if args.listen is not None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", args.listen))
            srv.listen(1)
            print(f"[listening on 0.0.0.0:{args.listen}]")
            conn, addr = srv.accept()
            print(f"[connected by {addr}]")
            chat(conn)
    else:
        host, port = args.connect.rsplit(":", 1)
        with socket.create_connection((host, int(port))) as s:
            print(f"[connected to {host}:{port}]")
            chat(s)

if __name__ == "__main__":
    main()
