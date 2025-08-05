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
    ap = argparse.ArgumentParser(description="Tiny two-peer chat")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--listen",  type=int, metavar="PORT",
                     help="wait for an incoming connection on PORT")
    grp.add_argument("--connect", type=int, metavar="PORT",
                     help="connect to a peer on PORT (IP is prompted)")
    args = ap.parse_args()

    if args.listen is not None:
        port = args.listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", port))
            srv.listen(1)
            print(f"[listening on 0.0.0.0:{port}]")
            conn, addr = srv.accept()
            print(f"[connected by {addr[0]}:{addr[1]}]")
            chat(conn)
    else:                                 # --connect mode
        port = args.connect
        host = input(f"Peer IP to connect on port {port}: ").strip()
        try:
            with socket.create_connection((host, port)) as s:
                print(f"[connected to {host}:{port}]")
                chat(s)
        except OSError as e:
            print(f"[connection failed] {e}")

if __name__ == "__main__":
    main()