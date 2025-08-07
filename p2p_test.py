import argparse, socket, threading, sys, os
from functions import create_rsa_key_pairs, encrypt_rsa, decrypt_rsa

# --- Global State ---
# Using a dictionary to hold state is cleaner than multiple global variables.
STATE = {
    "self_private": None,      # Our own private key object
    "peer_public_pem": None,   # Our peer's public key in PEM format
    "awaiting_key_response": False, # Flag to prevent key exchange loops
}

# A delimiter is crucial for message framing in a TCP stream.
# It ensures we can separate one message from the next.
DELIM = b"\r\n<EOM>\r\n" # End Of Message

def recv_loop(sock):
    """
    Handles receiving, framing, and decrypting all incoming messages.
    This runs in a separate thread.
    """
    buffer = b""
    while True:
        try:
            # Read data from the socket in chunks
            data = sock.recv(4096)
            if not data:
                break # Connection closed by peer
            
            buffer += data
            
            # Process all complete messages currently in the buffer
            while DELIM in buffer:
                # Split the buffer into the first message and the rest
                message, buffer = buffer.split(DELIM, 1)
                
                # Case 1: The message is a public key.
                if message.startswith(b"-----BEGIN PUBLIC KEY-----"):
                    # If we were the initiator waiting for this key, the exchange is now complete.
                    if STATE.get("awaiting_key_response"):
                        print("\n[+] Received peer's key response. Handshake complete.")
                        STATE["peer_public_pem"] = message
                        STATE["awaiting_key_response"] = False # Reset the flag
                        print("[*] New secure channel established.")
                    # Otherwise, this is a new request from the peer. We must respond.
                    else:
                        print("\n[+] Received new public key from peer. Resetting session.")
                        STATE["peer_public_pem"] = message
                        
                        print("[+] Generating new key pair to respond...")
                        key_info = create_rsa_key_pairs()
                        STATE["self_private"] = key_info["private"]
                        self_public_pem = key_info["public_pem"]
                        
                        sock.sendall(self_public_pem + DELIM)
                        print("[*] Response sent. New secure channel established.")

                # Case 2: The message is explicitly tagged as plaintext
                elif message.startswith(b"PLAINTEXT::"):
                    plaintext = message.split(b"::", 1)[1]
                    peer_addr = sock.getpeername()[0]
                    print(f"\r{peer_addr} (plaintext) > {plaintext.decode()}")

                # Case 3: The message is assumed to be encrypted
                else:
                    if STATE["self_private"]:
                        try:
                            plaintext = decrypt_rsa(message, STATE["self_private"])
                            peer_addr = sock.getpeername()[0]
                            print(f"\r{peer_addr} (encrypted) > {plaintext.decode()}")
                        except Exception:
                            print("\n[!] Failed to decrypt message. It may be corrupted or not encrypted.")
                    else:
                        print(f"\n[!] Received encrypted message, but no key is available for decryption.")

                print("> ", end="", flush=True)

        except ConnectionResetError:
            break # Peer forced the connection to close
            
    print("\n[!] Peer has closed the connection.")
    os._exit(1)


def chat(sock):
    """
    Handles user input, encryption, and sending messages.
    """
    # Start the receiving loop in a background thread
    threading.Thread(target=recv_loop, args=(sock,), daemon=True).start()
    
    print("--- Chat Initialized ---")
    print("Type '/rsa' to initiate or reset a secure key exchange.")
    print("Type 'quit' to exit.")
    print("---------------------------------")

    while True:
        try:
            line = input("> ")
            if not line:
                continue

            if line.lower() == "quit":
                sock.close()
                os._exit(0)
            
            # Command to initiate or reset key exchange
            if line.lower() == r"/rsa":
                print("[*] Initiating key exchange...")
                # Set a flag indicating we are waiting for the peer's key to complete the handshake.
                STATE["awaiting_key_response"] = True
                # Clear the old peer key to prevent sending messages until the new one arrives.
                STATE["peer_public_pem"] = None 
                
                key_info = create_rsa_key_pairs()
                STATE["self_private"] = key_info["private"]
                self_public_pem = key_info["public_pem"]
                
                sock.sendall(self_public_pem + DELIM)
                print("[+] Your public key sent. Waiting for peer's response...")
                continue

            # --- ENCRYPTION / PLAINTEXT STEP ---
            if STATE["peer_public_pem"] and STATE["self_private"]:
                try:
                    ciphertext = encrypt_rsa(line.encode(), STATE["peer_public_pem"])
                    sock.sendall(ciphertext + DELIM)
                except Exception as e:
                    print(f"[!] Encryption failed: {e}")
            else:
                print("[!] No encryption. Sending as plaintext.")
                sock.sendall(b"PLAINTEXT::" + line.encode() + DELIM)

        except (EOFError, KeyboardInterrupt):
            print("\n[+] Exiting...")
            sock.close()
            os._exit(0)


def main():
    """Parses arguments and starts the chat in either listen or connect mode."""
    ap = argparse.ArgumentParser(description="A simple two-peer encrypted chat application")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--listen",  type=int, metavar="PORT", help="Listen for an incoming connection on PORT")
    grp.add_argument("--connect", type=int, metavar="PORT", help="Connect to a peer on PORT (IP is prompted)")
    args = ap.parse_args()

    if args.listen:
        port = args.listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", port))
            srv.listen(1)
            print(f"[*] Listening for a connection on 0.0.0.0:{port}")
            conn, addr = srv.accept()
            print(f"[+] Connected by {addr[0]}:{addr[1]}")
            with conn:
                chat(conn)
    else:
        port = args.connect
        host = input(f"Peer IP to connect to on port {port}: ").strip()
        if not host:
            print("[!] Host IP cannot be empty.")
            sys.exit(1)
            
        try:
            with socket.create_connection((host, port)) as s:
                print(f"[*] Connected to {host}:{port}")
                chat(s)
        except OSError as e:
            print(f"[!] Connection failed: {e}")

if __name__ == "__main__":
    main()