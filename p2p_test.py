import argparse, socket, threading, sys, os
from functions import *

# --- Global State ---
# Using a dictionary to hold state is cleaner than multiple global variables.
STATE = {
    "self_private": None,      # Our own private key object
    "self_public_pem": None,   # Our own public key in PEM format
    "peer_public_pem": None,   # Our peer's public key in PEM format
    "awaiting_key_response": False, # Flag to prevent key exchange loops

    "shared_key":None,
    "self_nonce":None,
    "await_init":False,
    "await_send":False,
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
            data = sock.recv(4096)
            if not data:
                break
            buffer += data

            while DELIM in buffer:
                # message is everything up to the first DELIM (DELIM not included)
                message, buffer = buffer.split(DELIM, 1)

                # --- PUBLIC KEY EXCHANGE ---
                if message.startswith(b"-----BEGIN PUBLIC KEY-----"):
                    if STATE.get("awaiting_key_response"):
                        print("\n[+] Received peer's key response. Handshake complete.")
                        STATE["peer_public_pem"] = message
                        STATE["awaiting_key_response"] = False
                        print("[*] New secure channel established.")
                    else:
                        print("\n[+] Received new public key from peer. Resetting session.")
                        STATE["peer_public_pem"] = message

                        print("[+] Generating new key pair to respond...")
                        key_info = create_rsa_key_pairs()
                        STATE["self_private"] = key_info["private"]
                        STATE["self_public_pem"] = key_info["public_pem"]

                        sock.sendall(STATE["self_public_pem"] + DELIM)
                        print("[*] Response sent. New secure channel established.")

                # --- AES1:: incoming (first step of AES handshake) ---
                elif message.startswith(b"AES1::"):
                    # Extract the RSA ciphertext portion (exact bytes meant for RSA)
                    c1 = message[len(b"AES1::"):]

                    # Diagnostic: show ciphertext length vs expected RSA length (optional)
                    if STATE.get("self_private"):
                        expected_len = STATE["self_private"].key_size // 8
                        # only show if length mismatches (helpful debugging)
                        if len(c1) != expected_len:
                            print(f"[!] Warning: AES1 ciphertext length {len(c1)} != expected RSA length {expected_len}")

                    # If we were the initiator waiting for 1st handshake response
                    if STATE.get("await_init"):
                        # decrypt using our private key
                        payload = decrypt_rsa(c1, STATE["self_private"])

                        # Unpack nonce_self and nonce_peer
                        self_nonce, offset = unpack_len_prefixed(payload)
                        peer_nonce, _ = unpack_len_prefixed(payload, offset)

                        if self_nonce != STATE["self_nonce"]:
                            raise ValueError("Nonce mismatch — Received message not fresh")

                        print("[*] Message freshness verified by nonce match")
                        STATE["await_init"] = False

                        # create shared_key (Ks) and sign it
                        STATE["shared_key"] = create_aes_key()
                        signature = sign_message(STATE["self_private"], STATE["shared_key"])

                        # Build payload: peer_nonce, Ks, signature
                        out_payload = pack_len_prefixed(peer_nonce) + pack_len_prefixed(STATE["shared_key"]) + pack_len_prefixed(signature)

                        # Use hybrid encrypt (AES-GCM envelope + RSA-encrypted AES key)
                        c_out = hybrid_encrypt(out_payload, STATE["peer_public_pem"])
                        sock.sendall(b"AES2::" + c_out + DELIM)
                        print("[*] 1st Handshake complete.")
                        print("[*] Sent E(PU_b, [N2 || Ks || E(PR_a, Ks)])")

                    else:
                        # Responder behavior: unpack nonce and ID_A
                        payload = decrypt_rsa(c1, STATE["self_private"])
                        peer_nonce, offset = unpack_len_prefixed(payload)
                        peer_id, _ = unpack_len_prefixed(payload, offset)

                        expected_id = fingerprint_of_pem(STATE["peer_public_pem"]).encode()
                        if peer_id != expected_id:
                            raise ValueError("Fingerprint mismatch — identity of AES initiator not verified")

                        print("[*] Initiator identity verified by fingerprint:", peer_id.decode())
                        STATE["shared_key"] = None
                        STATE["await_send"] = True

                        # Build our nonce N2 and send back: [N1 || N2] encrypted with peer's public key
                        STATE["self_nonce"] = os.urandom(16)
                        out_payload = pack_len_prefixed(peer_nonce) + pack_len_prefixed(STATE["self_nonce"])
                        c_out = encrypt_rsa(out_payload, STATE["peer_public_pem"])
                        sock.sendall(b"AES1::" + c_out + DELIM)
                        print("[*] Sent E(PU_a, [N1 || N2])")

                # --- AES2:: incoming (second step: envelope contains Ks signed by A and encrypted for B) ---
                elif message.startswith(b"AES2::"):
                    c2 = message[len(b"AES2::"):]

                    # If we initiated and are awaiting peer's 2nd handshake:
                    if STATE.get("await_send"):
                        # hybrid_decrypt expects the hybrid blob (not the whole framed message)
                        payload = hybrid_decrypt(c2, STATE["self_private"])

                        # Unpack nonce_self, Ks, signature
                        self_nonce, offset = unpack_len_prefixed(payload)
                        Ks, offset1 = unpack_len_prefixed(payload, offset)
                        Signature, _ = unpack_len_prefixed(payload, offset1)

                        if self_nonce != STATE["self_nonce"]:
                            raise ValueError("Nonce mismatch — Received message not fresh")

                        print("[*] Message freshness verified by nonce match")
                        STATE["await_send"] = False

                        # Verify signature (returns True/False or raise depending on your impl)
                        val = verify_signature(STATE["peer_public_pem"], Ks, Signature)
                        if val:
                            STATE["shared_key"] = Ks
                            print("[*] 2nd Handshake complete. Shared Key successfully exchanged.")
                        else:
                            raise ValueError("Signature on Ks failed verification")

                    else:
                        # If not awaiting, we might be a responder receiving an unexpected AES2
                        print("[!] Unexpected AES2 message received while not awaiting handshake.")
                        # you may choose to ignore or log it.

                # --- Plaintext passthrough ---
                elif message.startswith(b"PLAINTEXT::"):
                    plaintext = message.split(b"::", 1)[1]
                    peer_addr = sock.getpeername()[0]
                    print(f"\r{peer_addr} (plaintext) > {plaintext.decode()}")

                # --- Generic encrypted message: try RSA decrypt if we have private key ---
                else:
                    if STATE["self_private"] and STATE["shared_key"]==None:
                        try:
                            plaintext = decrypt_rsa(message, STATE["self_private"])
                            peer_addr = sock.getpeername()[0]
                            print(f"\r{peer_addr} (encrypted with RSA) > {plaintext.decode()}")
                        except Exception:
                            print("\n[!] Failed to decrypt rsa message. It may be corrupted or not encrypted.")
                    elif STATE["shared_key"]:
                        try:
                            plaintext = decrypt_aes(message, STATE["shared_key"])
                            peer_addr = sock.getpeername()[0]
                            print(f"\r{peer_addr} (encrypted with AES256) > {plaintext}")
                        except Exception:
                            print("\n[!] Failed to decrypt aes message. It may be corrupted or not encrypted.")
                    else:
                        print(f"\n[!] Received encrypted message, but no key is available for decryption.")

                print("> ", end="", flush=True)

        except ConnectionResetError:
            break

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
            elif line.lower() == r"/rsa":
                print("[*] Initiating key exchange...")
                # Set a flag indicating we are waiting for the peer's key to complete the handshake.
                STATE["awaiting_key_response"] = True
                # Clear the old peer key to prevent sending messages until the new one arrives.
                STATE["peer_public_pem"] = None 
                
                key_info = create_rsa_key_pairs()
                STATE["self_private"] = key_info["private"]
                STATE["self_public_pem"] = key_info["public_pem"]
                
                sock.sendall(STATE["self_public_pem"] + DELIM)
                print("[+] Your public key sent. Waiting for peer's response...")

            # Command to initiate or reset shared key exchange
            elif line.lower() == r"/aes":
                if STATE["peer_public_pem"] and STATE["self_private"]:
                    print("[*] Initiating key exchange...")
                    # Set a flag indicating we are waiting for the peer to complete the 1st AES handshake.
                    STATE["await_init"] = True
                    # Clear the old AES key to prevent sending messages until the new one arrives.
                    STATE["shared_key"] = None 
                    
                    # Build Nonce and identifier (fingerprint)
                    STATE["self_nonce"] = os.urandom(16)
                    ID_A = fingerprint_of_pem(STATE["self_public_pem"]).encode()  # fingerprint as bytes
                    payload = pack_len_prefixed(STATE["self_nonce"]) + pack_len_prefixed(ID_A)
                    c1 = encrypt_rsa(payload, STATE["peer_public_pem"])
                    sock.sendall(b"AES1::" + c1 + DELIM)
                    print("[*] Sent E(PU_b, [N1 || ID_A])")
                else:
                    print("[!] AES-256 key exchange failed. Generate RSA key pairs using /rsa first.")

            # --- AES ENCRYPTION / PLAINTEXT STEP ---
            elif STATE["shared_key"]:
                try:
                    ciphertext = encrypt_aes(line, STATE["shared_key"])
                    sock.sendall(ciphertext + DELIM)
                except Exception as e:
                    print(f"[!] Encryption failed: {e}")

            # --- RSA ENCRYPTION / PLAINTEXT STEP ---
            elif STATE["peer_public_pem"] and STATE["self_private"] and STATE["shared_key"]==None:
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