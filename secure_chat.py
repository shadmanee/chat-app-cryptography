import argparse, socket, threading, sys, os
from functions import *

# a dictionary of global variables.
STATE = {
    "self_private": None,      # own private key object
    "self_public_pem": None,   # own public key in PEM format
    "peer_public_pem": None,   # peer's public key in PEM format
    "awaiting_key_response": False, # Flag to prevent RSA key exchange loops

    "shared_key":None,  # shared symmetric key object
    "self_nonce":None,  # own nonce
    "await_init":False, # Flag to prevent loop in 1st step of AES key exchange protocol
    "await_send":False, # Flag to prevent loop in 2nd step of AES key exchange protocol
}

# delimiter crucial for message framing in a TCP stream. It ensures we can separate one message from the next.
DELIM = b"\r\n<EOM>\r\n" # End Of Message

def recv_loop(sock):
    """
    Handles receiving and decrypting all incoming messages.
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
                # message is everything up to the first DELIM
                message, buffer = buffer.split(DELIM, 1)

                # --- PUBLIC KEY EXCHANGE PROTOCOL ---
                if message.startswith(b"-----BEGIN PUBLIC KEY-----"): #rsa public keys have this message at the start by default
                    if STATE.get("awaiting_key_response"):  #if it is the  RSA protocol initiator who received response from responder
                        print("\n[+] Received peer's key response. Handshake complete.")
                        STATE["peer_public_pem"] = message # store peer's public key
                        STATE["awaiting_key_response"] = False # reset await flag 
                        print("[+] New secure channel established.")
                    else: #else it is the rsa protocol responder who received public key from the initiator
                        print("\n[+] Received new public key from peer. Resetting session.")
                        STATE["peer_public_pem"] = message #store public key of initiator

                        print("[+] Generating new key pair to respond...")
                        key_info = create_rsa_key_pairs() #generate own public private key and send own public key back to initiator
                        STATE["self_private"] = key_info["private"]
                        STATE["self_public_pem"] = key_info["public_pem"]

                        sock.sendall(STATE["self_public_pem"] + DELIM)
                        print("[+] Response sent. New secure channel established.")



                # --- 1ST STEP OF SYMMETRIC KEY EXCHANGE PROTOCOL  ---
                elif message.startswith(b"AES1::"):
                    # Extract the RSA ciphertext portion by removing the header
                    c1 = message[len(b"AES1::"):]

                    # # Diagnostic: show ciphertext length vs expected RSA length (optional)
                    # if STATE.get("self_private"):
                    #     expected_len = STATE["self_private"].key_size // 8
                    #     # only show if length mismatches (helpful debugging)
                    #     if len(c1) != expected_len:
                    #         print(f"[!] Warning: AES1 ciphertext length {len(c1)} != expected RSA length {expected_len}")

                    # If it is the AES protocol initiator waiting for response from receiver 
                    if STATE.get("await_init"):
                        # decrypt using our rsa private key
                        payload = decrypt_rsa(c1, STATE["self_private"])

                        # Unpack nonce_self and nonce_peer
                        self_nonce, offset = unpack_len_prefixed(payload)
                        peer_nonce, _ = unpack_len_prefixed(payload, offset)

                        #initator verifies its own sent nonce
                        if self_nonce != STATE["self_nonce"]:
                            raise ValueError("Nonce mismatch — Received message not fresh")

                        print("[+] Message freshness verified by nonce match")
                        STATE["await_init"] = False

                        # create shared_key (Ks) and sign it
                        STATE["shared_key"] = create_aes_key()
                        signature = sign_message(STATE["self_private"], STATE["shared_key"])

                        # Build payload: peer_nonce, Ks, signature  i.e., N2||Ks||Sign(Ks)
                        out_payload = pack_len_prefixed(peer_nonce) + pack_len_prefixed(STATE["shared_key"]) + pack_len_prefixed(signature)

                        # Use hybrid encryption using self public key (AES-GCM envelope + RSA-encrypted AES key) for payload 
                        c_out = hybrid_encrypt(out_payload, STATE["peer_public_pem"])
                        sock.sendall(b"AES2::" + c_out + DELIM) # add AES2 header to indicate that next is the 2nd step of the AES key protocol
                        print("[+] 1st Handshake complete.")
                        print("[+] Sent E(PU_b, [N2 || Ks || E(PR_a, Ks)])")
                    
                    # Else it is the Responder who received protocol message from initiator
                    else:
                        # decrypt message using own private key and unpack initiator nonce and ID_A
                        payload = decrypt_rsa(c1, STATE["self_private"])
                        peer_nonce, offset = unpack_len_prefixed(payload)
                        peer_id, _ = unpack_len_prefixed(payload, offset)

                        #verify that it is actually the initiator and not some man-in-the-middle by using initator's ID
                        expected_id = fingerprint_of_pem(STATE["peer_public_pem"]).encode()
                        if peer_id != expected_id:
                            raise ValueError("Fingerprint mismatch — identity of AES initiator not verified")

                        print("[+] Initiator identity verified by fingerprint:", peer_id.decode())
                        STATE["shared_key"] = None # remove old shared key
                        STATE["await_send"] = True # set flag to indicate that the responder is waiting for initator's 2nd step message of the protocol

                        # Build responder's own nonce N2 and send back with initator's nonce: [N1 || N2] encrypted with initiator's public key
                        STATE["self_nonce"] = os.urandom(16)
                        out_payload = pack_len_prefixed(peer_nonce) + pack_len_prefixed(STATE["self_nonce"])
                        c_out = encrypt_rsa(out_payload, STATE["peer_public_pem"])
                        sock.sendall(b"AES1::" + c_out + DELIM)
                        print("[+] Sent E(PU_a, [N1 || N2])")


                # --- 2ND STEP OF SYMMETRIC KEY EXCHANGE PROTOCOL  ---
                elif message.startswith(b"AES2::"):
                    c2 = message[len(b"AES2::"):] #remove AES2 header

                    if STATE.get("await_send"): # If responder got the 2nd step AES protocol message:
                        # hybrid_decrypt expects the hybrid blob (not the whole framed message)
                        payload = hybrid_decrypt(c2, STATE["self_private"])

                        # Unpack nonce_self, Ks, signature
                        self_nonce, offset = unpack_len_prefixed(payload)
                        Ks, offset1 = unpack_len_prefixed(payload, offset)
                        Signature, _ = unpack_len_prefixed(payload, offset1)

                        #receiver verifies its own sent nonce
                        if self_nonce != STATE["self_nonce"]:
                            raise ValueError("Nonce mismatch — Received message not fresh")

                        print("[+] Message freshness verified by nonce match")
                        STATE["await_send"] = False

                        # Verify signature (returns True/False or raise error depending)
                        val = verify_signature(STATE["peer_public_pem"], Ks, Signature)
                        if val:
                            STATE["shared_key"] = Ks
                            print("[+] 2nd Handshake complete. Shared Key successfully exchanged.")
                        else:
                            raise ValueError("Signature on Ks failed verification")
                        
                    else:
                        # If not awaiting, we might be a responder receiving an unexpected AES2 message
                        print("[!] Unexpected message received. AES protocol failed.")

                # --- NOT A RSA OR AES PROTOCOL MESSAGE. INSTEAD ACTUAL ENCRYPTED/UNENCRYPTED TEXT MESSAGE ---
                else:
                    # --- RECEIVING PLAINTEXT ---
                    if message.startswith(b"PLAINTEXT::"): 
                        plaintext = message.split(b"::", 1)[1]
                        peer_addr = sock.getpeername()[0]
                        print(f"\r{peer_addr} (plaintext) > {plaintext.decode()}")

                    # --- RECEIVING RSA ENCRYPTED TEXT ---
                    elif STATE["self_private"] and STATE["shared_key"]==None:
                        try:
                            plaintext = decrypt_rsa(message, STATE["self_private"])
                            peer_addr = sock.getpeername()[0]
                            print(f"\r{peer_addr} (encrypted with RSA) > {plaintext.decode()}")
                        except Exception:
                            print("\n[!] Failed to decrypt rsa message. It may be corrupted or not encrypted.")

                    # --- RECEIVING AES ENCRYPTED TEXT ---
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
    print("Type '/rsa' to initiate or reset a public-private RSA key pair exchange.")
    print("Type '/aes' to initiate or reset a secure shared AES 256 key exchange.")
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
            
            # Command to initiate or reset RSA public key exchange
            elif line.lower() == r"/rsa":
                print("[*] Initiating key exchange...") 
                STATE["awaiting_key_response"] = True # Set a flag indicating we are waiting for the peer's key to complete the handshake.
                STATE["peer_public_pem"] = None # Clear the old peer key to prevent sending messages until the new one arrives.
                
                key_info = create_rsa_key_pairs() #generate own public private key paris
                STATE["self_private"] = key_info["private"]
                STATE["self_public_pem"] = key_info["public_pem"]
                
                #send the own public key to peer
                sock.sendall(STATE["self_public_pem"] + DELIM)
                print("[+] Your public key sent. Waiting for peer's response...")

            # Command to initiate or reset AES shared key exchange
            elif line.lower() == r"/aes":
                if STATE["peer_public_pem"] and STATE["self_private"]:
                    print("[*] Initiating key exchange...")
                    STATE["await_init"] = True  # Set a flag indicating we are waiting for the peer to complete the 1st AES handshake.
                    STATE["shared_key"] = None # Clear the old AES key to prevent sending messages until the new one arrives.
                    
                    # Build Nonce and identifier (fingerprint)
                    STATE["self_nonce"] = os.urandom(16)
                    ID_A = fingerprint_of_pem(STATE["self_public_pem"]).encode()  

                    #send rsa encrypted nonce and ID with a header indicating that this is 1st part of AES protocol
                    payload = pack_len_prefixed(STATE["self_nonce"]) + pack_len_prefixed(ID_A)
                    c1 = encrypt_rsa(payload, STATE["peer_public_pem"])
                    sock.sendall(b"AES1::" + c1 + DELIM)
                    print("[*] Sent E(PU_b, [N1 || ID_A])")
                else:
                    print("[!] AES-256 key exchange failed. Generate RSA key pairs using /rsa first.")

            # --- SEND TEXT STEP IF AES KEY EXISTS ---
            elif STATE["shared_key"]:
                try:
                    ciphertext = encrypt_aes(line, STATE["shared_key"])
                    sock.sendall(ciphertext + DELIM)
                except Exception as e:
                    print(f"[!] Encryption failed: {e}")

            # --- SEND TEXT STEP IF ONLY RSA KEY EXISTS BUT AES KEY DOES NOT ---
            elif STATE["peer_public_pem"] and STATE["self_private"] and STATE["shared_key"]==None:
                try:
                    ciphertext = encrypt_rsa(line.encode(), STATE["peer_public_pem"])
                    sock.sendall(ciphertext + DELIM)
                except Exception as e:
                    print(f"[!] Encryption failed: {e}")

            # --- SEND TEXT STEP IF NEITHER RSA KEY NOR AES KEY EXISTS. Header provided to indicate that this is a plaintext ---
            else:
                print("[!] No encryption. Sending as plaintext.")
                sock.sendall(b"PLAINTEXT::" + line.encode() + DELIM)

        except (EOFError, KeyboardInterrupt):
            print("\n[+] Exiting...")
            sock.close()
            os._exit(0)


def main():
    """start chat in either listen or connect mode"""
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
                print(f"[+] Connected to {host}:{port}")
                chat(s)
        except OSError as e:
            print(f"[!] Connection failed: {e}")

if __name__ == "__main__":
    main()