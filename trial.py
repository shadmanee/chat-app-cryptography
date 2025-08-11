

# import os
# import struct
# from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
# from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# # framing helpers for length-prefixed fields
# def pack_len_prefixed(b: bytes) -> bytes:
#     return struct.pack(">H", len(b)) + b

# def unpack_len_prefixed(buf: bytes, offset=0):
#     if len(buf) < offset + 2:
#         raise ValueError("not enough bytes for length")
#     L = struct.unpack(">H", buf[offset:offset+2])[0]
#     start = offset + 2
#     end = start + L
#     if len(buf) < end:
#         raise ValueError("buffer truncated for data")
#     return buf[start:end], end

# def fingerprint_of_pem(pub_pem: bytes) -> str:
#     # hex of SHA-256 of the public PEM for ID purposes
#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(pub_pem)
#     return digest.finalize().hex()

# def create_rsa_key_pairs():
#     """
#     Generates a new RSA private/public key pair.
#     Returns a dictionary containing the private key object and the 
#     public key in PEM format for easy transmission.
#     """
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,  # 2048 bits is a standard, secure size
#     )
    
#     # The public key is derived from the private key
#     public_key = private_key.public_key()

#     # We serialize the public key into PEM format. This is a standard
#     # text-based format for storing and sending cryptographic keys.
#     public_pem = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
    
#     return {"private": private_key, "public_pem": public_pem}

# def encrypt_rsa(message_bytes, peer_public_pem):
#     """
#     Encrypts a message using the peer's public key.
    
#     Args:
#         message_bytes (bytes): The message to encrypt, as bytes.
#         peer_public_pem (bytes): The peer's public key, in PEM format.
        
#     Returns:
#         bytes: The encrypted ciphertext.
#     """
#     # First, we load the peer's public key from the PEM data
#     public_key = serialization.load_pem_public_key(peer_public_pem)
    
#     # Now we encrypt the message using the loaded public key.
#     # OAEP padding is the modern standard and provides better security.
#     ciphertext = public_key.encrypt(
#         message_bytes,
#         asym_padding.OAEP(
#             mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return ciphertext

# def decrypt_rsa(ciphertext, self_private_key):
#     """
#     Decrypts a message using our own private key.
    
#     Args:
#         ciphertext (bytes): The encrypted data received from the peer.
#         self_private_key (object): Our own private key object.
        
#     Returns:
#         bytes: The decrypted plaintext message.
#     """
#     # We use our private key to decrypt the ciphertext.
#     # The padding scheme must match the one used for encryption.
#     plaintext = self_private_key.decrypt(
#         ciphertext,
#         asym_padding.OAEP(
#             mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return plaintext


# def sign_message(self_private_key, message_bytes):
#     return self_private_key.sign(
#         message_bytes,
#         asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
#         hashes.SHA256()
#     )

# def verify_signature(peer_public_pem, message_bytes, signature_bytes):
#     public_key = serialization.load_pem_public_key(peer_public_pem)
#     try:
#         print(message_bytes)
#         print(signature_bytes)
#         public_key.verify(
#             signature_bytes,
#             message_bytes,
#             asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
#             hashes.SHA256()
#         )
#         return True
#     except Exception:
#         return False

# a=create_rsa_key_pairs()["private"]
# b=create_rsa_key_pairs()["public_pem"]
# c=sign_message(a,"hello".encode())
# print(verify_signature(b,"hello".encode(),c))
