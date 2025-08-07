from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def create_rsa_key_pairs():
    """
    Generates a new RSA private/public key pair.
    Returns a dictionary containing the private key object and the 
    public key in PEM format for easy transmission.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048 bits is a standard, secure size
    )
    
    # The public key is derived from the private key
    public_key = private_key.public_key()

    # We serialize the public key into PEM format. This is a standard
    # text-based format for storing and sending cryptographic keys.
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {"private": private_key, "public_pem": public_pem}

def encrypt_rsa(message_bytes, peer_public_pem):
    """
    Encrypts a message using the peer's public key.
    
    Args:
        message_bytes (bytes): The message to encrypt, as bytes.
        peer_public_pem (bytes): The peer's public key, in PEM format.
        
    Returns:
        bytes: The encrypted ciphertext.
    """
    # First, we load the peer's public key from the PEM data
    public_key = serialization.load_pem_public_key(peer_public_pem)
    
    # Now we encrypt the message using the loaded public key.
    # OAEP padding is the modern standard and provides better security.
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext, self_private_key):
    """
    Decrypts a message using our own private key.
    
    Args:
        ciphertext (bytes): The encrypted data received from the peer.
        self_private_key (object): Our own private key object.
        
    Returns:
        bytes: The decrypted plaintext message.
    """
    # We use our private key to decrypt the ciphertext.
    # The padding scheme must match the one used for encryption.
    plaintext = self_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.backends import default_backend

# def create_public_key_pem(private_key):
#     public_key = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

#     return public_key

# def create_rsa_key_pairs(public_initiator_pem=None):
#     # public key as PEM, private key as is
#     if public_initiator_pem is not None:
#         # create responder's public-private key pair
#         private_responder = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
#         public_responder_pem = create_public_key_pem(private_key=private_responder)

#         return {
#             "role": "responder", 
#             "self": {
#                 "public_pem": public_responder_pem,
#                 "private": private_responder
#             },
#             "peer": {
#                 "public_pem": public_initiator_pem
#             }
#         }
    
#     # create initiator's public-private key pair
#     private_initiator = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
#     public_initiator_pem = create_public_key_pem(private_key=private_initiator)

#     return {
#         "role": "initiator",
#         "self": {
#             "public_pem": public_initiator_pem,
#             "private": private_initiator
#         }
#     }