import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# framing helpers for length-prefixed fields
def pack_len_prefixed(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b

def unpack_len_prefixed(buf: bytes, offset=0):
    if len(buf) < offset + 2:
        raise ValueError("not enough bytes for length")
    L = struct.unpack(">H", buf[offset:offset+2])[0]
    start = offset + 2
    end = start + L
    if len(buf) < end:
        raise ValueError("buffer truncated for data")
    return buf[start:end], end

def fingerprint_of_pem(pub_pem: bytes) -> str:
    # hex of SHA-256 of the public PEM for ID purposes
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_pem)
    return digest.finalize().hex()

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
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
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
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def sign_message(self_private_key, message_bytes):
    return self_private_key.sign(
        message_bytes,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(peer_public_pem, message_bytes, signature_bytes):
    public_key = serialization.load_pem_public_key(peer_public_pem)
    try:
        public_key.verify(
            signature_bytes,
            message_bytes,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False



#HYBRID ENCRYPTION DECRYPTION USED IN CASE OF E(PUB, E(PR, M) )

def hybrid_encrypt(plaintext_bytes, peer_public_pem):
    # Generate AES-256 key and nonce
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aes_ct = aesgcm.encrypt(nonce, plaintext_bytes, None)  # returns ciphertext||tag

    # Encrypt AES key under peer's RSA public key
    public_key = serialization.load_pem_public_key(peer_public_pem)
    enc_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Pack: 2-byte length + enc_key + nonce + aes_ct
    blob = struct.pack(">H", len(enc_key)) + enc_key + nonce + aes_ct
    return blob

def hybrid_decrypt(blob_bytes, self_private_key):
    if len(blob_bytes) < 2:
        raise ValueError("blob too short")

    # parse length
    L = struct.unpack(">H", blob_bytes[:2])[0]
    if len(blob_bytes) < 2 + L + 12:
        raise ValueError("blob truncated")

    enc_key = blob_bytes[2:2+L]
    nonce = blob_bytes[2+L:2+L+12]
    aes_ct = blob_bytes[2+L+12:]

    # RSA-decrypt AES key
    aes_key = self_private_key.decrypt(
        enc_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, aes_ct, None)
    return plaintext



# 1. Generate AES 256-bit key
def create_aes_key():
    return os.urandom(32)  # 32 bytes = 256 bits

# 2. Encrypt plaintext using AES-CBC
def encrypt_aes(plaintext, key):
    iv = os.urandom(16)  # AES block size is 16 bytes
    padder = sym_padding.PKCS7(128).padder()  # Block size for PKCS7 is 128 bits
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext  # prepend IV to ciphertext

# 3. Decrypt ciphertext using AES-CBC
def decrypt_aes(ciphertext_with_iv, key):
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()