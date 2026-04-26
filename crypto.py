import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_ITERATIONS = 600_000
_KEY_LEN    = 32   # 256 bits
_NONCE_LEN  = 12   # 96 bits (GCM standard)


def derive_kek(password: str, salt: bytes) -> bytes:
    """Deriva Key Encryption Key a partir da senha. Nunca é armazenada."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_dek() -> bytes:
    return os.urandom(_KEY_LEN)


def wrap_dek(dek: bytes, kek: bytes) -> str:
    """Cifra a DEK com a KEK (AES-256-GCM). Retorna base64."""
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(kek).encrypt(nonce, dek, None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def unwrap_dek(wrapped_b64: str, kek: bytes) -> bytes:
    """Decifra a DEK com a KEK. Lança InvalidTag se a senha estiver errada."""
    raw          = base64.urlsafe_b64decode(wrapped_b64)
    nonce, ct    = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(kek).decrypt(nonce, ct, None)


def encrypt_field(plaintext: str, dek: bytes) -> str:
    """Cifra um valor de campo. Cada chamada gera um nonce único."""
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_field(ciphertext_b64: str, dek: bytes) -> str:
    raw       = base64.urlsafe_b64decode(ciphertext_b64)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(dek).decrypt(nonce, ct, None).decode("utf-8")
