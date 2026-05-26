"""
crypto.py — криптографические примитивы.
- RSA-OAEP-SHA256 для обмена ключами
- RSA-PSS-SHA256 для подписи файлов
- AES-256-GCM для шифрования файлов
- Шифрование приватного ключа паролем (BestAvailableEncryption)
"""

import os
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── RSA ──────────────────────────────────────────────────────────────────────

def generate_rsa():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def serialize_public(pub) -> str:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def serialize_private(priv, password: bytes | None = None) -> bytes:
    """
    Сериализует приватный ключ.
    Если password задан — шифрует с BestAvailableEncryption (AES-256-CBC + PBKDF2).
    Если password=None — сохраняет без шифрования (не рекомендуется).
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def load_private(pem: bytes, password: bytes | None = None):
    """
    Загружает приватный ключ.
    password — байты пароля или None для незашифрованного ключа.
    Выбрасывает ValueError при неверном пароле.
    """
    return serialization.load_pem_private_key(pem, password=password)


def rsa_encrypt(pub, data: bytes) -> bytes:
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(priv, data: bytes) -> bytes:
    return priv.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ── RSA-PSS ───────────────────────────────────────────────────────────────────

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def sign_data(priv, data: bytes) -> bytes:
    return priv.sign(data, _PSS_PADDING, hashes.SHA256())


def verify_signature(pub, data: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, data, _PSS_PADDING, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def generate_session_key() -> bytes:
    return os.urandom(32)


def encrypt_file(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ct


def decrypt_file(data: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ── Бинарный пакет ────────────────────────────────────────────────────────────
def pack_bundle(enc_key: bytes, signature: bytes, encrypted: bytes, filename: str = "") -> bytes:
    fname_bytes = filename.encode("utf-8")
    return (
        struct.pack(">I", len(enc_key)) + enc_key
        + struct.pack(">I", len(signature)) + signature
        + struct.pack(">I", len(fname_bytes)) + fname_bytes
        + encrypted
    )


def unpack_bundle(bundle: bytes):
    offset = 0

    enc_key_len = int.from_bytes(bundle[offset:offset + 4], 'big')
    offset += 4
    enc_key = bundle[offset:offset + enc_key_len]
    offset += enc_key_len

    sig_len = int.from_bytes(bundle[offset:offset + 4], 'big')
    offset += 4
    signature = bundle[offset:offset + sig_len]
    offset += sig_len

    fname_len = int.from_bytes(bundle[offset:offset + 4], 'big')
    offset += 4
    filename = bundle[offset:offset + fname_len].decode("utf-8")
    offset += fname_len

    encrypted = bundle[offset:]

    return enc_key, signature, encrypted, filename

