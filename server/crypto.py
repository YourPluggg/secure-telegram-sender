"""
crypto.py — криптографические примитивы
- RSA-OAEP-SHA256 для обмена ключами
- RSA-PSS-SHA256 для подписи файлов (аутентификация отправителя)
- AES-256-GCM для шифрования файлов (с аутентификацией содержимого)
"""

import os
import struct

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# ── RSA ──────────────────────────────────────────────────────────────────────

def generate_rsa():
    """Генерирует RSA-2048 пару ключей."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()

def serialize_public(pub) -> str:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def serialize_private(priv) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())

def load_private(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

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

# ── RSA-PSS подпись ──────────────────────────────────────────────────────────

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)

def sign_data(priv, data: bytes) -> bytes:
    """
    Подписывает данные приватным ключом (RSA-PSS-SHA256).
    Возвращает подпись (256 байт для RSA-2048).
    """
    return priv.sign(data, _PSS_PADDING, hashes.SHA256())

def verify_signature(pub, data: bytes, signature: bytes) -> bool:
    """
    Проверяет подпись публичным ключом отправителя.
    Возвращает True если подпись верна, False если нет.
    """
    try:
        pub.verify(signature, data, _PSS_PADDING, hashes.SHA256())
        return True
    except InvalidSignature:
        return False

# ── AES-GCM ──────────────────────────────────────────────────────────────────

def generate_session_key() -> bytes:
    """32 байта (AES-256)."""
    return os.urandom(32)

def encrypt_file(data: bytes, key: bytes) -> bytes:
    """
    Шифрует данные AES-256-GCM.
    Формат вывода: [nonce 12 байт][зашифрованные данные + тег 16 байт]
    """
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ct

def decrypt_file(data: bytes, key: bytes) -> bytes:
    """
    Расшифровывает данные AES-256-GCM.
    Выбрасывает cryptography.exceptions.InvalidTag если данные повреждены.
    """
    nonce, ct = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ct, None)

# ── Сборка пакета ─────────────────────────────────────────────────────────────
#
# Формат бинарного пакета:
#   [4 байта: длина enc_key]  [enc_key]
#   [4 байта: длина signature][signature]
#   [остаток: encrypted data ]
#
# Подпись RSA-PSS вычисляется над зашифрованными данными (encrypt-then-sign),
# что исключает атаки на основе выбранного шифртекста.

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