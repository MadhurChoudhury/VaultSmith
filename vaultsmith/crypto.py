# vaultsmith/crypto.py
import os
import json
import base64
from dataclasses import dataclass
from typing import Dict, Any

from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------- Helper functions ----------
def b64u(b: bytes) -> str:
    """Base64 encode bytes → string"""
    return base64.b64encode(b).decode("ascii")

def ub64(s: str) -> bytes:
    """Base64 decode string → bytes"""
    return base64.b64decode(s.encode("ascii"))


# ---------- Argon2id Key Derivation ----------
@dataclass
class KDFParams:
    time_cost: int = 3        # number of iterations
    memory_kib: int = 65536   # memory cost (64 MB)
    parallelism: int = 1
    salt_len: int = 16        # salt length in bytes

def derive_key(password: str, salt: bytes, params: KDFParams, key_len: int = 32) -> bytes:
    """
    Derive a symmetric key from password using Argon2id.
    - password: string (user input)
    - salt: bytes (unique random per vault)
    - returns: derived key (bytes)
    """
    pwd = password.encode("utf-8")
    key = low_level.hash_secret_raw(
        secret=pwd,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=key_len,
        type=low_level.Type.ID,  # Argon2id variant
    )
    return key


# ---------- AES-GCM Encryption ----------
def seal(plaintext: bytes, key: bytes, aad: bytes = b"") -> Dict[str, bytes]:
    """
    Encrypt and authenticate plaintext with AES-GCM.
    Returns dict with nonce and ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit random nonce
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {"nonce": nonce, "ciphertext": ct}

def open_sealed(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt and verify AES-GCM ciphertext.
    Raises exception if authentication fails.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ---------- Vault Envelope ----------
def create_vault_envelope(password: str, plaintext_blob: bytes, kdf_params: KDFParams = None) -> str:
    """
    Encrypt plaintext_blob and wrap metadata into a JSON envelope.
    """
    if kdf_params is None:
        kdf_params = KDFParams()

    salt = os.urandom(kdf_params.salt_len)
    key = derive_key(password, salt, kdf_params, key_len=32)
    sealed = seal(plaintext_blob, key, aad=b"vault-v1")

    envelope = {
        "version": 1,
        "kdf": {
            "name": "argon2id",
            "time_cost": kdf_params.time_cost,
            "memory_kib": kdf_params.memory_kib,
            "parallelism": kdf_params.parallelism,
            "salt": b64u(salt),
        },
        "aead": "AES-256-GCM",
        "nonce": b64u(sealed["nonce"]),
        "ciphertext": b64u(sealed["ciphertext"]),
    }

    return json.dumps(envelope, indent=2)

def open_vault_envelope(password: str, envelope_json: str) -> bytes:
    """
    Decrypt an encrypted vault JSON envelope and return the plaintext blob.
    """
    env = json.loads(envelope_json)
    if env.get("kdf", {}).get("name") != "argon2id":
        raise ValueError("Unsupported KDF type")

    kdf = env["kdf"]
    salt = ub64(kdf["salt"])
    params = KDFParams(
        time_cost=kdf["time_cost"],
        memory_kib=kdf["memory_kib"],
        parallelism=kdf["parallelism"],
        salt_len=len(salt)
    )

    key = derive_key(password, salt, params, key_len=32)
    nonce = ub64(env["nonce"])
    ciphertext = ub64(env["ciphertext"])

    return open_sealed(nonce, ciphertext, key, aad=b"vault-v1")
