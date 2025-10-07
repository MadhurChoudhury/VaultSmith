# tests/test_crypto.py
import json
from vaultsmith.crypto import create_vault_envelope, open_vault_envelope

def test_roundtrip():
    password = "correct horse battery staple"
    data = {
        "created": "2025-10-04T00:00:00Z",
        "entries": [
            {"id": "1", "name": "Example", "username": "me", "password": "P@ssw0rd!", "notes": ""}
        ]
    }
    plaintext = json.dumps(data).encode("utf-8")

    envelope = create_vault_envelope(password, plaintext)
    recovered = open_vault_envelope(password, envelope)

    assert recovered == plaintext