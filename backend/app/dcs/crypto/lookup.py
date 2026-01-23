import hmac
import hashlib

def normalize_external_id(external_id: str) -> str:
    return external_id.strip().upper()

def hmac_lookup(pepper: bytes, value: str) -> bytes:
    return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).digest()
