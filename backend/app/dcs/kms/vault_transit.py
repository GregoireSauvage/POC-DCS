import base64
import requests
from app.core.config import settings

class VaultClient:
    def __init__(self):
        self.addr = settings.VAULT_ADDR.rstrip("/")
        self.token = settings.VAULT_TOKEN
        self.transit_key = settings.VAULT_TRANSIT_KEY
        self.kv_path = settings.VAULT_KV_PEPPER_PATH

    def _headers(self):
        return {"X-Vault-Token": self.token}

    def encrypt(self, plaintext: str) -> str:
        b64 = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        url = f"{self.addr}/v1/transit/encrypt/{self.transit_key}"
        r = requests.post(url, headers=self._headers(), json={"plaintext": b64}, timeout=5)
        r.raise_for_status()
        return r.json()["data"]["ciphertext"]

    def decrypt(self, ciphertext: str) -> str:
        url = f"{self.addr}/v1/transit/decrypt/{self.transit_key}"
        r = requests.post(url, headers=self._headers(), json={"ciphertext": ciphertext}, timeout=5)
        r.raise_for_status()
        b64 = r.json()["data"]["plaintext"]
        return base64.b64decode(b64).decode("utf-8")

    def get_pepper(self) -> bytes:
        # KV v2 read: /v1/secret/data/<path>
        path = self.kv_path.strip("/")
        if path.startswith("secret/"):
            sub = path[len("secret/"):]
            url = f"{self.addr}/v1/secret/data/{sub}"
        else:
            url = f"{self.addr}/v1/{path}"
        r = requests.get(url, headers=self._headers(), timeout=5)
        r.raise_for_status()
        pepper = r.json()["data"]["data"]["pepper"]
        return pepper.encode("utf-8")
