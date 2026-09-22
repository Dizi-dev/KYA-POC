"""A demo agent operator ("Acme Shopping Agent") publishing its key directory."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from kya_gateway.keys import WELL_KNOWN
from kya_gateway.signer import public_jwk

ACME_KEY = Ed25519PrivateKey.generate()
ACME_NEW_KEY = Ed25519PrivateKey.generate()   # published during the key-rotation scenario
PUBLISHED = [ACME_KEY]                        # the demo edits this list to rotate keys
# Short cache lifetime so the rotation scenario can show a removed key expiring (D9).
CACHE_CONTROL = "max-age=2"

app = FastAPI(title="Acme agent key directory")


@app.get(WELL_KNOWN)
def directory():
    return JSONResponse({"keys": [public_jwk(k) for k in PUBLISHED]},
                        media_type="application/http-message-signatures-directory+json",
                        headers={"Cache-Control": CACHE_CONTROL})
