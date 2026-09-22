"""A demo agent operator ("Acme Shopping Agent") publishing its key directory."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from kya_gateway.keys import WELL_KNOWN
from kya_gateway.signer import public_jwk

ACME_KEY = Ed25519PrivateKey.generate()

app = FastAPI(title="Acme agent key directory")


@app.get(WELL_KNOWN)
def directory():
    return JSONResponse({"keys": [public_jwk(ACME_KEY)]},
                        media_type="application/http-message-signatures-directory+json",
                        headers={"Cache-Control": "max-age=300"})
