import { generateNonce, sign } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";
const KEY = { kty:"OKP", crv:"Ed25519", alg:"EdDSA", kid:"test-key-ed25519",
  d:"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU", x:"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" };
const url = process.argv[2]; const sa = process.argv[3];
const headers = sa ? { "Signature-Agent": sa } : {};
const request = new Request(url, { headers });
const now = new Date();
const f = await sign(request, { signer: await signerFromJWK(KEY), created: now,
  expires: new Date(now.getTime() + 60_000), nonce: generateNonce() });
console.log(JSON.stringify({ ...headers, "Signature": f.signature, "Signature-Input": f.signatureInput }));
