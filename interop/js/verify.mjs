import { verify } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";
const KEY = { kty:"OKP", crv:"Ed25519", alg:"EdDSA", kid:"test-key-ed25519", x:"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" };
const [url, hdrsJson] = [process.argv[2], process.argv[3]];
const req = new Request(url, { headers: JSON.parse(hdrsJson) });
const v = await verifierFromJWK(KEY);
try {
  await verify(req, { resolver: (c) => { if (c.keyid !== v.keyid) throw new Error("unknown key"); return v; },
                      validate: () => {} });
  console.log("CF_VERIFY_OK");
} catch (e) { console.log("CF_VERIFY_FAIL " + e.message); }
