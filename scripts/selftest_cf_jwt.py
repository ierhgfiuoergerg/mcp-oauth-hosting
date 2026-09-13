#!/usr/bin/env python3
"""selftest_cf_jwt.py — prove the server really verifies Cloudflare Access identities.

No Cloudflare account needed: a local RSA keypair stubs the team's JWKS, so the test
runs entirely offline. What it checks is that the *signature* decides, not the header:

  valid JWT            -> identity returned
  no header            -> None
  tampered signature   -> None
  signed by another key-> None
  unknown kid          -> None
  expired              -> None
  wrong issuer         -> None
  wrong audience       -> None (when MCP_CF_ACCESS_AUD is set)
  team not configured  -> None (mechanism inert)

Usage: <venv>/bin/python scripts/selftest_cf_jwt.py [repo_dir]
Needs pyjwt + cryptography. Exit code 0 iff everything passes.
"""
import json
import os
import sys
import time

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

import oauth_shim  # noqa: E402

TEAM = "selftest.cloudflareaccess.com"
AUD = "selftest-aud-tag"


def keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.PKCS8,
                             encryption_algorithm=serialization.NoEncryption()).decode()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update({"kid": "selftest-kid", "use": "sig", "alg": "RS256"})
    return pem, jwk


GOOD_PEM, GOOD_JWK = keypair()
BAD_PEM, _ = keypair()


class Req:
    def __init__(self, headers):
        self.headers = headers


def token(pem=GOOD_PEM, kid="selftest-kid", iss=f"https://{TEAM}", exp_delta=3600,
          email="user@example.com", aud=AUD):
    now = int(time.time())
    claims = {"email": email, "sub": "sub-123", "iss": iss, "iat": now, "exp": now + exp_delta}
    if aud:
        claims["aud"] = aud
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def hdr(tok):
    return {"cf-access-jwt-assertion": tok}


def main():
    oauth_shim.CF_TEAM = TEAM
    oauth_shim.CF_AUD = AUD
    oauth_shim._cf_jwks = lambda: [GOOD_JWK]

    cases = [
        ("valid JWT -> identity", oauth_shim.cf_identity(Req(hdr(token()))), "user@example.com"),
        ("no header -> None", oauth_shim.cf_identity(Req({})), None),
    ]
    head, payload, sig = token().split(".")
    cases += [
        ("tampered signature -> None",
         oauth_shim.cf_identity(Req(hdr(f"{head}.{payload}.{sig[:-4]}AAAA"))), None),
        ("signed by another key -> None", oauth_shim.cf_identity(Req(hdr(token(pem=BAD_PEM)))), None),
        ("unknown kid -> None", oauth_shim.cf_identity(Req(hdr(token(kid="other-kid")))), None),
        ("expired -> None", oauth_shim.cf_identity(Req(hdr(token(exp_delta=-120)))), None),
        ("wrong issuer -> None",
         oauth_shim.cf_identity(Req(hdr(token(iss="https://evil.example.com")))), None),
        ("wrong audience -> None",
         oauth_shim.cf_identity(Req(hdr(token(aud="someone-elses-app")))), None),
    ]
    oauth_shim.CF_TEAM = ""
    cases.append(("team unset -> inert", oauth_shim.cf_identity(Req(hdr(token()))), None))

    bad = 0
    for name, got, want in cases:
        good = got == want
        bad += 0 if good else 1
        print(("  PASS " if good else "  FAIL ") + f"{name}  (got={got!r})")
    print(f"\n{len(cases) - bad}/{len(cases)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
