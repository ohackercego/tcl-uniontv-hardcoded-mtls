# Advisory: Hard-coded mTLS client certificate & private key in TCL UnionTV firmware

**Discovered by:** [@ohackercego](https://github.com/ohackercego)
**Date:** 2026-11-03
**Device:** TCL UnionTV (Android TV) — chassis RT41 / R41KT01, SoC Realtek RTD2841
**Firmware:** R609 (`UpdateR609.img`), platform R41KT01, Android 9 (SDK 28)
**Severity:** High — CVSS 3.1 **7.4** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**CWE:** CWE-798, CWE-321, CWE-320
**CVE:** none assigned (unreported — vendor notification pending)

---

## Summary

The TCL UnionTV firmware ships a **shared X.509 client certificate and its unencrypted RSA-2048 private key**, plus a **hard-coded password**, used for **mutual-TLS client authentication** against third-party servers — including the **BBC iPlayer production gateway**.

Every unit in this product line carries the **same** credential, the private key is stored **in plaintext**, and the firmware is **publicly obtainable**. The certificate is valid until **2042** with no rotation. As a result, the client-certificate authentication provides no real protection: anyone who extracts the firmware obtains a working client credential.

## Affected file

```
/vendor/etc/tbrowser2/config/crt/client/client_cert_config.xml
```

```xml
<client_cert_config>
  <element>
    <host>securegate.iplayer.bbc.co.uk</host>
    <port>443</port>
    <type>PEM</type>
    <certificate>/system/tbrowser2/crt/client/www.tcl.com.cert_bag.pem</certificate>
    <key>/system/tbrowser2/crt/client/www.tcl.com.key.pem</key>
    <password>REDACTED</password>
  </element>
  <!-- additional hosts: ipsecure.stage/test/int.bbc.co.uk,
       b.digitaltv-labs-ssl-test.co.uk, fvp-auth.testing.digitaluk.co.uk,
       auth-ctv.uat.digitaluk.co.uk -->
</client_cert_config>
```

## Affected hosts (authentication targets)

| Host | Environment |
|---|---|
| `securegate.iplayer.bbc.co.uk` | **Production** (BBC iPlayer) |
| `ipsecure.stage.bbc.co.uk` | Staging |
| `ipsecure.test.bbc.co.uk` | Test |
| `ipsecure.int.bbc.co.uk` | Integration |
| `b.digitaltv-labs-ssl-test.co.uk` | Test |
| `fvp-auth.testing.digitaluk.co.uk` | Test (Freeview Play) |
| `auth-ctv.uat.digitaluk.co.uk` | UAT |

## Evidence

| Artifact | Path | SHA-256 |
|---|---|---|
| Client private key (RSA-2048, plaintext) | `/vendor/etc/tbrowser2/config/crt/client/www.tcl.com.key.pem` | `67ed210f07dd98af62a9494722373d4a70685fbafea3cb7f22999036d3b2095b` |
| Client certificate | `/vendor/etc/tbrowser2/config/crt/client/www.tcl.com.cert_bag.pem` | `5d5bbd18ec567f77cc6ca76a9d4f297baeadc3f862bd2834f228000b1cc8574e` |
| Additional private key | `/vendor/etc/tbrowser2/config/crt/privkey.pem` | `060bddb9db70dbf6d3e33f4e3bb5f7b18c433e96bf0e03e36b2364a4a9a74d7c` |
| Usage config | `/vendor/etc/tbrowser2/config/crt/client/client_cert_config.xml` | `05d563e54b8bebc20e96b48faf609620cda0c72574621c155a4daf06d9e856e6` |
| Firmware image | `UpdateR609.img` | `b7df72b38785c3541b51d522efe4a5f219169abaeda171dad9d5e97cce9a5ecd` |

Certificate details:

```
subject = C=FR, ST=France, L=Paris, O=TCL EUROPE, OU=TMT, CN=TCL CA Freeview
issuer  = (self-signed)
serial  = 1000
valid   = 2017-04-21 .. 2042-04-15
EKU     = TLS Web Client Authentication (critical)
SHA-256 = 71:A1:88:F3:43:FA:9F:A2:1F:53:0F:18:CB:00:9B:A3:FD:B2:2E:07:35:08:DB:00:54:94:39:D1:CC:B3:A9:2B
```

Key/certificate pair verified (identical RSA modulus); private key is **not** encrypted.

## Impact

- The mTLS client authentication no longer proves device identity.
- A single extracted secret is valid across the **entire affected product line** (global, not per-device).
- Enables impersonation of a legitimate TCL client toward the listed third-party gateways.
- No server-side fix is possible without revoking the certificate (valid to 2042).

## Reproduction

1. Obtain the R41KT01 platform firmware image (public sources).
2. Extract `system` / `vendor` partitions; locate `/vendor/etc/tbrowser2/config/crt/client/`.
3. Read `client_cert_config.xml`, `www.tcl.com.cert_bag.pem`, `www.tcl.com.key.pem`.
4. Confirm the pair:
   ```sh
   openssl rsa  -in www.tcl.com.key.pem     -noout -modulus | openssl md5
   openssl x509 -in www.tcl.com.cert_bag.pem -noout -modulus | openssl md5   # identical
   openssl rsa  -in www.tcl.com.key.pem     -noout -check                    # RSA key ok
   openssl x509 -in www.tcl.com.cert_bag.pem -noout -subject -ext extendedKeyUsage
   ```

## Remediation

**Vendor (TCL):** remove the private key from firmware; migrate to **per-device** credentials provisioned in manufacturing; **rotate and revoke** the current certificate at the CA; stop embedding global critical security parameters in images (ETSI EN 303 645 §5.4-4).

**End users:** keep the TV on a trusted LAN only; disable UPnP on the router; segment IoT/TV devices; do not expose the device to the internet; treat the TV as untrusted on the network.

## Proof of Concept

[`poc/poc_extract_mtls_creds.py`](poc/poc_extract_mtls_creds.py) locates the
credential files inside a firmware image (or an extracted `vendor/` tree),
extracts the certificate and private key, and proves that the key **pairs with
the certificate** and is **not encrypted**.

```sh
# straight from an OTA image
python3 poc/poc_extract_mtls_creds.py --image UpdateR609.img

# or from an extracted vendor partition
python3 poc/poc_extract_mtls_creds.py --vendor ./vendor_x
```

Expected output includes:

```
[+] hard-coded password entry present in config : True
[+] authentication targets (7):
      securegate.iplayer.bbc.co.uk  <-- PRODUCTION
      ...
[+] private key encrypted                      : False  (False = plaintext)
[+] KEY PAIRS WITH CERTIFICATE                 : True
 RESULT: VULNERABLE — shared plaintext mTLS client credential shipped in firmware.
```

The PoC ships **no key material**; it operates on a firmware image you provide.

## Vendor notification

- **2026-11-03** — reported to the vendor (TCL) through its security contact.
- Status at time of publication: **no response received**.

## Disclosure

Reported to the vendor and coordinated through a CNA. This repository is the public advisory required for submission.

## License

MIT — see [LICENSE](LICENSE).
