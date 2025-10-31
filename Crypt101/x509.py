from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64

# Base64 본문을 붙여넣으면 된다
b64_data = """MIIDazCCAlMCFEJ7F1+RDOTCP2V6sewx72z+i4DNMA0GCSqGSIb3DQEBCwUAMHIx
CzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTZW91bDEQMA4GA1UEBwwHR2FuZ25hbTES
MBAGA1UECgwJQXV0b2NyeXB0MQwwCgYDVQQLDANWVFIxHzAdBgNVBAMMFmZsYWd7
eDUwOV9jM3JUaWZpYzR0RX0wHhcNMjUxMDMwMDMyMDM3WhcNMjYxMDMwMDMyMDM3
WjByMQswCQYDVQQGEwJLUjEOMAwGA1UECAwFU2VvdWwxEDAOBgNVBAcMB0dhbmdu
YW0xEjAQBgNVBAoMCUF1dG9jcnlwdDEMMAoGA1UECwwDVlRSMR8wHQYDVQQDDBZm
bGFne3g1MDlfYzNyVGlmaWM0dEV9MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAzdNM6zhNK+3mPn9RRkSO/BW4XiQx1XRcpmtuaOPO/3g5pq0Qq/OiI/Fg
WKlDpwEc3e31WvcIcVK9unS5cT4RWFByAU/75gyUr44gsn2FVKDRFa3ewykocySo
Y0pXXEytnvSQqezincequZVo/pURD+BVxaQCQqD5QaZy4qmi1o6Jj+jch0b7TzzG
fELdtL9vW35YVQRb1nJEvVTm8UVrI65nF8qod6whiSKcNy+riF8gHwn1IPj/+qq2
owYCaQ6iJMAnlmmaGjxLFBjg3eUgN64rXpTk1QqS1WMgaJIxl50JIrVidHDNat3e
SVF/P9g7toTaFBuKN20KnYD+0/3O6QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAS
eaQpaU7C3UF6YNuAj8elCbSuw0blIpwsngv3tdEVEqip4mLjiSUZjtNpleHIe/p4
qNqnMYRZNUkyKeaaYJtAAXasxXeTj5v0giTrVDaL2R2CbnFBVCQhypZFwz/5zYcf
76kssLass6YKRcOvjyJbTxSW0iVnm0SMF7uWEExjdCQaZvnHgTYX70/lP9/wr+6Y
XpcISs542mfa54FDFt5lctGT4Rm8013oJzLRYQpqkip03Bo7qvaCrbAIsm9Y/HPE
KBZz20StySHacfVoN6sgSZpjJ0kTsor4dtfPqwjPn1xFugETpYZnCowNYFAp9Yoq
PWJWm+pVAF1YIuW54+sz"""

# DER 디코딩 & 인증서 로드
der = base64.b64decode("".join(b64_data.splitlines()))
cert = x509.load_der_x509_certificate(der)  # default_backend() 불필요 (신규 버전)

print("==== Basic Info ====")
print("Version:", cert.version.name)
print("Serial Number:", cert.serial_number)
# 해시 알고리즘 이름 (예: sha256)
print("Signature Hash:", cert.signature_hash_algorithm.name)

print("\n==== Validity ====")
print("Not Before:", cert.not_valid_before)
print("Not After :", cert.not_valid_after)

print("\n==== Subject ====")
for attr in cert.subject:
    print(f"{attr.oid._name}: {attr.value}")

print("\n==== Issuer ====")
for attr in cert.issuer:
    print(f"{attr.oid._name}: {attr.value}")

print("\n==== Public Key (PEM) ====")
pubkey = cert.public_key()
pem = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
print(pem.decode())
