from yubikit.piv import (
    PivSession,
    SLOT,
    KEY_TYPE,
    DEFAULT_MANAGEMENT_KEY,
)
from ykman import scripting as s

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import ec
from yubikit.core.smartcard import ApduError

import datetime
import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import CertificateSigningRequestBuilder
from cryptography.x509.extensions import Extension, SubjectAlternativeName, DNSName
from cryptography import x509
import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import binascii
from OpenSSL import crypto
import hashlib
from pyasn1.type import univ, char, namedtype, tag, useful
from pyasn1.codec.der import encoder, decoder


def main():
    pkcs11_lib = PyKCS11.PyKCS11Lib()
    pkcs11_lib.load("/usr/lib64/libykcs11.so.2")

    slot = pkcs11_lib.getSlotList(tokenPresent=True)[0]
    token = pkcs11_lib.getTokenInfo(slot)

    if token.label.strip() != "YubiKey PIV #30767293":
        print("could not find correct token")
        exit(1)

    session = pkcs11_lib.openSession(
        slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
    )
    session.login("123456")

    objs = session.findObjects(
        [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_ID, bytes.fromhex("05")),
        ]
    )
    ca_private_key_handle = objs[0]
    print(ca_private_key_handle)

    with open(
        "/var/home/rbelgrave/projects/github.com/rmb938/ansible_step-ca/ca.pem", "rb"
    ) as f:
        ca_cert = x509.load_der_x509_certificate(f.read(), default_backend())

    with open(
        "/var/home/rbelgrave/projects/github.com/rmb938/ansible_step-ca/leaf.csr", "rb"
    ) as f:
        csr = x509.load_pem_x509_csr(f.read())

    # Sign with cryptography
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )

    # Add Extensions
    # Subject Key Identifier
    subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
    builder = builder.add_extension(subject_key_identifier, critical=False)

    # Authority Key Identifier
    authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca_cert.public_key()
    )
    builder = builder.add_extension(authority_key_identifier, critical=False)

    # Add extensions from CSR (CRUCIAL FIX)
    # for ext in csr.extensions:
    #     builder = builder.add_extension(ext, ext.critical)

    # Use a dummy private key (can be None) for cryptography signing
    certificate = builder.sign(
        private_key=ec.generate_private_key(ec.SECP384R1(), default_backend()),
        algorithm=hashes.SHA384(),
        backend=default_backend(),
    )
    print(
        "TBS Certificate (Hex):",
        binascii.hexlify(certificate.tbs_certificate_bytes).decode(),
    )

    # Sign the certificate using PKCS#11
    tbs_bytes = certificate.tbs_certificate_bytes

    hashed_tbs = hashlib.sha384(tbs_bytes).digest()

    # Sign the certificate using PKCS#11
    tbs_bytes = certificate.tbs_certificate_bytes
    hashed_tbs = hashlib.sha384(tbs_bytes).digest()
    signature_der = bytes(
        session.sign(
            ca_private_key_handle, hashed_tbs, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)
        )
    )

    # Robust signature decoding and padding
    try:
        signature_asn1, _ = decoder.decode(signature_der, asn1Spec=univ.Sequence())
        r = int(signature_asn1[0])
        s = int(signature_asn1[1])

        # Get key size in bytes (for SECP384R1 this is 48)
        key_size_bytes = (csr.public_key().key_size + 7) // 8

        r_bytes = r.to_bytes(key_size_bytes, "big")  # Pad R
        s_bytes = s.to_bytes(key_size_bytes, "big")  # Pad S
        signature_bytes = r_bytes + s_bytes  # Concatenate padded values

    except Exception as e:
        print(
            f"Signature is not ASN.1 encoded (probably raw R/S). Padding raw signature."
        )
        key_size_bytes = (csr.public_key().key_size + 7) // 8
        if len(signature_der) != 2 * key_size_bytes:
            print(
                f"Signature length is incorrect. Expected {2 * key_size_bytes} bytes, got {len(signature_der)} bytes."
            )
            return
        signature_bytes = signature_der

    # Correctly create the BitString (CRUCIAL FIX - Using a different method)
    sig_value = univ.BitString(
        hexValue=binascii.hexlify(signature_bytes).decode()
    )  # No explicit tagging

    # Construct the full Certificate structure
    cert_data = univ.Sequence()
    cert_data.setComponentByPosition(
        0, decoder.decode(certificate.tbs_certificate_bytes)[0]
    )

    # Signature Algorithm (in Certificate - THIS WAS MISSING)
    sig_alg_cert = univ.Sequence()
    sig_alg_cert.setComponentByPosition(
        0, univ.ObjectIdentifier("1.2.840.10045.4.3.3")
    )  # ecdsa-with-SHA384
    sig_alg_cert.setComponentByPosition(1, univ.Null(""))
    cert_data.setComponentByPosition(1, sig_alg_cert)

    cert_data.setComponentByPosition(2, sig_value)  # No explicit tagging here

    signed_cert_der = encoder.encode(cert_data)

    # Convert DER to PEM
    cert = x509.load_der_x509_certificate(signed_cert_der, default_backend())
    signed_cert_pem = cert.public_bytes(Encoding.PEM)
    print(signed_cert_pem.decode("utf-8"))


main()
