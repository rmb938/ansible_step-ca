import datetime

import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import _serialization, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class YubiKeyECPrivateKey(ec.EllipticCurvePrivateKey):
    def __init__(self):
        self._pkcs11_lib = PyKCS11.PyKCS11Lib()
        self._pkcs11_lib.load("/usr/lib64/libykcs11.so.2")

    def exchange(
        self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        raise NotImplementedError()

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """
        The EllipticCurvePublicKey for this private key.
        """
        return self.certificate.public_key()

    @property
    def certificate(self) -> x509.Certificate:
        slot = self._pkcs11_lib.getSlotList(tokenPresent=True)[0]

        session = self._pkcs11_lib.openSession(
            slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )

        objs = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_LABEL, "X.509 Certificate for Retired Key 1"),
            ]
        )
        ca_public_key_handle = objs[0]

        attributes = session.getAttributeValue(
            ca_public_key_handle,
            [PyKCS11.CKA_VALUE],
        )

        return x509.load_der_x509_certificate(bytes(attributes[0]))

    @property
    def curve(self) -> ec.EllipticCurve:
        """
        The EllipticCurve that this key is on.
        """
        return self.public_key().curve

    @property
    def key_size(self) -> int:
        return self.public_key().key_size

    def sign(
        self,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        # TODO: what to do with signature_algorithm

        slot = self._pkcs11_lib.getSlotList(tokenPresent=True)[0]

        session = self._pkcs11_lib.openSession(
            slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        session.login("123456")

        objs = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL, "Private key for Retired Key 1"),
            ]
        )
        ca_private_key_handle = objs[0]

        return bytes(
            session.sign(
                ca_private_key_handle, data, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA384)
            )
        )

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()


def main():
    # TODO: take pins as input
    # TODO: take object id labels as input, see "Key Alias per Slot and Object Type"
    #   here https://developers.yubico.com/yubico-piv-tool/YKCS11/Functions_and_values.html
    ybi_key = YubiKeyECPrivateKey()

    private_key = ec.generate_private_key(ec.SECP384R1())

    print(ybi_key.public_key())
    print(ybi_key.curve)
    print(ybi_key.key_size)

    now = datetime.datetime.now()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "YubiKey Cert"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Home Lab"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Step CA"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .issuer_name(ybi_key.certificate.subject)
        .subject_name(subject)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=(365 * 3)))  # 3 year validity
        .serial_number(x509.random_serial_number())
        .public_key(private_key.public_key())
        # Some examples of extensions to add, many more are possible:
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ybi_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "http://step-ca.us-homelab1.hl.rmb938.me/1.0/crl"
                            ),
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    ),
                ]
            ),
            critical=False,
        )
    )

    certificate = builder.sign(private_key=ybi_key, algorithm=hashes.SHA384())
    print(certificate.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"))


main()
