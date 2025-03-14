#!/usr/bin/env python3

import datetime

import click
import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import _serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from ykman import scripting as s
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import DEFAULT_USER_PIN
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, SLOT, PivSession

libykcs11_locations = [
    "/usr/lib64/libykcs11.so.2",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so.2",
    "/usr/lib/aarch64-linux-gnu/libykcs11.so.2",
]


class YubiKeyECPrivateKey(ec.EllipticCurvePrivateKey):
    def __init__(self, serial: int, pin: str):
        self._pkcs11_lib = PyKCS11.PyKCS11Lib()

        lib_found = False
        for libykcs11_location in libykcs11_locations:
            print(f"Trying to load {libykcs11_location}")
            try:
                self._pkcs11_lib.load(libykcs11_location)
                lib_found = True
                print(f"Loaded {libykcs11_location}")
                break
            except PyKCS11.PyKCS11Error:
                continue

        if not lib_found:
            raise Exception("could not find libykcs11.so.2")

        for slot in self._pkcs11_lib.getSlotList(tokenPresent=True):
            token_info = self._pkcs11_lib.getTokenInfo(slot)
            if int(token_info.serialNumber) == serial:
                self._pkcs11_slot = slot
                break

        self._session = self._pkcs11_lib.openSession(
            self._pkcs11_slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self._session.login(pin)

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
        objs = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_LABEL, "X.509 Certificate for Retired Key 1"),
            ]
        )
        ca_cert_handle = objs[0]

        attributes = self._session.getAttributeValue(
            ca_cert_handle, [PyKCS11.CKA_VALUE], True
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
        objs = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_LABEL, "Private key for Retired Key 1"),
            ]
        )
        ca_private_key_handle = objs[0]

        signature = self._session.sign(
            ca_private_key_handle,
            data,
            PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA384),
        )

        key_size_bytes = (
            self.key_size // 8
        )  # Calculate key size in bytes (384 // 8 = 48)

        r = int.from_bytes(signature[:key_size_bytes], byteorder="big")
        s = int.from_bytes(signature[key_size_bytes:], byteorder="big")

        return utils.encode_dss_signature(r, s)

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()


def generate_intermediate_certificate(
    root_certificate: x509.Certificate,
    root_private_key: ec.EllipticCurvePrivateKey,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    print("Generating Intermediate Private Key")
    private_key = ec.generate_private_key(ec.SECP384R1())

    now = datetime.datetime.now()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Home Lab Intermediate CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Home Lab"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Step CA"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .issuer_name(root_certificate.subject)
        .subject_name(subject)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=(365 * 3)))  # 3 year validity
        .serial_number(x509.random_serial_number())
        .public_key(private_key.public_key())
        # Some examples of extensions to add, many more are possible:
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
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
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.DNSName(".rmb938.me"),
                    x509.DNSName(".tailnet-047c.ts.net"),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_certificate.public_key()
            ),
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
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "http://hl-us-homelab1-step-ca.tailnet-047c.ts.net/1.0/crl"
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

    print("Creating Intermediate CA certificate")
    certificate = builder.sign(
        private_key=root_private_key,
        algorithm=hashes.SHA384(),
    )

    return certificate, private_key


def write_keys(
    yubikey: s.ScriptingDevice,
    root_certificate: x509.Certificate,
    certificate: x509.Certificate,
    private_key: ec.EllipticCurvePrivateKey,
    pin: str,
):
    # Slot 82
    slot = SLOT.RETIRED1

    root_slot = SLOT.RETIRED2

    # Establish PIV session
    piv = PivSession(yubikey.smart_card())

    # Check if a key is already stored, if so error
    try:
        piv.get_slot_metadata(slot)
        print(f"Key already exists in slot {slot}.")
        exit(1)
    except ApduError as e:
        pass

    piv.authenticate(
        key_type=MANAGEMENT_KEY_TYPE.AES256, management_key=bytes.fromhex(pin)
    )

    # Put the key and certificate
    print("Writting private key and public certificate")
    piv.put_key(slot, private_key)
    piv.put_certificate(slot, certificate)
    piv.put_certificate(root_slot, root_certificate)


def next_yubikey(serials: list[int]) -> tuple[s.ScriptingDevice, list[int]]:
    while True:
        click.echo("Remove Yubikey and insert another, press enter to continue...")
        input()
        print("Connecting to new Yubikey")
        yubikey = s.single()
        print(f"Connected to Yubikey with Serial {yubikey.info.serial}")

        # Serial is different so we have a different one inserted
        if yubikey.info.serial not in serials:
            serials.append(yubikey.info.serial)
            break

        # Serial is the same to log and continue
        click.echo("The same yubikey was inserted, please insert a different one.")

    return yubikey, serials


def main():
    print("Connecting to Root Yubikey")
    yubikey = s.single()
    serials = [yubikey.info.serial]
    print(f"Connected to Root Yubikey with Serial {yubikey.info.serial}")

    # Unlock with the user pin
    root_user_pin = click.prompt(
        "Enter user pin", default=DEFAULT_USER_PIN, hide_input=True
    )
    ybi_key = YubiKeyECPrivateKey(yubikey.info.serial, root_user_pin)

    intermediate_certificate, intermediate_private_key = (
        generate_intermediate_certificate(ybi_key.certificate, ybi_key)
    )

    yubikey, serials = next_yubikey(serials)
    piv = PivSession(yubikey.smart_card())

    # Unlock with the management key
    while True:
        try:
            intermediate_management_pin = click.prompt(
                "Enter management key",
                default=DEFAULT_MANAGEMENT_KEY.hex(),
                hide_input=True,
            )
            piv.authenticate(
                key_type=MANAGEMENT_KEY_TYPE.AES256,
                management_key=bytes.fromhex(intermediate_management_pin),
            )
            break
        except (ApduError, ValueError):
            print("Invalid Management Key, try again.")
    write_keys(
        yubikey,
        ybi_key.certificate,
        intermediate_certificate,
        intermediate_private_key,
        intermediate_management_pin,
    )


if __name__ == "__main__":
    main()
