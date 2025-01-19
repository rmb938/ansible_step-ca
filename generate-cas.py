#!/usr/bin/env python3

from yubikit.piv import (
    PivSession,
    SLOT,
    DEFAULT_MANAGEMENT_KEY,
)
from ykman import scripting as s

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import ec
from yubikit.core.smartcard import ApduError

import datetime
import click


def generate_root_certificate() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    print("Generating Root Private Key")
    private_key = ec.generate_private_key(ec.SECP384R1())

    now = datetime.datetime.now()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Home Lab Root CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Home Lab"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Step CA"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .issuer_name(subject)  # Same as subject since this is self-signed
        .subject_name(subject)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=(365 * 20)))  # 20 year validity
        .serial_number(x509.random_serial_number())
        .public_key(private_key.public_key())
        # Some examples of extensions to add, many more are possible:
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
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
    )

    print("Creating Root CA certificate")
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA384(),
    )

    return certificate, private_key


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
            x509.BasicConstraints(ca=True, path_length=None),
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
    certificate: x509.Certificate,
    private_key: ec.EllipticCurvePrivateKey,
):
    # Slot 82
    slot = SLOT.RETIRED1

    # Establish PIV session
    piv = PivSession(yubikey.smart_card())

    # Check if a key is already stored, if so error
    try:
        piv.get_slot_metadata(slot)
        print(f"Key already exists in slot {slot}.")
        exit(1)
    except ApduError as e:
        pass

    # Unlock with the management key
    # key = click.prompt(
    #     "Enter management key", default=DEFAULT_MANAGEMENT_KEY.hex(), hide_input=True
    # )
    piv.authenticate(bytes.fromhex(DEFAULT_MANAGEMENT_KEY.hex()))

    # Put the key and certificate
    print("Writting private key and public certificate")
    piv.put_key(slot, private_key)
    piv.put_certificate(slot, certificate)


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
    root_certificate, root_private_key = generate_root_certificate()

    # Connect to yubikey
    print("Connecting to Yubikey")
    yubikey = s.single()
    serials = [yubikey.info.serial]
    print(f"Connected to Yubikey with Serial {yubikey.info.serial}")

    write_keys(yubikey, root_certificate, root_private_key)

    print("Backing up root to another Yubikey")
    yubikey, serials = next_yubikey(serials)

    write_keys(yubikey, root_certificate, root_private_key)

    intermediate_certificate, intermediate_private_key = (
        generate_intermediate_certificate(root_certificate, root_private_key)
    )

    yubikey, serials = next_yubikey(serials)

    write_keys(yubikey, intermediate_certificate, intermediate_private_key)


main()
