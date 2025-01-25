#!/usr/bin/env python3

import datetime

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from ykman import scripting as s
from yubikit.core.smartcard import ApduError
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, SLOT, PivSession


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


def write_keys(
    yubikey: s.ScriptingDevice,
    certificate: x509.Certificate,
    private_key: ec.EllipticCurvePrivateKey,
    pin: str,
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

    piv.authenticate(
        key_type=MANAGEMENT_KEY_TYPE.AES192, management_key=bytes.fromhex(pin)
    )

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

    # Unlock with the management key
    root_management_pin = click.prompt(
        "Enter management key", default=DEFAULT_MANAGEMENT_KEY.hex(), hide_input=True
    )
    write_keys(yubikey, root_certificate, root_private_key, root_management_pin)

    print("Backing up root to another Yubikey")
    yubikey, serials = next_yubikey(serials)

    # Unlock with the management key
    root_management_pin = click.prompt(
        "Enter management key", default=DEFAULT_MANAGEMENT_KEY.hex(), hide_input=True
    )
    write_keys(yubikey, root_certificate, root_private_key, root_management_pin)


if __name__ == "__main__":
    main()
