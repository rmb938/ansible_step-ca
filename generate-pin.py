#!/usr/bin/env python3

import os
import secrets
import string
from typing import Optional

import click
from ykman import scripting as s
from yubikit.openpgp import DEFAULT_USER_PIN
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, PivSession


@click.command()
@click.option(
    "--user-pin-path",
    type=click.STRING,
    default=None,
    help="The path to save the user pin to",
)
def main(user_pin_path: Optional[str]):
    # Connect to yubikey
    print("Connecting to Yubikey")
    yubikey = s.single()
    print(f"Connected to Yubikey with Serial {yubikey.info.serial}")

    piv = PivSession(yubikey.smart_card())

    print(
        f"Authenticating with default management key of: {DEFAULT_MANAGEMENT_KEY.hex()}"
    )
    piv.authenticate(
        key_type=MANAGEMENT_KEY_TYPE.AES192, management_key=DEFAULT_MANAGEMENT_KEY
    )

    new_management_key = secrets.token_hex(32)
    print(f"Generated new management key: '{new_management_key}'")

    new_pin = "".join(secrets.choice(string.digits) for _ in range(8))
    print(f"Generated new user pin: '{new_pin}'")

    new_puk = "".join(secrets.choice(string.digits) for _ in range(8))
    print(f"Generated new puk: '{new_puk}'")

    piv.set_management_key(
        key_type=MANAGEMENT_KEY_TYPE.AES256,
        management_key=bytes.fromhex(new_management_key),
        require_touch=False,
    )
    print("Set new management key")

    piv.change_pin(
        old_pin=DEFAULT_USER_PIN,
        new_pin=new_pin,
    )
    print("Set new user pin")

    piv.change_puk(
        old_puk="12345678",  # there is no variable for this
        new_puk=new_puk,
    )
    print("Set new puk")

    if user_pin_path is not None:
        print(f"Saving user pin to file at path: '{user_pin_path}'")

        # Opening pin path with 0400 so only our user can read it.
        with os.fdopen(
            os.open(user_pin_path, os.O_CREAT | os.O_WRONLY, 0o400), "w"
        ) as f:
            f.write(new_pin)


if __name__ == "__main__":
    main()
