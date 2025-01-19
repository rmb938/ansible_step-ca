# ansible_step-ca
Ansible to setup Step CA with a Yubikey + RA's to handle certificate requests.

Currently this runs a Raspberry Pi 4 4GB with [UEFI](https://github.com/pftf/RPi4)
and [Ubuntu Server for Arm - 24.04](https://ubuntu.com/download/server/arm) installed.

## Requirements

### Software

* Setup Passwordless Sudo
    ```bash
    echo "ubuntu ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/ubuntu
    ```

* Fix Hostname
    ```bash
    sudo hostnamectl hostname step-ca.us-homelab1.hl.rmb938.me
    sudo sed -i '/127.0.1.1 step-ca/d' /etc/hosts
    echo "127.0.1.1 step-ca.us-homelab1.hl.rmb938.me" | sudo tee -a /etc/hosts
    ```

* Tailscale installed and configured for ssh
    ```bash
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
    sudo apt-get update
    sudo apt-get install tailscale
    sudo tailscale up --hostname "$(hostname -f | awk -F"." '{print $3}')-$(hostname -f | awk -F"." '{print $2}')-$(hostname)" --ssh --advertise-tags "tag:servers,tag:cloud-$(hostname -f | awk -F"." '{print $3}')-region-$(hostname -f | awk -F"." '{print $2}'),tag:step-ca"
    ```

### Full Disk Encryption via USB Key

Make sure Ubuntu is installed with Full Disk Encryption with a password.

* Add a USB drive as an ecryption key for non-interactive boot
    ```bash
    export BOOT_PARTITION=/dev/sda3
    export USB_DEVICE=/dev/sdb

    # Format USB and generate key
    sudo sfdisk --delete ${USB_DEVICE}
    sudo wipefs -af ${USB_DEVICE}
    echo -e 'size=1G, type=L' | sudo sfdisk ${USB_DEVICE}
    sudo mkfs.ext4 ${USB_DEVICE}1
    sudo e2label ${USB_DEVICE}1 luksKey
    sudo mount ${USB_DEVICE}1 /mnt
    sudo openssl genrsa -out /mnt/keyfile 4096
    sudo chmod 0400 /mnt/keyfile
    sudo chown root:root /mnt/keyfile
    sudo tune2fs -O read-only ${USB_DEVICE}1

    # Add key to luks
    sudo cryptsetup luksAddKey ${BOOT_PARTITION} /mnt/keyfile

    # Setup crypttab for initramfs
    # Ubuntu Noble doesnt officially support dracut with systemd crypttab yet
    # Use manpage for Debian https://manpages.debian.org/testing/cryptsetup/crypttab.5.en.html
    # See: https://discourse.ubuntu.com/t/please-try-out-dracut/48975
    # Once dracut is supported switch to https://www.freedesktop.org/software/systemd/man/latest/crypttab.html
    # Keyscript passdev doesnt ask for a password, it will just retry forever
    # If the usb dies, see troubleshooting section
    echo "dm_crypt-0 UUID=$(blkid -o value ${BOOT_PARTITION} | head -n1) /dev/disk/by-label/luksKey:/keyfile:5 luks,discard,keyscript=passdev,initramfs" | sudo tee /etc/crypttab
    sudo update-initramfs -u

    # Disable systemd luks generate by adding luks.crypttab=no
    sudo sed -i -e 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="luks.crypttab=no"/g' /etc/default/grub
    sudo update-grub
    ```

#### Troubleshooting

If the USB key dies or for some reason the system is not able to decrypt use the following steps to get in manually.

If you see logs like the following, either the USB isn't plugged in, it's dead, or corrupted in some way.

```
Unable to stat /dev/disk/by-label/luksKey
Nothing to read on input.
```
or
```
cryptsetup failed, password or options?
```

1. Get to the grub boot menu during bootup and edit the boot option.
1. On the `linux` line at the end add `break`.
    * This will force a boot into the initramfs
1. Once in the initramfs manually decrypt the boot drive
    * `cryptsetup luksOpen /dev/sdb3 dm_crypt-0`
    * This command will ask for the password instead of using the USB key.
1. Run `vgchange -ay` to discover the LVM volumes.
1. Run `exit` to exit the initramfs and continue booting.

Once booted you can remove the old USB Key.

1. List the key slots `cryptsetup luksDump /dev/sda3`
1. Remove the slot that is dead `cryptsetup -v luksKillSlot /dev/sda3 ${SLOT_NUM}`
    * **Important:** Read the output before entering your password to make sure you selected the correct one.
1. Follow the above [Full Disk Encryption via USB Key](#full-disk-encryption-via-usb-key) steps to create a new key on a new USB drive.

### Root & Intermediate Generation

Need 3 yubikeys total, 2 for the roots (one as a backup) and one for the intermediate

#### Install Yubikey Manager

1. Install Step CLI
    ```bash
    sudo apt install yubikey-manager
    ```

#### Generate Certificates

The following steps should be performed while the computer is not plugged into a network. This minimizes any risk of key compromise.

TODO: yubikey can generate CA's directly on the device but need to do it via raw python.

Can use

`PKCS11_MODULE_PATH=/usr/lib64/libykcs11.so.2 /usr/bin/openssl x509 -req -in leaf.csr -CA ca.pem -CAkey "pkcs11:token=YubiKey PIV #30767293;id=%05;type=private" -engine pkcs11 -CAkeyform engine -CAcreateserial -out leaf.crt -days 365 -sha384`

to sign a CSR from a key on a yubikey. It works and can be used in Golang.

Cannot figure out how to do the above command it in python without subprocess. `sign-cert.py` creates a valid cert to use in openssl, but golang explodes trying to read it in. No idea what is wrong.