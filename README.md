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

* Update Packages
    ```bash
    sudo apt update
    sudo apt upgrade
    sudo reboot
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
    sudo reboot
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

1. List the key slots `sudo cryptsetup luksDump /dev/sda3`
1. Remove the slot that is dead `sudo cryptsetup -v luksKillSlot /dev/sda3 ${SLOT_NUM}`
    * **Important:** Read the output before entering your password to make sure you selected the correct one.
1. Follow the above [Full Disk Encryption via USB Key](#full-disk-encryption-via-usb-key) steps to create a new key on a new USB drive.

### Root & Intermediate Generation

Need 3 yubikeys total, 2 for the roots (one as a backup) and one for the intermediate

#### Generate Certificates

1. Install the required packages
    ```bash
    sudo apt install yubikey-manager pwgen ykcs11 pkcs11-provider python3-pykcs11
    ```
1. Copy the `generate-root.py` and `generate-intermediate.py` scripts to the server
    ```bash
    scp generate-root.py ubuntu@step-ca.us-homelab1.hl.rmb938.me:/home/ubuntu/
    scp generate-intermediate.py ubuntu@step-ca.us-homelab1.hl.rmb938.me:/home/ubuntu/
    ```
1. Disconnect the server from the network

##### Root Certificate

1. Change the management, user pins, and PUK pins.
    ```bash
    # Generate and change PIN
    pwgen -s -B -v -r abcdefghijklmnopqrstuvwxyz -A 8 1
    ykman piv access change-pin

    # Generate and change Management Key
    ykman piv access change-management-key -g -a AES256

    # Generate and change PUK
    pwgen -s -B -v -n 8 1
    ykman piv access change-puk
    ```
1. Write the management, user pins, and PUK pins down and keep them in a safe place
1. Generate the root
    ```bash
    /usr/bin/python3 generate-root.py
    ```
1. Unplug Yubikeys and reboot to clear any memory of the keys
1. Keep the Root Yubikeys and Pins in a safe place

##### Intermediate Certificate

1. Create `step` user and home directory
    ```bash
    useradd --user-group --system --home /etc/step-ca --shell /bin/false step
    mkdir -p /etc/step-ca
    chown -R step:step /etc/step-ca
    ```
1. Change the management, user, and PUK PINs, store them on the filesystem for Step CA
    ```bash
    mkdir -p /etc/step-ca/yubikey/
    # Generate and change PIN
    ykman piv access change-pin -P 123456 -n $(pwgen -s -B -v -r abcdefghijklmnopqrstuvwxyz -A 8 1 | tee /etc/step-ca/yubikey/pin)
    chmod 0400 /etc/step-ca/yubikey/pin

    # Generate and change Management Key
    ykman piv access change-management-key -a AES256 -m 010203040506070801020304050607080102030405060708 -n $(openssl rand -hex 32 | tee /etc/step-ca/yubikey/management-key)
    chmod 0400 /etc/step-ca/yubikey/management-key

    # Generate and change PUK
    ykman piv access change-puk -p 12345678 -n $(pwgen -s -B -v -n 8 1 | tee /etc/step-ca/yubikey/puk)
    chmod 0400 /etc/step-ca/yubikey/puk
    ```
1. Insert one of the Yubikeys with the root keys
1. Generate the intermediate
    ```bash
    /usr/bin/python3 generate-intermediate.py
    ```
1. Unplug Root Yubikey and reboot to clear any memory of the keys
1. Put the root Yubikey back in a safe place
1. Plug the system back into the network

### Yubikey Lost/Corrupted

#### Root

If your root Yubikey is lost, consider your PKI compromised, you'll need to secure your environment start over.

If your root Yubikey is corrupted you cannot copy your keys from your backup to another Yubikey due to how they work. If you are using a HSM you may be able to clone it.

You will want to generate a new Root and intermediate then cross-sign the new intermediate with your old Root. Then deploy the cross-signed intermediate to your PKI infra 
until you can distribute the new Root public keys to all users. Once the new Root is distributed, update your PKI infra to use the non-cross signed intermediate.

TODO: create guide for cross signing, updating step-ca, ect...

#### Intermediate

If your intermediate is lost or corrupted simply following [Intermediate Certificate](#intermediate-certificate) steps to generate a new intermediate and rerun this ansible.

You will also want to update your CRL to revoke the current intermediate if it was lost.
    ```bash
    TODO:
    ```
