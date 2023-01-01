# PocketBeagle Builder

This repo is dedicated to my build, install and configuration scripts for the
[RaspberryPi](https://www.raspberrypi.org).

You can use the `install.sh` (or `install-aarch64.sh` for Pi3-Pi4/PiZero2) script to install
and configure an ArchLinux install that contains:

- Auto DHCP for eth0
- Read-only Root
- BTRFS Cache partition

The install script requires a valid ArchLinux tar blob, which one of the following
can be used:

- [ARM7 (Pi1-Pi4/PiZero(W)/PiZero2)](http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-armv7-latest.tar.gz)
  - With curl: `curl -Lo ArchLinuxARM-rpi-armv7-latest.tar.gz http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-armv7-latest.tar.gz`
  - With wget: `wget http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-armv7-latest.tar.gz`
- [ARM7 (Pi3-Pi4/PiZero2)](http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-aarch64-latest.tar.gz)
  - With curl: `curl -Lo ArchLinuxARM-rpi-aarch64-latest.tar.gz http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-aarch64-latest.tar.gz`
  - With wget: `wget http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-aarch64-latest.tar.gz`

## Command Line Arguments

`sudo bash install.sh <tar> <disk> [source script]`

An example that should work "Out-Of-The-Box" would be:

**ARM7**

```shell
sudo bash install.sh ArchLinuxARM-rpi-armv7-latest.tar.gz /dev/mmcblk0
```

**AArch64**

```shell
sudo bash install.sh ArchLinuxARM-rpi-aarch64-latest.tar.gz /dev/mmcblk0
```

This example assumes the SD card you'd be using is at `/dev/mmcblk0`.

The last command line argument `[source script]` is a path to a script file that
is executed in the **Context of the PI (ARM7/AARCH64) before completion** which
allows you to install other programs, enable systemd units, etc. This optional
argument is ignored if the path suggested does not exist, or is not a file.

## Install Requirements

(on the computer you're using to install from):

- `qemu-arm-static` from "qemu-user-static" (ARM chroot)
- `lsof` from "lsof" (Process monitoring)
- `bsdtar` from "libarchive" (Extraction)
- `mkfs.ext4` from "e2fsprogs" (Formatting)
- `mkfs.vfat` from "dosfstools" (Formatting)
- `mkfs.btrfs` from "btrfs-progs" (Formatting)

## Building "config.sh"

The contents of "Config" directory are built using the `build-config.py` file with
the arguments:

```shell
python build-config.py ./Config ./config.sh
```

This will generate the configuration script from any changes made in the `Config`
folder. *(Requires `python3`)*

## AArch64 Notes

If you are installing for the Pi3-Pi4 or PiZero2, you may use the AArch64 install.
This script will detect if the install is AARCH64 and will update the filesystem
accordingly. **You are still required to used the correct tar image file**.
