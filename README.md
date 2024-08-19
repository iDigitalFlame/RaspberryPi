# RaspberryPi Builder

This repo is dedicated to my build, install and configuration scripts for the
[RaspberryPi](https://www.raspberrypi.org).

You can use the `install.sh` script to install and configure an ArchLinux install
that contains:

- Auto DHCP for eth0
- Read-only Root
- BTRFS Cache partition
- Local Console via UART

The install script requires a valid ArchLinuxARM tar blob, which one of the following
can be used:

- [ARM7 (Pi2-Pi4/PiZero(W)/PiZero2)](http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-armv7-latest.tar.gz)
  - With curl: `curl -Lo ArchLinuxARM-rpi-armv7-latest.tar.gz http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-armv7-latest.tar.gz`
  - With wget: `wget http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-armv7-latest.tar.gz`
- [ARM8 (Pi3-Pi4/PiZero2)](http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-aarch64-latest.tar.gz)
  - With curl: `curl -Lo ArchLinuxARM-rpi-aarch64-latest.tar.gz http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-aarch64-latest.tar.gz`
  - With wget: `wget http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-aarch64-latest.tar.gz`

_Sadly, the Pi1[A|B]/Pi[A|B]+/PiZero[W] (which are ARMv6) aren't supported by ArchLinuxARM anymore,_
_so this script won't work for them._

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
folder. _(Requires `python3`)_

## Default Login Credentials

The default login credentials are `root`:`root`. _This works over SSH and local_
_console._ _YOU SHOULD CHANGE THESE!_

## AArch64 Notes

If you are installing for the Pi3-Pi4 or PiZero2, you may use the AArch64 install.
This script will detect if the install is AARCH64 and will update the filesystem
accordingly. **You are still required to used the correct tar image file**.

## U-Boot Notes

U-Boot should work fine for Pi3/4 out of the box. For the PiZero2, it will **not**
workout without manual intervention. It's recommended to use the RPI bootloader instead
unless U-Boot is needed.

Using U-Boot by default can be disabled by passing the `UBOOT` environment variable
with a value of `0`.

Using `export UBOOT=0` or `sudo env UBOOT=0 bash install.sh ...` works fine to
disable U-Boot.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Z8Z4121TDS)
