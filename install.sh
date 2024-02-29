#!/usr/bin/bash
# Copyright 2021 - 2024 iDigitalFlame
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if ! [ "$UID" = "0" ]; then
    echo "You MUST be root to do this!" 1>&2
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "%s <tar_image> <disk> [source script]" "$0" 1>&2
    exit 1
fi

SETUP_DISK="$2"
SETUP_IMAGE="$1"
SETUP_UBOOT=${UBOOT:-1}
SETUP_SCRIPT="$3"
SETUP_AARCH64=0
SETUP_ROOT="/tmp/$(date +%s)-root"
SETUP_CONFIGURATION="/opt/sysconfig"
SETUP_DIRECTORY="${SETUP_ROOT}${SETUP_CONFIGURATION}"

_SEPERATOR=""
if echo "$SETUP_DISK" | grep -q 'blk'; then
    _SEPERATOR="n"
else
    if echo "$SETUP_DISK" | grep -q 'nvme'; then
        _SEPERATOR="p"
    fi
fi

log() {
    printf "\x1b[1m[+]\x1b[0m \x1b[32m%s\x1b[0m\n" "$1"
}
exec() {
    if [ $# -lt 1 ]; then
        return
    fi
    eval "$1" 1> /dev/null; r=$?
    if [ $# -eq 1 ]; then
        if [ $r -eq 0 ]; then
            return
        fi
        printf '\x1b[1m[!]\x1b[0m \033[1;31mCommand \033[0m%s\033[1;31m exited witn a non-zero \033[0m(%d) \033[1;31mstatus code!\033[0m\n' "$1" "$r" 1>&2
        cleanup 1
    fi
    if [ $# -eq 3 ]; then
        if [ $r -eq "$2" ] || [ $r -eq "$3" ]; then
            return
        fi
        printf '\x1b[1m[!]\x1b[0m \033[1;31mCommand \033[0m%s\033[1;31m exited witn a non-zero \033[0m(%d) \033[1;31mstatus code!\033[0m\n' "$1" "$r" 1>&2
        cleanup 1
    fi
    if [ "$r" -ne "$2" ]; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31mCommand \033[0m%s\033[1;31m exited with a \033[0m(%d) \033[1;31mstatus code!\033[0m\n' "$1" "$r" 1>&2
        cleanup 1
    fi
}
bail() {
    printf "\x1b[1m[!]\x1b[0m \x1b[31m%s\x1b[0m\n" "$1" 1>&2
    printf "\x1b[1m[!]\x1b[0m \x1b[31mCannot continue, quitting!\x1b[0m\n" 1>&2
    ceanup 1
}
cleanup() {
    log "Performing cleanup..."
    sync
    [ -e "/proc/sys/fs/binfmt_misc/arm" ] && echo '-1' > "/proc/sys/fs/binfmt_misc/arm"
    [ -e "/proc/sys/fs/binfmt_misc/aarch64" ] && echo '-1' > "/proc/sys/fs/binfmt_misc/aarch64"
    umount "/proc/sys/fs/binfmt_misc" 2> /dev/null
    lsof -n | grep "$SETUP_ROOT" | awk '{print $2}' | xargs -I % kill -9 % 2> /dev/null
    sleep 5
    umount "${SETUP_ROOT}/sys" 2> /dev/null
    umount "${SETUP_ROOT}/dev" 2> /dev/null
    umount "${SETUP_ROOT}/proc" 2> /dev/null
    umount "${SETUP_ROOT}/dev" 2> /dev/null
    sync
    umount "${SETUP_ROOT}/boot" 2> /dev/null
    umount "${SETUP_ROOT}/var" 2> /dev/null
    umount "${SETUP_ROOT}"
    sync
    rmdir "${SETUP_ROOT}" 2> /dev/null
    if [ $# -ne 1 ]; then
        exit 0
    fi
    exit "$1"
}

setup_check() {
    if ! which lsof 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"lsof" \033[1;31mis missing, please install \033[0m"lsof" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which bsdtar 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"bsdtar" \033[1;31mis missing, please install \033[0m"libarchive" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which mkimage 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"mkimage" \033[1;31mis missing, please install \033[0m"uboot-tools" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which mkfs.ext4 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0"mmkfs.ext4" \033[1;31mis missing, please install \033[0m"e2fsprogs" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which mkfs.vfat 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"mkfs.vfat" 033[1;31mis missing, please install \033[0m"dosfstools" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which mkfs.btrfs 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"mkfs.btrfs" 033[1;31mis missing, please install \033[0m"btrfs-progs" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which qemu-arm-static 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"qemu-arm-static" \033[1;31mis missing, please install \033[0m"qemu-user-static" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! which qemu-aarch64-static 1> /dev/null 2> /dev/null; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31m\033[0m"qemu-aarch64-static" \033[1;31mis missing, please install \033[0m"qemu-user-static" \033[1;31mfirst!\033[0m\n' 1>&2
        exit 1
    fi
    if ! [ -b "$SETUP_DISK" ]; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31mPath \033[0m"%s" \033[1;31mis not a block device!\033[0m\n' "$SETUP_DISK" 1>&2
        exit 1
    fi
    if ! [ -f "$SETUP_IMAGE" ]; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31mImage path \033[0m"%s" \033[1;31mdoes not exist!\033[0m\n' "$SETUP_IMAGE" 1>&2
        exit 1
    fi
    if ! [ -f "$(pwd)/config.sh" ]; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31mPath \033[0m"%s/config.sh" \033[1;31mdoes not exist!\033[0m\n' "$(pwd)" 1>&2
        exit 1
    fi
}
setup_files() {
    log "Preparing supplimantary files.."
    rm "${SETUP_ROOT}"/etc/systemd/network/*.network
    rm "${SETUP_ROOT}/etc/resolv.conf"
    cp -fL "/etc/resolv.conf" "${SETUP_ROOT}/etc/resolv.conf"
    if [ "$SETUP_AARCH64" -eq 0 ] || [ "${SETUP_UBOOT:-1}" -eq 0 ]; then
        log "Using the RPI bootloader instead of U-Boot!"
        SETUP_AARCH64=1
    fi
}
setup_config() {
    log "Starting system configuration.."
    mkdir -p "${SETUP_DIRECTORY}/etc/systemd/network"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/timers.target.wants"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/sockets.target.wants"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/sysinit.target.wants"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/network-online.target.wants"

    log "Adding configuration.."
    setup_script
    log "Configuration done!"

    mkdir -p "${SETUP_ROOT}/var/cache/pacman"
    mv "${SETUP_ROOT}/etc/pacman.d/mirrorlist" "${SETUP_ROOT}/var/cache/pacman/mirrorlist"

    printf 'proc           /proc    proc  rw,nosuid,noexec,nodev,noatime,hidepid=invisible,gid=proc                                                                     0 0\n' > "${SETUP_ROOT}/etc/fstab"
    printf 'tmpfs          /tmp     tmpfs rw,nosuid,nodev,noatime                                                                                                       0 0\n' > "${SETUP_ROOT}/etc/fstab"
    printf 'tmpfs          /dev/shm tmpfs rw,nosuid,noexec,nodev,noatime                                                                                                0 0\n' >> "${SETUP_ROOT}/etc/fstab"
    printf '/dev/mmcblk0p1 /boot    vfat  ro,nosuid,noexec,nodev,noatime,fmask=0137,dmask=0027,codepage=437,iocharset=iso8859-1,shortname=mixed,utf8,errors=remount-ro  0 2\n' >> "${SETUP_ROOT}/etc/fstab"
    printf '/dev/mmcblk0p2 /        ext4  ro,nodev,discard,noatime                                                                                                      0 0\n' >> "${SETUP_ROOT}/etc/fstab"
    printf '/dev/mmcblk0p3 /var     btrfs rw,nosuid,noexec,nodev,noatime,compress=zstd:3,ssd,space_cache=v2,subvol=/base,discard=async                                  0 0\n' >> "${SETUP_ROOT}/etc/fstab"
    chmod 0444 "${SETUP_ROOT}/etc/fstab"

    printf 'rpi' > "${SETUP_DIRECTORY}/etc/hostname"
    printf 'SYSCONFIG="%s"\nSYSCONFIG_SECURE=1\n' "$SETUP_CONFIGURATION" > "${SETUP_ROOT}/etc/sysconfig.conf"

    if [ $SETUP_UBOOT -eq 0 ]; then
        printf 'root=/dev/mmcblk0p2 ro rootwait console=ttyAMA0,9600 kgdboc=ttyAMA0,9600 console=tty1 selinux=0 audit=0 fsck.repair=yes quiet loglevel=2 rd.systemd.show_status=auto rd.udev.log_priority=2\n' > "${SETUP_ROOT}/boot/cmdline.txt"
    else
        printf 'part uuid ${devtype} ${devnum}:2 uuid\n\nsetenv bootargs "root=PARTUUID=${uuid} ro rootwait' >> "${SETUP_ROOT}/boot/boot.txt"
        printf 'console=ttyS1,9600 kgdboc=ttyS1,9600 console=tty1 selinux=0 audit=0 fsck.repair=yes quiet loglevel=2 rd.systemd.show_status=auto rd.udev.log_priority=2"\n\nif ' >> "${SETUP_ROOT}/boot/boot.txt"
        printf 'load ${devtype} ${devnum}:${bootpart} ${kernel_addr_r} /Image; then\n  if load ${' >> "${SETUP_ROOT}/boot/boot.txt"
        printf 'devtype} ${devnum}:${bootpart} ${fdt_addr_r} /dtbs/${fdtfile}; then\n    if load ' >> "${SETUP_ROOT}/boot/boot.txt"
        printf '${devtype} ${devnum}:${bootpart} ${ramdisk_addr_r} /initramfs-linux.img; then\n  ' >> "${SETUP_ROOT}/boot/boot.txt"
        printf '    booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr_r};\n    else' >> "${SETUP_ROOT}/boot/boot.txt"
        printf '\n      booti ${kernel_addr_r} - ${fdt_addr_r};\n    fi;\n  fi;\nfi\n' >> "${SETUP_ROOT}/boot/boot.txt"
    fi
    printf '\ndtparam=audio=on\n' >> "${SETUP_ROOT}/boot/config.txt"

    chmod 0555 "${SETUP_DIRECTORY}/bin"
    chmod 0555 "${SETUP_DIRECTORY}/etc/ssh"
    chmod 0550 "${SETUP_DIRECTORY}/etc/sysctl.d"
    chmod 0555 "${SETUP_DIRECTORY}/etc/profile.d"
    chmod 0550 "${SETUP_DIRECTORY}/etc/syscheck.d"
    chmod 0550 "${SETUP_DIRECTORY}/etc/udev/rules.d"
    chmod 0440 "${SETUP_DIRECTORY}/etc/nftables.conf"
    chmod 0550 "${SETUP_DIRECTORY}/etc/pacman.d/hooks"
    chmod 0555 "${SETUP_DIRECTORY}/etc/systemd/system"
    chmod 0555 "${SETUP_DIRECTORY}/etc/pacman.d/hooks"
    chmod 0555 "${SETUP_DIRECTORY}/etc/systemd/network"
    chmod 0550 "${SETUP_DIRECTORY}/etc/security/limits.d"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/timers.target.wants"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/sockets.target.wants"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/sysinit.target.wants"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/network-online.target.wants"
    chmod 0444 "${SETUP_ROOT}/etc/sysconfig.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/motd"
    chmod 0444 "${SETUP_DIRECTORY}/etc/hosts"
    chmod 0444 "${SETUP_DIRECTORY}/etc/sysless"
    chmod 0444 "${SETUP_DIRECTORY}/etc/hostname"
    chmod 0444 "${SETUP_DIRECTORY}/etc/locale.gen"
    chmod 0400 "${SETUP_DIRECTORY}/etc/vconsole.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/ssh/ssh_config"
    chmod 0440 "${SETUP_DIRECTORY}/etc/mkinitcpio.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/ssh/sshd_config"
    chmod 0400 "${SETUP_DIRECTORY}/etc/mkinitcpio.conf"
    chmod 0555 "${SETUP_DIRECTORY}/etc/profile.d/umask.sh"
    chmod 0400 "${SETUP_DIRECTORY}/etc/sysctl.d/kernel.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/systemd/coredump.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/resolved.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/journald.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/timesyncd.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/security/limits.d/limits.conf"
    chmod 0555 "${SETUP_DIRECTORY}/etc/profile.d/z_system_status.sh"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/system/reflector.service"
    chmod 0555 "${SETUP_DIRECTORY}"/bin/*
    chmod 0400 "${SETUP_DIRECTORY}"/etc/pacman.d/hooks/*
    chmod 0444 "${SETUP_DIRECTORY}"/etc/systemd/system/*
    rm -f ${SETUP_ROOT}/etc/ssh/*key* 2> /dev/null
    awk '$5 > 2000' "${SETUP_ROOT}/etc/ssh/moduli" > "${SETUP_ROOT}/etc/ssh/moduli"
    ssh-keygen -t ed25519 -f "${SETUP_ROOT}/etc/ssh/ssh_host_ed25519_key" -N "" < /dev/null > /dev/null
    ssh-keygen -t rsa -b 4096 -f "${SETUP_ROOT}/etc/ssh/ssh_host_rsa_key" -N "" < /dev/null > /dev/null
    log "System configuration complete.."
}
setup_script() {
    export SETUP_ROOT
    export SETUP_UBOOT
    export SETUP_DIRECTORY
    export SETUP_CONFIGURATION
    if ! source "$(pwd)/config.sh"; then
        printf '\x1b[1m[!]\x1b[0m \033[1;31mSourcing \033[0m"config.sh" \033[1;31mfailed!\033[0m\n' 1>&2
        cleanup 1
    fi
}
setup_chroot() {
    log "Building chroot.."
    printf '#!/usr/bin/bash\n\n' > "${SETUP_ROOT}/root/start.sh"
    printf 'pacman-key --init\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'pacman-key --populate archlinuxarm\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'pacman -Syy --noconfirm\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mkdir -p "/var/db/pacman"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'chmod 555 "/var/db/pacman"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mkdir -p "/var/cache/pacman"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mv "/etc/ld.so.cache" "/var/cache/ld.so.cache"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mv "/etc/pacman.d/gnupg" "/var/db/pacman/gnupg"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -sT "/var/cache/ld.so.cache" "/etc/ld.so.cache"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -sT "/var/db/pacman/gnupg" "/etc/pacman.d/gnupg"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -sT "/var/cache/pacman/mirrorlist" "/etc/pacman.d/mirrorlist"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf "bash %s/bin/relink %s /\n" "$SETUP_CONFIGURATION" "$SETUP_CONFIGURATION" >> "${SETUP_ROOT}/root/start.sh"
    printf "bash %s/bin/syslink\n" "$SETUP_CONFIGURATION" >> "${SETUP_ROOT}/root/start.sh"
    printf 'locale-gen\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/share/zoneinfo/America/New_York /etc/localtime\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'pacman -Syu --noconfirm\n' >> "${SETUP_ROOT}/root/start.sh"
    if [ $SETUP_UBOOT -eq 0 ]; then
        printf 'pacman -S --noconfirm --ask 4 linux-rpi firmware-raspberrypi btrfs-progs pacman-contrib zstd logrotate git git-lfs\n' >> "${SETUP_ROOT}/root/start.sh"
    else
        printf 'pacman -S --noconfirm btrfs-progs pacman-contrib zstd logrotate git git-lfs\n' >> "${SETUP_ROOT}/root/start.sh"
    fi
    printf 'mount -o rw,remount /\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/fstrim.timer /etc/systemd/system/timers.target.wants/fstrim.timer\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/logrotate.timer /etc/systemd/system/timers.target.wants/logrotate.timer\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/systemd-networkd.socket /etc/systemd/system/sockets.target.wants/systemd-networkd.socket\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/systemd-networkd.service /etc/systemd/system/multi-user.target.wants/systemd-networkd.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/systemd-networkd-wait-online.service /etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/systemd-resolved.service /etc/systemd/system/multi-user.target.wants/systemd-resolved.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/systemd-timesyncd.service /etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/sshd.service /etc/systemd/system/multi-user.target.wants/sshd.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/home.mount\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/var-lib-machines.mount\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/emergency.target\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/first-boot-complete.target\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/syslog.target\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/emergency.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/debug-shell.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/display-manager.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/plymouth-quit-wait.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/plymouth-start.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/rescue.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/syslog.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-boot-system-token.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-boot-update.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-bsod.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-firstboot.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-network-generator.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-homed.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-hwdb-update.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-pstore.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-repart.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'rm -f /etc/systemd/system/systemd-sysusers.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/home.mount\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/var-lib-machines.mount\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/emergency.target\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/first-boot-complete.target\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-boot-update.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/syslog.target\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/emergency.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/debug-shell.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/display-manager.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/plymouth-quit-wait.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/plymouth-start.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/rescue.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/syslog.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-boot-system-token.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-bsod.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-firstboot.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-network-generator.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-homed.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-hwdb-update.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-pstore.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-repart.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /dev/null /etc/systemd/system/systemd-sysusers.service\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/fstrim.timer "/etc/systemd/system/timers.target.wants/fstrim.timer"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/logrotate.timer "/etc/systemd/system/timers.target.wants/logrotate.timer"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /usr/lib/systemd/system/btrfs-scrub@.timer "/etc/systemd/system/timers.target.wants/btrfs-scrub@var.timer"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'timedatectl set-ntp true 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'pacman -Rsc $(pacman -Qtdq) --noconfirm 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mount -o rw,remount /\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'update-ca-trust\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'userdel -rf alarm 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'userdel -rf belly 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    _resolv=$(md5sum "${SETUP_ROOT}/etc/resolv.conf" | awk '{print $1}')
    if [ -n "$SETUP_SCRIPT" ] && [ -f "$SETUP_SCRIPT" ]; then
        printf '\x1b[1m[+]\x1b[0m \033[1;32mAddding addditional script \033[0m"%s"\033[1;32m..\033[0m\n"' "$SETUP_SCRIPT"
        cp "$SETUP_SCRIPT" "${SETUP_ROOT}/root/extra.sh"
        chmod 0550 "${SETUP_ROOT}/root/extra.sh"
        printf 'bash /root/extra.sh\n' >> "${SETUP_ROOT}/root/start.sh"
        printf 'if [ "$(md5sum /etc/resolv.conf | awk '\''{print $1}'\'')" = "' >> "${SETUP_ROOT}/root/start.sh"
        # ^ We do this to prevent deleting/modifying "/etc/resolv.conf" if it's modified via the above script.
        printf '%s" ]; then\n' "$_resolv" >> "${SETUP_ROOT}/root/start.sh"
    fi
    printf 'rm -f /etc/resolv.conf\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -s /var/run/systemd/resolve/resolv.conf /etc/resolv.conf\n' >> "${SETUP_ROOT}/root/start.sh"
    if [ -n "$SETUP_SCRIPT" ] && [ -f "$SETUP_SCRIPT" ]; then
        printf 'fi\n' >> "${SETUP_ROOT}/root/start.sh"
    fi
    printf 'exit\n' >> "${SETUP_ROOT}/root/start.sh"
    chmod 0550 "${SETUP_ROOT}/root/start.sh"
    chmod 0444 "${SETUP_ROOT}/etc/sysconfig.conf"
    printf '\x1b[1m[+]\x1b[0m \033[1;32mPreperaring to chroot into \033[0m"%s"\033[1;32m..\033[0m\n' "$SETUP_ROOT"
    exec "mount -o bind /dev ${SETUP_ROOT}/dev"
    exec "mount -o bind /sys ${SETUP_ROOT}/sys"
    exec "mount -o bind /proc ${SETUP_ROOT}/proc"
    if [ $SETUP_AARCH64 -eq 1 ]; then
        exec "cp $(which qemu-aarch64-static) ${SETUP_ROOT}/usr/bin/qemu-aarch64-static"
        printf ':aarch64:M:18:\xB7:\xFF:/usr/bin/qemu-aarch64-static:\n' > /proc/sys/fs/binfmt_misc/register 2> /dev/null
    else
        exec "cp $(which qemu-arm-static) ${SETUP_ROOT}/usr/bin/qemu-arm-static"
        printf ':arm:M:18:\x28:\xFF:/usr/bin/qemu-arm-static:\n' > /proc/sys/fs/binfmt_misc/register 2> /dev/null
    fi
    log "Running chroot init script.."
    unset HOME
    unset PIP_USER
    unset PYTHONSTARTUP
    unset PYTHONUSERBASE
    export HOME="/root"
    export SETUP_ROOT
    export SETUP_UBOOT
    export SETUP_DIRECTORY
    export SETUP_CONFIGURATION
    if ! chroot "${SETUP_ROOT}" "/root/start.sh"; then
        bail "Chroot non-zero exit code!"
    fi
    log "Chroot finished!"
    unset HOME
    mount -o rw,remount "${SETUP_ROOT}"
    mount -o rw,remount "${SETUP_ROOT}/boot"
    find "${SETUP_ROOT}" -type f -name "*.pacnew" -delete 2> /dev/null
    find "${SETUP_ROOT}" -type f -name "*.pacsave" -delete 2> /dev/null
    if [ $SETUP_UBOOT -eq 1 ]; then
        # Compile this after so we can make changes to boot.txt first.
        exec "mkimage -A arm -O linux -T script -C none -n 'U-Boot boot script' -d ${SETUP_ROOT}/boot/boot.txt ${SETUP_ROOT}/boot/boot.scr"
    fi
    log "Cleaning up.."
    rm "${SETUP_ROOT}/root/start.sh" 2> /dev/null
    rm "${SETUP_ROOT}/root/extra.sh" 2> /dev/null
    rm "${SETUP_ROOT}/usr/bin/qemu-arm-static" 2> /dev/null
    rm "${SETUP_ROOT}/usr/bin/qemu-aarch64-static" 2> /dev/null
}
setup_partitions() {
    _total=$(fdisk -l "${SETUP_DISK}" | grep "Disk" | grep "sectors" | awk '{print $7}')
    if [ $? -ne 0 ]; then
        bail "Could not get disk sector size!"
    fi
    printf '\x1b[1m[+]\x1b[0m \033[1;32mPartitioning disk \033[0m%s\033[1;32m..\033[0m\n' "${SETUP_DISK}"
    printf "o\nn\np\n1\n\n+200M\ny\nt\nc\nn\np\n2\n\n%d\n\ny\nn\np\n3\n\n\nw\n" "$((_total - 16777218))" | exec "fdisk ${SETUP_DISK}" 2>&1 | grep -vE 'Partition #|y: unknown command'
    log "Creating and formatting partitions.."
    exec "mkfs.vfat -nBOOT -I ${SETUP_DISK}${_SEPERATOR}1"
    exec "mkfs.ext4 -q -L root -F ${SETUP_DISK}${_SEPERATOR}2"
    exec "mkfs.btrfs -L cache -f ${SETUP_DISK}${_SEPERATOR}3"
    log "Mounting partitions.."
    exec "mkdir -p ${SETUP_ROOT}"
    exec "mount -t ext4 -o rw,noatime,nodev,discard ${SETUP_DISK}${_SEPERATOR}2 ${SETUP_ROOT}"
    exec "mkdir -p ${SETUP_ROOT}/boot"
    exec "mount -t vfat -o rw,noatime,nodev,noexec,nosuid ${SETUP_DISK}${_SEPERATOR}1 ${SETUP_ROOT}/boot"
    exec "mkdir -p ${SETUP_ROOT}/var"
    exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd:3,ssd,discard=async ${SETUP_DISK}${_SEPERATOR}3 ${SETUP_ROOT}/var"
    exec "btrfs subvolume create ${SETUP_ROOT}/var/base"
    exec "umount ${SETUP_ROOT}/var"
    exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd:3,ssd,discard=async,subvol=/base ${SETUP_DISK}${_SEPERATOR}3 ${SETUP_ROOT}/var"
    if echo "$SETUP_IMAGE" | grep -q "aarch64"; then
        log "Detected an AARCH64 setup!"
        SETUP_AARCH64=1
    fi
    printf '\x1b[1m[+]\x1b[0m \033[1;32mExtracting \033[0m"%s"\033[1;32m to disk..\033[0m\n' "$SETUP_IMAGE"
    exec "bsdtar -xpf \"${SETUP_IMAGE}\" -C ${SETUP_ROOT}" 0 1 2>&1 | grep -vE "Cannot restore extended attributes on this file system.: Operation not supported|bsdtar: Error exit delayed from previous errors."
    sync
    if [ "$SETUP_AARCH64" -eq 0 ] && file "${SETUP_ROOT}/usr/bin/bash" | grep -q ": ELF 64-bit LSB pie executable, ARM aarch64"; then
        log "Detected an AARCH64 setup!"
        SETUP_AARCH64=1
    fi
}

set -o pipefail

# Set Cleanup on failure
trap cleanup 1 2 3 6

setup_check
setup_partitions
setup_files
setup_config
setup_chroot
sync

log "Done!"

printf '\033[1;32mPlease change the \033[0mroot\033[1;32m user password "\033[33mroot\033[1;32m" on first login!!\033[0m\n'
cleanup
