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
    printf "%s <tar_image> <disk> [source script]\n" "$0" 1>&2
    exit 1
fi

SETUP_DRIVE="$2"
SETUP_IMAGE="$1"
SETUP_UBOOT=${UBOOT:-1}
SETUP_SCRIPT="$3"
SETUP_AARCH64=0

SETUP_ROOT="/tmp/$(date +%s)-root"
SETUP_CONFIGURATION="/opt/sysconfig"
SETUP_DIRECTORY="${SETUP_ROOT}${SETUP_CONFIGURATION}"

log() {
    local _m="$1"; shift
    printf "\x1b[1m[+]\x1b[0m \x1b[32m${_m}\x1b[0m\n" $*
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
        bail 'Command \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[31m exited witn a non-zero \x1b[0m\x1b[1m(%d)\x1b[0m\x1b[31m status code' "$1" "$r"
    fi
    if [ $# -eq 3 ]; then
        if [ $r -eq "$2" ] || [ $r -eq "$3" ]; then
            return
        fi
        bail 'Command \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[31m exited witn a non-zero \x1b[0m\x1b[1m(%d)\x1b[0m\x1b[31m status code' "$1" "$r"
    fi
    if [ $r -ne $2 ]; then
        bail 'Command \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[31m exited witn a \x1b[0m\x1b[1m(%d)\x1b[0m\x1b[31m status code' "$1" "$r"
    fi
}
bail() {
    local _m="$1"; shift
    printf "\x1b[1m[!]\x1b[0m \x1b[31m${_m}!\x1b[0m\n" $* 1>&2
    printf '\x1b[1m[!]\x1b[0m \x1b[31mCannot continue, quitting!\x1b[0m\n' 1>&2
    cleanup 1
}
cleanup() {
    sync
    [ -e "/proc/sys/fs/binfmt_misc/arm" ] && echo '-1' > "/proc/sys/fs/binfmt_misc/arm"
    [ -e "/proc/sys/fs/binfmt_misc/aarch64" ] && echo '-1' > "/proc/sys/fs/binfmt_misc/aarch64"
    umount "/proc/sys/fs/binfmt_misc" 2> /dev/null
    lsof -n 2> /dev/null | grep "$SETUP_ROOT" | awk '{print $2}' | xargs -I % kill -9 % 2> /dev/null
    sleep 3
    umount "${SETUP_ROOT}/sys" 2> /dev/null
    umount "${SETUP_ROOT}/dev" 2> /dev/null
    umount "${SETUP_ROOT}/proc" 2> /dev/null
    umount "${SETUP_ROOT}/dev" 2> /dev/null
    sync
    umount "${SETUP_ROOT}/boot" 2> /dev/null
    umount "${SETUP_ROOT}/var" 2> /dev/null
    umount "${SETUP_ROOT}" 2> /dev/null
    sync
    rmdir "${SETUP_ROOT}" 2> /dev/null
    if [ $# -ne 1 ]; then
        exit 0
    fi
    exit "$1"
}

setup_disk() {
    log 'Creating partitions on \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[32m..' "$SETUP_DRIVE"
    umount "${SETUP_DRIVE}"* 2> /dev/null
    local _total=$(fdisk -l "$SETUP_DRIVE" | grep "Disk" | grep "sectors" | awk '{print $7}')
    if [ $? -ne 0 ]; then
        bail 'Could not get disk \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[31m sector size' "$SETUP_DRIVE"
    fi
    printf "o\nn\np\n1\n\n+200M\ny\nt\nc\nn\np\n2\n\n%d\n\ny\nn\np\n3\n\n\nw\n" "$((_total - 16777218))" | exec "fdisk ${SETUP_DRIVE}" 2>&1 | grep -vE 'Partition #|y: unknown command' 1> /dev/null
    log "Formatting partitions.."
    exec "mkfs.vfat -nBOOT -I ${SETUP_DRIVE}${_SEPERATOR}1"
    exec "mkfs.ext4 -q -L root -F ${SETUP_DRIVE}${_SEPERATOR}2"
    exec "mkfs.btrfs -L cache -f ${SETUP_DRIVE}${_SEPERATOR}3"
    log "Mounting partitions.."
    exec "mkdir -p ${SETUP_ROOT}"
    exec "mount -t ext4 -o rw,noatime,nodev,discard ${SETUP_DRIVE}${_SEPERATOR}2 ${SETUP_ROOT}"
    exec "mkdir -p ${SETUP_ROOT}/boot"
    exec "mount -t vfat -o rw,noatime,nodev,noexec,nosuid ${SETUP_DRIVE}${_SEPERATOR}1 ${SETUP_ROOT}/boot"
    exec "mkdir -p ${SETUP_ROOT}/var"
    exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd:3,ssd,discard=async ${SETUP_DRIVE}${_SEPERATOR}3 ${SETUP_ROOT}/var"
    exec "btrfs subvolume create ${SETUP_ROOT}/var/base"
    exec "umount ${SETUP_ROOT}/var"
    exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd:3,ssd,discard=async,subvol=/base ${SETUP_DRIVE}${_SEPERATOR}3 ${SETUP_ROOT}/var"
    if echo "$SETUP_IMAGE" | grep -q "aarch64"; then
        log "Detected an \x1b[0m\x1b[1mAARCH\x1b[0m\x1b[32m install."
        SETUP_AARCH64=1
    fi
    log 'Extracting \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[32m to \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[32m..' "$SETUP_IMAGE" "$SETUP_DRIVE"
    exec "bsdtar -xpf \"${SETUP_IMAGE}\" -C ${SETUP_ROOT}" 0 1 2>&1 | grep -vE "Cannot restore extended attributes on this file system|bsdtar: Error exit delayed from previous errors."
    sync
    if [ "$SETUP_AARCH64" -eq 0 ] && file "${SETUP_ROOT}/usr/bin/bash" | grep -q ": ELF 64-bit LSB pie executable, ARM aarch64"; then
        log "Detected an \x1b[0m\x1b[1mAARCH\x1b[0m\x1b[32m install."
        SETUP_AARCH64=1
    fi
}
setup_check() {
    if ! which lsof 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"lsof"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"lsof"\x1b[0m\x1b[31m first'
    fi
    if ! which bsdtar 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"bsdtar"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"libarchive"\x1b[0m\x1b[31m first'
    fi
    if ! which mkimage 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"mkimage"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"uboot-tools"\x1b[0m\x1b[31m first'
    fi
    if ! which mkfs.ext4 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"mkfs.ext4"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"e2fsprogs"\x1b[0m\x1b[31m first'
    fi
    if ! which mkfs.vfat 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"mkfs.vfat"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"dosfstools"\x1b[0m\x1b[31m first'
    fi
    if ! which mkfs.btrfs 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"mkfs.btrfs"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"btrfs-progs"\x1b[0m\x1b[31m first'
    fi
    if ! which qemu-arm-static 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"qemu-arm-static"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"qemu-user-static"\x1b[0m\x1b[31m first'
    fi
    if ! which qemu-aarch64-static 1> /dev/null 2> /dev/null; then
        bail '\x1b[0m\x1b[1m"qemu-aarch64-static"\x1b[0m\x1b[31m is missing, please install \x1b[0m\x1b[1m"qemu-user-static"\x1b[0m\x1b[31m first'
    fi
    if ! [ -b "$SETUP_DRIVE" ]; then
        bail 'Path \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[31m is not a block device' "$SETUP_DRIVE"
    fi
    if ! [ -f "$SETUP_IMAGE" ]; then
        bail 'Image \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[31m does not exist' "$SETUP_IMAGE"
    fi
    if ! [ -f "$(pwd)/config.sh" ]; then
        bail 'File \x1b[0m\x1b[1m"%s/config.sh"\x1b[0m\x1b[31m does not exist' "$(pwd)"
    fi
}
setup_config() {
    log "Starting configuration.."
    rm "${SETUP_ROOT}"/etc/systemd/network/*.network
    rm "${SETUP_ROOT}/etc/resolv.conf"
    cp -fL "/etc/resolv.conf" "${SETUP_ROOT}/etc/resolv.conf"
    if [ "$SETUP_AARCH64" -eq 0 ] && [ "${SETUP_UBOOT:-1}" -eq 0 ]; then
        log "Using the RPI bootloader instead of U-Boot!"
        SETUP_AARCH64=1
    fi

    mkdir -p "${SETUP_DIRECTORY}/etc/systemd/network"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/timers.target.wants"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/sockets.target.wants"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/sysinit.target.wants"
    mkdir -p "${SETUP_ROOT}/etc/systemd/system/network-online.target.wants"

    mkdir -p "${SETUP_ROOT}/var/db/pacman"
    mkdir -p "${SETUP_ROOT}/var/cache/pacman"
    mkdir -p "${SETUP_ROOT}/var/cache/pacman/pkg"
    chmod 0555 "${SETUP_ROOT}/var/db/pacman"

    mv "${SETUP_ROOT}/etc/ld.so.cache" "${SETUP_ROOT}/var/cache/ld.so.cache"
    mv "${SETUP_ROOT}/etc/pacman.d/mirrorlist" "${SETUP_ROOT}/var/cache/pacman/mirrorlist"

    ln -sT "/var/cache/ld.so.cache" "${SETUP_ROOT}/etc/ld.so.cache"
    ln -sT "/var/cache/pacman/mirrorlist" "${SETUP_ROOT}/etc/pacman.d/mirrorlist"

    printf 'proc           /proc    proc  rw,nosuid,noexec,nodev,noatime,hidepid=invisible,gid=proc                                                                     0 0\n' > "${SETUP_ROOT}/etc/fstab"
    printf 'tmpfs          /tmp     tmpfs rw,nosuid,nodev,noatime                                                                                                       0 0\n' > "${SETUP_ROOT}/etc/fstab"
    printf 'tmpfs          /dev/shm tmpfs rw,nosuid,noexec,nodev,noatime                                                                                                0 0\n' >> "${SETUP_ROOT}/etc/fstab"
    printf '/dev/mmcblk0p1 /boot    vfat  ro,nosuid,noexec,nodev,noatime,fmask=0137,dmask=0027,codepage=437,iocharset=iso8859-1,shortname=mixed,utf8,errors=remount-ro  0 2\n' >> "${SETUP_ROOT}/etc/fstab"
    printf '/dev/mmcblk0p2 /        ext4  ro,nodev,discard,noatime                                                                                                      0 0\n' >> "${SETUP_ROOT}/etc/fstab"
    printf '/dev/mmcblk0p3 /var     btrfs rw,nosuid,noexec,nodev,noatime,compress=zstd:3,ssd,space_cache=v2,subvol=/base,discard=async                                  0 0\n' >> "${SETUP_ROOT}/etc/fstab"
    chmod 0444 "${SETUP_ROOT}/etc/fstab"

    printf 'rpi' > "${SETUP_DIRECTORY}/etc/hostname"
    printf 'SYSCONFIG="%s"\nSYSCONFIG_SECURE=1\n' "$SETUP_CONFIGURATION" > "${SETUP_ROOT}/etc/sysconfig.conf"

    rm "${SETUP_ROOT}/etc/localtime" 2> /dev/null
    ln -sT "/usr/share/zoneinfo/America/New_York" "${SETUP_ROOT}/etc/localtime"

    ln -sT "/usr/lib/systemd/system/fstrim.timer" "${SETUP_ROOT}/etc/systemd/system/timers.target.wants/fstrim.timer"
    ln -sT "/usr/lib/systemd/system/sshd.service" "${SETUP_ROOT}/etc/systemd/system/multi-user.target.wants/sshd.service" 2> /dev/null
    ln -sT "/usr/lib/systemd/system/logrotate.timer" "${SETUP_ROOT}/etc/systemd/system/timers.target.wants/logrotate.timer"
    ln -sT "/usr/lib/systemd/system/btrfs-scrub@.timer" "${SETUP_ROOT}/etc/systemd/system/timers.target.wants/btrfs-scrub@var.timer"
    ln -sT "/usr/lib/systemd/system/systemd-networkd.socket" "${SETUP_ROOT}/etc/systemd/system/sockets.target.wants/systemd-networkd.socket" 2> /dev/null
    ln -sT "/usr/lib/systemd/system/systemd-timesyncd.service" "${SETUP_ROOT}/etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service" 2> /dev/null
    ln -sT "/usr/lib/systemd/system/systemd-networkd.service" "${SETUP_ROOT}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service" 2> /dev/null
    ln -sT "/usr/lib/systemd/system/systemd-resolved.service" "${SETUP_ROOT}/etc/systemd/system/multi-user.target.wants/systemd-resolved.service" 2> /dev/null
    ln -sT "/usr/lib/systemd/system/systemd-networkd-wait-online.service" "${SETUP_ROOT}/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service" 2> /dev/null

    rm -f "${SETUP_ROOT}/etc/systemd/system/home.mount"
    rm -f "${SETUP_ROOT}/etc/systemd/system/syslog.target"
    rm -f "${SETUP_ROOT}/etc/systemd/system/rescue.target"
    rm -f "${SETUP_ROOT}/etc/systemd/system/rescue.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/syslog.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/emergency.target"
    rm -f "${SETUP_ROOT}/etc/systemd/system/emergency.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/debug-shell.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-bsod.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-homed.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/var-lib-machines.mount"
    rm -f "${SETUP_ROOT}/etc/systemd/system/plymouth-start.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-pstore.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-repart.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/display-manager.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-sysusers.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-firstboot.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/first-boot-complete.target"
    rm -f "${SETUP_ROOT}/etc/systemd/system/plymouth-quit-wait.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-boot-update.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-hwdb-update.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-boot-system-token.service"
    rm -f "${SETUP_ROOT}/etc/systemd/system/systemd-network-generator.service"

    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/home.mount"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/syslog.target"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/rescue.target"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/rescue.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/syslog.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/emergency.target"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/emergency.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/debug-shell.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-bsod.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-homed.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/var-lib-machines.mount"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/plymouth-start.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-pstore.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-repart.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/display-manager.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-sysusers.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-firstboot.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/first-boot-complete.target"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/plymouth-quit-wait.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-quotacheck.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-boot-update.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-hwdb-update.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-boot-system-token.service"
    ln -sT "/dev/null" "${SETUP_ROOT}/etc/systemd/system/systemd-network-generator.service"

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

    log "Adding configuration.."
    setup_script
    log "Configuration setup complete!"

    chmod 0444 "${SETUP_ROOT}/etc/sysconfig.conf"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/timers.target.wants"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/sockets.target.wants"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/sysinit.target.wants"
    chmod 0555 "${SETUP_ROOT}/etc/systemd/system/network-online.target.wants"
    chmod 0400 "${SETUP_DIRECTORY}/etc/mkinitcpio.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/security/limits.d/limits.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/ssh/sshd_config"
    chmod 0400 "${SETUP_DIRECTORY}/etc/sysctl.d/kernel.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/systemd/coredump.conf"
    chmod 0400 "${SETUP_DIRECTORY}/etc/vconsole.conf"
    chmod 0440 "${SETUP_DIRECTORY}/etc/mkinitcpio.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/hostname"
    chmod 0444 "${SETUP_DIRECTORY}/etc/hosts"
    chmod 0444 "${SETUP_DIRECTORY}/etc/locale.gen"
    chmod 0444 "${SETUP_DIRECTORY}/etc/motd"
    chmod 0444 "${SETUP_DIRECTORY}/etc/ssh/ssh_config"
    chmod 0444 "${SETUP_DIRECTORY}/etc/sysless"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/journald.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/resolved.conf"
    chmod 0444 "${SETUP_DIRECTORY}/etc/systemd/timesyncd.conf"
    chmod 0550 "${SETUP_DIRECTORY}/etc/pacman.d/hooks"
    chmod 0550 "${SETUP_DIRECTORY}/etc/security/limits.d"
    chmod 0550 "${SETUP_DIRECTORY}/etc/syscheck.d"
    chmod 0550 "${SETUP_DIRECTORY}/etc/syscheck.d"
    chmod 0550 "${SETUP_DIRECTORY}/etc/sysctl.d"
    chmod 0555 "${SETUP_DIRECTORY}/bin"
    chmod 0555 "${SETUP_DIRECTORY}/etc/pacman.d/hooks"
    chmod 0555 "${SETUP_DIRECTORY}/etc/profile.d"
    chmod 0555 "${SETUP_DIRECTORY}/etc/profile.d/umask.sh"
    chmod 0555 "${SETUP_DIRECTORY}/etc/profile.d/z_system_status.sh"
    chmod 0555 "${SETUP_DIRECTORY}/etc/ssh"
    chmod 0555 "${SETUP_DIRECTORY}/etc/systemd/network"
    chmod 0555 "${SETUP_DIRECTORY}/etc/systemd/system"
    chmod 0555 "${SETUP_DIRECTORY}"/bin/*
    chmod 0400 "${SETUP_DIRECTORY}"/etc/pacman.d/hooks/*
    chmod 0444 "${SETUP_DIRECTORY}"/etc/systemd/system/*

    if [ $SETUP_AARCH64 -eq 0 ]; then
        sed -i'' -e 's/Architecture        = aarch64/Architecture        = armv7h/g' "${SETUP_DIRECTORY}/etc/pacman.conf"
    fi

    rm -f ${SETUP_ROOT}/etc/ssh/*key* 2> /dev/null
    awk '$5 > 2000' "${SETUP_ROOT}/etc/ssh/moduli" > "${SETUP_ROOT}/etc/ssh/moduli"
    ssh-keygen -t ed25519 -f "${SETUP_ROOT}/etc/ssh/ssh_host_ed25519_key" -N "" < /dev/null > /dev/null
    ssh-keygen -t rsa -b 4096 -f "${SETUP_ROOT}/etc/ssh/ssh_host_rsa_key" -N "" < /dev/null > /dev/null

    log "Configuration complete!"
}
setup_script() {
    export SETUP_ROOT
    export SETUP_UBOOT
    export SETUP_DIRECTORY
    export SETUP_CONFIGURATION
    if ! source "$(pwd)/config.sh"; then
        bail 'Executing \x1b[0m\x1b[1m"config.sh"\x1b[0m\x1b[31m failed'
    fi
}
setup_chroot() {
    log "Building chroot script.."
    printf '#!/usr/bin/bash\n\n' > "${SETUP_ROOT}/root/start.sh"
    printf 'pacman-key --init 1> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'pacman-key --populate archlinuxarm 1> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mv "/etc/pacman.d/gnupg" "/var/db/pacman/gnupg"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'ln -sT "/var/db/pacman/gnupg" "/etc/pacman.d/gnupg"\n' >> "${SETUP_ROOT}/root/start.sh"
    printf "bash %s/bin/relink %s / 1> /dev/null\n" "$SETUP_CONFIGURATION" "$SETUP_CONFIGURATION" >> "${SETUP_ROOT}/root/start.sh"
    printf "bash %s/bin/syslink 1> /dev/null 2> /dev/null\n" "$SETUP_CONFIGURATION" >> "${SETUP_ROOT}/root/start.sh"
    printf 'mount -o rw,remount /\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'locale-gen 1> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'pacman -Syu --noconfirm\n' >> "${SETUP_ROOT}/root/start.sh"
    if [ $SETUP_UBOOT -eq 0 ]; then
        printf 'pacman -S --noconfirm --ask 4 linux-rpi firmware-raspberrypi net-tools iptables-nft btrfs-progs pacman-contrib zstd logrotate git git-lfs\n' >> "${SETUP_ROOT}/root/start.sh"
    else
        printf 'pacman -S --noconfirm --ask 4 net-tools iptables-nft btrfs-progs pacman-contrib zstd logrotate git git-lfs\n' >> "${SETUP_ROOT}/root/start.sh"
    fi
    printf 'pacman -Rsc $(pacman -Qtdq) --noconfirm 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'mount -o rw,remount /\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'timedatectl set-ntp true 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'update-ca-trust\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'userdel -rf alarm 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'userdel -rf belly 2> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'git config --global user.name "rpi" 1> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'git config --global user.email "rpi@localhost" 1> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"
    printf 'git lfs install 1> /dev/null\n' >> "${SETUP_ROOT}/root/start.sh"

    local _resolv=$(md5sum "${SETUP_ROOT}/etc/resolv.conf" | awk '{print $1}')
    if [ -n "$SETUP_SCRIPT" ] && [ -f "$SETUP_SCRIPT" ]; then
        log 'Adding additional script \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[32m..' "$SETUP_SCRIPT"
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

    log 'Build complete, preparing to chroot into \x1b[0m\x1b[1m"%s"\x1b[0m\x1b[32m..' "$SETUP_ROOT"
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
        bail "Chroot exited with a non-zero exit code, you might have used an invalid arch"
    fi
    log "Chroot complete!"
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

set -uo pipefail

_SEPERATOR=""
if echo "$SETUP_DRIVE" | grep -q 'blk'; then
    _SEPERATOR="n"
else
    if echo "$SETUP_DRIVE" | grep -q 'nvme'; then
        _SEPERATOR="p"
    fi
fi

# Set Cleanup on failure
trap cleanup 1 2 3 6

setup_check
setup_disk
setup_config
setup_chroot
sync

log "Install complete!"
trap - 1 2 3 6
log 'Please change the \x1b[0m\x1b[1mroot\x1b[0m\x1b[32m user password \x1b[0m\x1b[1m"root"\x1b[0m\x1b[32m on first login!!'
cleanup
