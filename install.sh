#!/usr/bin/bash
# Copyright 2021 - 2022 iDigitalFlame
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
    printf "%s <tar image> <disk> [source script]" "$0" 1>&2
    exit 1
fi

DISK="$2"
IMAGE="$1"
SCRIPT="$3"
IS_AARCH64=0
ROOT="/tmp/$(date +%s)-root"
SYSCONFIG_DIR="/opt/sysconfig"

if basename "$0" | grep -q "arch64" || echo "$IMAGE" | grep -q "aarch64"; then
    print "Detected AARCH64 setup!"
    IS_AARCH64=1
fi

exec() {
    if [ $# -lt 1 ]; then
        return
    fi
    eval "$1" 1>/dev/null; r=$?
    if [ $# -eq 1 ]; then
        if [ $r -eq 0 ]; then
            return
        fi
        printf "\033[1;31mCommand \033[0m\"%s\"\033[1;31m exited witn a non-zero \033[0m(%d) \033[1;31mstatus code!\033[0m\n" "$1" "$r" 1>&2
        cleanup 1
    fi
    if [ $# -eq 3 ]; then
        if [ $r -eq "$2" ] || [ $r -eq "$3" ]; then
            return
        fi
        printf "\033[1;31mCommand \033[0m\"%s\"\033[1;31m exited witn a non-zero \033[0m(%d) \033[1;31mstatus code!\033[0m\n" "$1" "$r" 1>&2
        cleanup 1
    fi
    if [ "$r" -ne "$2" ]; then
        printf "\033[1;31mCommand \033[0m\"%s\"\033[1;31m exited with a \033[0m(%d) \033[1;31mstatus code!\033[0m\n" "$1" "$r" 1>&2
        cleanup 1
    fi
}
print() {
    printf "\033[1;32m"
    printf "%s" "$*"
    printf "\033[0m\n"
}
checks() {
    if ! which dd 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"dd\" \033[1;31mis missing, please install \033[0mcore\"utils\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which lsof 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"lsof\" \033[1;31mis missing, please install \033[0m\"lsof\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which bsdtar 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"bsdtar\" \033[1;31mis missing, please install \033[0m\" libarchive\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkimage 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"mkimage\" \033[1;31mis missing, please install \033[0m\"uboot-tools\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkfs.ext4 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0\"mmkfs.ext4\" \033[1;31mis missing, please install \033[0m\"e2fsprogs\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkfs.vfat 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"mkfs.vfat\" 033[1;31mis missing, please install \033[0m\"dosfstools\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkfs.btrfs 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"mkfs.btrfs\" 033[1;31mis missing, please install \033[0m\"btrfs-progs\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which qemu-arm-static 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"qemu-arm-static\" \033[1;31mis missing, please install 033[0m\"qemu-user-static\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which qemu-aarch64-static 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"qemu-aarch64-static\" \033[1;31mis missing, please install 033[0m\"qemu-user-static\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! [ -b "$DISK" ]; then
        printf "\033[1;31mPath \033[0m\"%s\" \033[1;31mis not a block device!\033[0m\n" "$DISK" 1>&2
        exit 1
    fi
    if ! [ -f "$IMAGE" ]; then
        printf "\033[1;31mImage path \033[0m\"%s\" \033[1;31mdoes not exist!\033[0m\n" "$IMAGE" 1>&2
        exit 1
    fi
    if ! [ -f "$(pwd)/config.sh" ]; then
        printf "\033[1;31mPath 033[0m\"%s/config.sh\" \033[1;31mdoes not exist!\033[0m\n" "$(pwd)" 1>&2
        exit 1
    fi
}
cleanup() {
    print "Performing cleanup..."
    sync
    umount "/proc/sys/fs/binfmt_misc" 2> /dev/null
    umount "${ROOT}/boot" 2> /dev/null
    umount "${ROOT}/var" 2> /dev/null
    umount "${ROOT}" 2> /dev/null
    rmdir "${ROOT}" 2> /dev/null
    if [ $# -ne 1 ]; then
        exit 0
    fi
    exit "$1"
}

# Check env first
checks

# Set Cleanup on failure
trap cleanup 1 2 3 6

total=$(fdisk -l "${DISK}" | grep "Disk" | grep "sectors" | awk '{print $7}')
if [ $? -ne 0 ]; then
    printf "\033[1;31Could not get disk sector size!\033[0m\n" 1>&2
    cleanup 1
fi

print "Partitioning disk ${DISK}.."
printf "o\nn\np\n1\n\n+200M\ny\nt\nc\nn\np\n2\n\n%d\n\ny\nn\np\n3\n\n\nw\n" "$((total - 16777218))" | exec "fdisk ${DISK}"

print "Creating and formatting partitions.."
exec "mkfs.vfat -nBOOT -I ${DISK}p1"
exec "mkfs.ext4 -q -L root -F ${DISK}p2"
exec "mkfs.btrfs -L cache -f ${DISK}p3"

print "Mounting partitions.."
exec "mkdir -p ${ROOT}"
exec "mount -t ext4 -o rw,noatime,nodev,discard ${DISK}p2 ${ROOT}"
exec "mkdir -p ${ROOT}/boot"
exec "mount -t vfat -o rw,noatime,nodev,noexec,nosuid ${DISK}p1 ${ROOT}/boot"
exec "mkdir -p ${ROOT}/var"
exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd,ssd,discard=async ${DISK}p3 ${ROOT}/var"
exec "btrfs subvolume create ${ROOT}/var/base"
exec "umount ${ROOT}/var"
exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd,ssd,discard=async,subvol=/base ${DISK}p3 ${ROOT}/var"

print "Extracting ${IMAGE} to disk..."
exec "bsdtar -xpf \"${IMAGE}\" -C ${ROOT}" 0 1 2>&1 | grep -vE "Cannot restore extended attributes on this file system.: Operation not supported|bsdtar: Error exit delayed from previous errors."
sync

if [ "$IS_AARCH64" -eq 0 ] && file "${ROOT}/usr/bin/bash" | grep -q ": ELF 64-bit LSB pie executable, ARM aarch64"; then
    print "Detected AARCH64 setup!"
    IS_AARCH64=1
fi

print "Preparing supplimantary files.."
# Fix DNS Config issue
rm "${ROOT}/etc/resolv.conf"
cp -fL "/etc/resolv.conf" "${ROOT}/etc/resolv.conf"

# /etc/sysconfig.conf
printf "SYSCONFIG=%s\n" "$SYSCONFIG_DIR" > "${ROOT}/etc/sysconfig.conf"

# /root/init.sh
printf '#!/usr/bin/bash\n\n' > "${ROOT}/root/init.sh"
printf "bash %s/bin/relink %s /\n" "$SYSCONFIG_DIR" "$SYSCONFIG_DIR" >> "${ROOT}/root/init.sh"
printf "bash %s/bin/syslink\n" "$SYSCONFIG_DIR" >> "${ROOT}/root/init.sh"

# Change /etc/pacman.conf for aarch64
if [ "$IS_AARCH64" -eq 1 ]; then
    print "Fixing pacman.conf architecture for aarch64.."
    printf "sed -ie 'g/= armv7h/= aarch64/g' %s/etc/pacman.conf\n" "$SYSCONFIG_DIR" >> "${ROOT}/root/init.sh"
    printf 'rm -f "%s/etc/pacman.confe"\n' "$SYSCONFIG_DIR" >> "${ROOT}/root/init.sh"
fi

printf 'locale-gen\n' >> "${ROOT}/root/init.sh"
printf 'pacman-key --init\n' >> "${ROOT}/root/init.sh"
printf 'pacman-key --populate archlinuxarm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Syy --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Syu --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -S rng-tools btrfs-progs pacman-contrib zstd --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'mount -o rw,remount /\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask debug-shell.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask display-manager.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask plymouth-quit-wait.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask plymouth-start.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask syslog.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask syslog.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask rescue.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask emergency.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask emergency.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask var-lib-machines.mount > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-boot-system-token.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-firstboot.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-homed.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-hwdb-update.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-network-generator.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-pstore.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-repart.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-sysusers.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask first-boot-complete.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-resolved.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-networkd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-timesyncd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable fstrim.timer > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable rngd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Rsc $(pacman -Qtdq) --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'mount -o rw,remount /\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -A\n' >> "${ROOT}/root/init.sh"
printf 'chmod 400 /etc/ssh/*_key\n' >> "${ROOT}/root/init.sh"
printf 'userdel -rf alarm 2> /dev/null\n' >> "${ROOT}/root/init.sh"

if [ -n "$SCRIPT" ] && [ -f "$SCRIPT" ]; then
    print "Addding addditional script \"${SCRIPT}\".."
    cp "$SCRIPT" "${ROOT}/root/extra.sh"
    chmod 500 "${ROOT}/root/extra.sh"
    printf 'bash /root/extra.sh\n' >> "${ROOT}/root/init.sh"
fi

printf 'rm -f /etc/resolv.conf\n' >> "${ROOT}/root/init.sh"
printf 'ln -s /var/run/systemd/resolve/resolv.conf /etc/resolv.conf\n' >> "${ROOT}/root/init.sh"
printf 'exit\n' >> "${ROOT}/root/init.sh"

# /etc/fstab
printf 'tmpfs          /tmp     tmpfs rw,noatime,nodev,nosuid                                                                       0 0\n' > "${ROOT}/etc/fstab"
printf 'tmpfs          /dev/shm tmpfs rw,noatime,nodev,noexec,nosuid                                                                0 0\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p1 /boot    vfat  ro,noatime,nodev,noexec,nosuid                                                                0 2\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p2 /        ext4  ro,noatime,nodev,discard                                                                      0 1\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p3 /var     btrfs rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd,ssd,discard=async,subvol=/base    0 0\n' >> "${ROOT}/etc/fstab"

# /boot/cmdline.txt
printf 'root=/dev/mmcblk0p2 ro rootwait console=ttyAMA0,9600 kgdboc=ttyAMA0,9600 console=tty1 fsck.repair=yes quiet loglevel=2 audit=0 rd.systemd.show_status=auto rd.udev.log_priority=2\n' > "${ROOT}/boot/cmdline.txt"

# /boot/config.txt
printf '\ndtparam=audio=on\n' >> "${ROOT}/boot/config.txt"

# SYSCONFIG Files
export ROOT
export SYSCONFIG
if ! source "$(pwd)/config.sh"; then
    printf "\033[1;31mSourcing \033[0m\"config.sh\" \033[1;31mfailed!\033[0m\n" 1>&2
    cleanup 1
fi

# Fixing permissions
chmod 0444 "${ROOT}/etc/fstab"
chmod 0500 "${ROOT}/root/init.sh"
chmod 0444 "${ROOT}/etc/sysconfig.conf"
chmod 0555 -R "${ROOT}${SYSCONFIG_DIR}/bin"

print "Preperaring to chroot into \"${ROOT}\".."
exec "mount -o bind /dev ${ROOT}/dev"
exec "mount -o bind /sys ${ROOT}/sys"
exec "mount -o bind /proc ${ROOT}/proc"

if [ "$IS_AARCH64" -eq 1 ]; then
    exec "cp $(which qemu-aarch64-static) ${ROOT}/usr/bin/qemu-aarch64-static"
    printf ':arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-aarch64-static:\n' > /proc/sys/fs/binfmt_misc/register 2> /dev/null
else
    exec "cp $(which qemu-arm-static) ${ROOT}/usr/bin/qemu-arm-static"
    printf ':arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:\n' > /proc/sys/fs/binfmt_misc/register 2> /dev/null
fi

print "Running chroot init script.."
if ! chroot "${ROOT}" "/root/init.sh"; then
    printf "\033[1;33mChroot non-zero exit code!\033[0m\n"
fi

mount -o rw,remount "${ROOT}"
mount -o rw,remount "${ROOT}/boot"

print "Chroot Done, cleaning up.."
rm "${ROOT}/root/init.sh" 2> /dev/null
rm "${ROOT}/root/extra.sh" 2> /dev/null
rm "${ROOT}/usr/bin/qemu-arm-static" 2> /dev/null
rm "${ROOT}/usr/bin/qemu-aarch64-static" 2> /dev/null

awk '$5 > 2000' "${ROOT}/etc/ssh/moduli" > "${ROOT}/etc/ssh/moduli"
chmod 0400 "${ROOT}/etc/ssh/moduli"
chmod 0444 "${ROOT}/etc/resolv.conf"
find "${ROOT}" -type f -name "*.pacnew" -delete

lsof -n | grep "$ROOT" | awk '{print $2}' | xargs kill -9
sleep 5
umount "${ROOT}/sys"
umount "${ROOT}/dev"
umount "${ROOT}/proc"
sync

print "Done!"
cleanup
