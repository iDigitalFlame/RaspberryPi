#!/usr/bin/bash
# Copyright 2021 - 2023 iDigitalFlame
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

source "/etc/sysconfig.conf" || exit 1

# Create file "/etc/dnsmasq.conf"
printf 'no-poll\nno-ping\nbind-dynamic\nexpand-hosts\ndnssec-no-timecheck\n\nport            = ' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf '53\nuser            = dnsmasq\ngroup           = dnsmasq\nlocal           = /usb/\nd' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf 'omain          = usb,10.1.10.1/30\naddress         = /zero.usb/10.1.10.1\naddress ' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf '        = /zero/10.1.10.1\ninterface       = usb0\ndhcp-range      = 10.1.10.2,10.' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf '1.10.2,255.255.255.252,1m\nresolv-file     = /etc/resolv.conf\ndhcp-option     = v' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf 'endor:MSFT,2,1i\ndhcp-option     = option:router,10.1.10.1\ndhcp-option     = opti' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf 'on:domain-search,usb\ndhcp-option     = option:domain-name,zero.usb\nlisten-addres' >> "${SYSCONFIG}/etc/dnsmasq.conf"
printf 's  = 10.1.10.1\ndhcp-lease-max  = 1\ndhcp-leasefile  = /dev/null\n' >> "${SYSCONFIG}/etc/dnsmasq.conf"

# Create file "/etc/profile.d/proxy.sh"
printf '#!/usr/bin/bash\n\nexport http_proxy="http://host.usb:8050/"\nexport https_proxy' > "${SYSCONFIG}/etc/profile.d/proxy.sh"
printf '="http://host.usb:8050/"\nexport no_proxy="localhost,127.0.0.1,localaddress,.loc' >> "${SYSCONFIG}/etc/profile.d/proxy.sh"
printf 'aldomain.com,.usb"\n' >> "${SYSCONFIG}/etc/profile.d/proxy.sh"

# Create file "/etc/systemd/network/usb0.network"
printf '[Match]\nType                    = gadget\n\n[Link]\nActivationPolicy        = a' > "${SYSCONFIG}/etc/systemd/network/usb0.network"
printf 'lways-up\n\n[Network]\nDNS                     = 10.1.10.2\nAddress             ' >> "${SYSCONFIG}/etc/systemd/network/usb0.network"
printf '    = 10.1.10.1/30\nIPv6AcceptRA            = no\nLinkLocalAddressing     = no\n' >> "${SYSCONFIG}/etc/systemd/network/usb0.network"
printf '\n[Route]\nGateway                 = 10.1.10.1\n' >> "${SYSCONFIG}/etc/systemd/network/usb0.network"

# Create file "/etc/syscheck.d/perms.sh"
printf '#!/usr/bin/bash\n\nchmod -R 0550 "/etc/modprobe.d" 2> /dev/null\nchmod -R 0550 "/op' >> "${SYSCONFIG}/etc/syscheck.d/perms.sh"
printf 't/sysconfig/etc/modprobe.d" 2> /dev/null\nfind "/etc/modprobe.d" -type f -exec ch' >> "${SYSCONFIG}/etc/syscheck.d/perms.sh"
printf 'mod 0440 {} \\; 2> /dev/null\n' >> "${SYSCONFIG}/etc/syscheck.d/perms.sh"

# Update file "/etc/sysctl.d/ipv6.conf"
printf 'net.ipv6.conf.all.use_tempaddr      = 1\nnet.ipv6.conf.usb0.disable_ipv6     = 1' > "${SYSCONFIG}/etc/sysctl.d/ipv6.conf"
printf '\nnet.ipv6.conf.all.accept_redirects  = 0\n' >> "${SYSCONFIG}/etc/sysctl.d/ipv6.conf"

# Update file "/etc/hostname"
printf 'zero' > "${SYSCONFIG}/etc/hostname"

# Update file "/etc/hosts"
printf '::1         localhost.local     localhost\n127.0.0.1   localhost.local     localhost\n' > "${SYSCONFIG}/etc/hosts"
printf '10.1.10.2   host.usb            host\n10.1.10.1   zero.usb            zero\n' >> "${SYSCONFIG}/etc/hosts"

sed -i'' -e 's/ 0.0.0.0/ 10.1.10.1/g' "${SYSCONFIG}/etc/ssh/sshd_config"
sed -i'' -e 's/time-b-g.nist.gov/host.usb/g' "${SYSCONFIG}/etc/systemd/timesyncd.conf"

pacman -S dnsmasq --noconfirm
mount -o rw,remount /

systemctl disable systemd-resolved
rm /etc/systemd/system/multi-user.target.wants/systemd-resolved.service 2> /dev/null
rm /etc/systemd/system/dbus-org.freedesktop.resolve1.service 2> /dev/null
systemctl enable dnsmasq.service

rm -f /etc/resolv.conf 2> /dev/null
rm -rf /var/run/systemd/resolve 2> /dev/null
printf 'nameserver 10.1.10.1\nsearch rpi.usb\n' > "${SYSCONFIG}/etc/resolv.conf"
chmod 0444 "${SYSCONFIG}/etc/resolv.conf"
chmod 0444 "/etc/resolv.conf"

mount -o rw,remount /
mount -o rw,remount /boot

_mac=$(printf '%x%x:%x%x:%x%x' $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)))

mkdir "${SYSCONFIG}/etc/modprobe.d"
printf "options g_ether host_addr=be:ef:ed:%s dev_addr=%s\n" "$_mac" "$_mac" > "${SYSCONFIG}/etc/modprobe.d/gadget.conf"

printf 'dtoverlay=dwc2\n' > "/boot/config.txt"
sed -i'' -e "s/log_priority=2/log_priority=2 modules-load=dwc2,g_ether g_ether.host_addr=be:ef:ed:${_mac} g_ether.dev_addr=${_mac}/g" "/boot/cmdline.txt"

syslink
