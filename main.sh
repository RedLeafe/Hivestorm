#!/bin/bash

mkdir /opt/cache

cp /etc/passwd /opt/cache/passwd
cp /etc/group /opt/cache/group
cp /etc/shadow /opt/cache/shadow
cp /etc/sudoers /opt/cache/sudoers
cp /etc/group   /opt/cache/group
cp -r /var/log /opt/cache/log

if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if $( cat /etc/os-release | grep -qi Ubuntu ); then
        UBUNTU
    else
        DEBIAN
    fi
else
    echo "Unknown OS, cooked"
fi

UBUNTU() {
    DEBIAN
}

DEBIAN() {
    apt-get install libpam0g libpam-modules libpam-modules-bin libpam-runtime -y -qq
    apt-get install libpam-failock -y -qq
    apt-get install libpam-cracklib -y -qq

    cp Files/sudoers-DEBIAN /etc/sudoers
}

RHEL() {
    yum install pam pam-devel pam_cracklib -y -qq

    cp Files/sudoers-RHEL /etc/sudoers
}


# Passwords

pass=jbLXfs*^mr6oHaX

CHANGEPASSWORD() {
	BIN=$( which chpasswd || which passwd )
	if echo "$BIN" | grep -qi "chpasswd"; then
		CMD="echo \"$1:$2\" | $BIN"
	elif echo "$BIN" | grep -qi "passwd"; then
		CMD="printf \"$2\\n$2\\n\" | $BIN $1" 
	fi
	sh -c "$CMD" >/dev/null 2>&1
}

getent passwd {1000..10000} | cut -d: -f1 > user.txt
while read u; do
    CHANGEPASSWORD $u $pass
    printf "$u,$pass\n"
    #echo '$u:jbLXfs*^mr6oHaX' | chpasswd
    chage -d 0 -m 7 -M 90 -I 30 -W 14 "$u"
done<user.txt

passwd -l "root"

# Password Policy
cp /etc/login.defs /opt/cache/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs

cp /etc/security/pwquality.conf /opt/cache/pwquality.conf
cp Files/pwquality.conf /etc/security/pwquality.conf

cp /etc/pam.d/common-auth /opt/cache/common-auth
cp Files/common-auth /opt/cache/common-auth

cp /etc/pam.d/common-password /opt/cache/common-password
cp Files/common-password /etc/pam.d/common-password

# Sysctl
cp /etc/sysctl.conf /opt/cache/sysctl.conf
cp Files/sysctl.conf /etc/sysctl.conf

# Permissions and ownership for resolvconf and related files
chmod 755 /etc/resolvconf/resolv.conf.d/ && chown root:root /etc/resolvconf/resolv.conf.d/
chmod 644 /etc/resolvconf/resolv.conf.d/base && chown root:root /etc/resolvconf/resolv.conf.d/base
chmod 777 /etc/resolv.conf && chown root:root /etc/resolv.conf
chmod 644 /etc/hosts && chown root:root /etc/hosts
chmod 644 /etc/host.conf && chown root:root /etc/host.conf
chmod 644 /etc/hosts.deny && chown root:root /etc/hosts.deny

# APT configuration files
chmod 755 /etc/apt/ && chown root:root /etc/apt/
chmod 755 /etc/apt/apt.conf.d/ && chown root:root /etc/apt/apt.conf.d/
chmod 644 /etc/apt/apt.conf.d/10periodic && chown root:root /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/20auto-upgrades && chown root:root /etc/apt/apt.conf.d/20auto-upgrades
chmod 664 /etc/apt/sources.list && chown root:root /etc/apt/sources.list

# UFW configuration files
chmod 644 /etc/default/ufw && chown root:root /etc/default/ufw
chmod 755 /etc/ufw/ && chown root:root /etc/ufw/

# Sysctl configuration files
chmod 644 /etc/ufw/sysctl.conf && chown root:root /etc/ufw/sysctl.conf
chmod 755 /etc/sysctl.d/ && chown root:root /etc/sysctl.d/
chmod 644 /etc/sysctl.conf && chown root:root /etc/sysctl.conf
chmod 644 /proc/sys/net/ipv4/ip_forward && chown root:root /proc/sys/net/ipv4/ip_forward

# User and group files
chmod 644 /etc/passwd && chown root:root /etc/passwd
chmod 640 /etc/shadow && chown root:shadow /etc/shadow
chmod 644 /etc/group && chown root:root /etc/group
chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow
chmod 755 /etc/sudoers.d/ && chown root:root /etc/sudoers.d/
chmod 440 /etc/sudoers.d/* && chown root:root /etc/sudoers.d/*
chmod 440 /etc/sudoers && chown root:root /etc/sudoers
chmod 644 /etc/deluser.conf && chown root:root /etc/deluser.conf
chmod 644 /etc/adduser.conf && chown root:root /etc/adduser.conf
chmod 664 /etc/lightdm/lightdm.conf && chown root:root /etc/lightdm/lightdm.conf

# Password policy
chmod 644 /etc/login.defs && chown root:root /etc/login.defs
chmod 644 /etc/pam.d/common-auth && chown root:root /etc/pam.d/common-auth
chmod 644 /etc/pam.d/common-password && chown root:root /etc/pam.d/common-password

# Potential backdoors
chmod og-rwx /etc/anacrontab && chown root:root /etc/anacrontab
chmod og-rwx -R /etc/cron* && chown root:root /etc/cron*
chmod og-rwx /etc/crontab && chown root:root /etc/crontab
chmod og-rwx /var/spool/cron/crontabs && chown root:root /var/spool/cron/crontabs
chmod 755 /etc/rc.local && chown root:root /etc/rc.local
chmod -R 755 /var/www/html

# GRUB configuration
chmod 755 /etc/grub.d/ && chown root:root /etc/grub.d/
chmod og-rwx /boot/grub/grub.cfg && chown root:root /boot/grub/grub.cfg

# SELinux
chmod 644 /etc/securetty && chown root:root /etc/securetty
chmod 644 /etc/security/limits.conf && chown root:root /etc/security/limits.conf
chmod 664 /etc/fstab && chown root:root /etc/fstab
chmod 644 /etc/updatedb.conf && chown root:root /etc/updatedb.conf
chmod 644 /etc/modprobe.d/blacklist.conf && chown root:root /etc/modprobe.d/blacklist.conf
chmod 644 /etc/environment && chown root:root /etc/environment

# Main directories
chmod 755 /etc && chown root:root /etc
chmod 755 /bin && chown root:root /bin
chmod 755 /boot && chown root:root /boot
chmod 775 /cdrom && chown root:root /cdrom
chmod 755 /dev && chown root:root /dev
chmod 755 /home && chown root:root /home
chmod 755 /lib && chown root:root /lib
chmod 755 /media && chown root:root /media
chmod 755 /mnt && chown root:root /mnt
chmod 755 /opt && chown root:root /opt
chmod 555 /proc && chown root:root /proc
chmod 700 /root && chown root:root /root
chmod 755 /run && chown root:root /run
chmod 755 /sbin && chown root:root /sbin
chmod 755 /snap && chown root:root /snap
chmod 755 /srv && chown root:root /srv
chmod 555 /sys && chown root:root /sys
chmod 1777 /tmp && chown root:root /tmp
chmod 755 /usr && chown root:root /usr
chmod 755 /var && chown root:root /var
chmod -R g-wx,o-rwx /var/log/* && chown root:root /var/log/*

# /etc/fstab
echo 'none /tmp tmpfs rw,noexec,nosuid,nodev 0 0' >> /etc/fstab
echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab

# remove rysnc
apt remove rsync
apt-get --purge autoremove