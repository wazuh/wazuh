#!/usr/bin/env bash
#
# Create a base CentOS Docker image.
#
# This script is useful on systems with yum installed (e.g., building
# a CentOS image on CentOS).  See contrib/mkimage-rinse.sh for a way
# to build CentOS images on other systems.

set -e

# Configuration options
groups=("Core" "Development tools")
name="centos-5-i386"
target=$(mktemp -d /tmp/mkimage-yum.XXXXXX)
yum_config="/etc/yum.conf"

packages=("sudo" "ca-certificates" "make" "gcc" "curl" "initscripts" \
          "tar" "rpm-build" "automake" "autoconf" "libtool" "wget" \
          "libselinux" "devicemapper" "libselinux-python" "krb5-libs" \
          "policycoreutils" "checkpolicy" "zlib-devel" "bzip2-devel" \
          "openssl-devel" "ncurses-devel" "setarch")
set -x

# Create the directories
mkdir -m 755 "$target"/dev
mknod -m 600 "$target"/dev/console c 5 1
mknod -m 600 "$target"/dev/initctl p
mknod -m 666 "$target"/dev/full c 1 7
mknod -m 666 "$target"/dev/null c 1 3
mknod -m 666 "$target"/dev/ptmx c 5 2
mknod -m 666 "$target"/dev/random c 1 8
mknod -m 666 "$target"/dev/tty c 5 0
mknod -m 666 "$target"/dev/tty0 c 4 0
mknod -m 666 "$target"/dev/urandom c 1 9
mknod -m 666 "$target"/dev/zero c 1 5

# Install the groups
yum -c "$yum_config" --installroot="$target" -y groupinstall "$groups"

# Copy the repository file
rm -f "$target"/etc/yum.repos.d/*
cp -p /etc/yum.repos.d/CentOS-Base.repo "$target"/etc/yum.repos.d/CentOS-Base.repo

# Install the packages
for i in "${packages[@]}"
do
    yum -c "$yum_config" --installroot="$target" -y install "$i"
done
yum -c "$yum_config" --installroot="$target" -y clean all

# Install perl 5.10
wget http://packages.wazuh.com/utils/perl/perl-5.10.1.tar.gz
gunzip perl-5.10.1.tar.gz && tar -xvf perl*.tar
cd perl-5.10.1 && ./Configure -des -Dcc='gcc' -Dprefix="$target"/usr/local
make && make install && ln -fs "$target"/usr/local/bin/perl "$target"/bin/perl
cd .. && rm -rf perl-5.10.1

cat > "$target"/etc/sysconfig/network <<EOF
NETWORKING=yes
HOSTNAME=localhost.localdomain
EOF

# effectively: febootstrap-minimize --keep-zoneinfo --keep-rpmdb --keep-services "$target".
#  docs and man pages
rm -rf "$target"/usr/share/{man,doc,info,gnome/help}
#  cracklib
rm -rf "$target"/usr/share/cracklib
#  i18n
rm -rf "$target"/usr/share/i18n
#  yum cache
rm -rf "$target"/var/cache/yum
mkdir -p --mode=0755 "$target"/var/cache/yum
#  sln
rm -rf "$target"/sbin/sln
#  ldconfig
rm -rf "$target"/etc/ld.so.cache "$target"/var/cache/ldconfig
mkdir -p --mode=0755 "$target"/var/cache/ldconfig

version=
if [ -r "$target"/etc/redhat-release ]; then
    version="$(sed 's/^[^0-9\]*\([0-9.]\+\).*$/\1/' "$target"/etc/redhat-release)"
fi

if [ -z "$version" ]; then
    echo >&2 "warning: cannot autodetect OS version, using '$name' as tag"
    version=$name
fi

tar --numeric-owner -c -C "$target" -zf /vagrant/$name.tar.gz .

rm -rf "$target"
