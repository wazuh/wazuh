#!/bin/sh
# postinstall script for Solaris VMs
# Wazuh, Inc 2015

# install wazuh dependencies & some important packages

if [ "$(uname -v)" = "11.3" ]; then
  export PATH="${PATH}:/usr/sfw/bin:/opt/csw/bin"
else
  PATH="${PATH}:/usr/sbin:/usr/bin:/usr/sbin/:/opt/csw/gnu/:/usr/sfw/bin/:/opt/csw/bin/"
  export PATH
fi
yes | /usr/sbin/pkgadd -d http://get.opencsw.org/now all
/opt/csw/bin/pkgutil -U

#Download and install tools
pkgutil -y -i git
pkgutil -y -i gmake
pkgutil -y -i automake
pkgutil -y -i autoconf
pkgutil -y -i libtool
pkgutil -y -i wget
pkgutil -y -i curl
pkgutil -y -i gcc5core
pkgutil -y -i gcc5g++
pkgutil -y -i perl
pkgutil -y -i sudo
pkgutil -y -i git
pkgutil -y -i nano
rm /usr/bin/perl
mv /opt/csw/bin/perl5.10.1 /usr/bin/
mv /usr/bin/perl5.10.1 /usr/bin/perl

# Compile GCC-5.5 and CMake
curl -L http://packages.wazuh.com/utils/gcc/gcc-5.5.0.tar.gz | gtar xz
cd gcc-5.5.0
curl -L http://packages.wazuh.com/utils/gcc/mpfr-2.4.2.tar.bz2 | gtar xj
mv mpfr-2.4.2 mpfr
curl -L http://packages.wazuh.com/utils/gcc/gmp-4.3.2.tar.bz2 | gtar xj
mv gmp-4.3.2 gmp
curl -L http://packages.wazuh.com/utils/gcc/mpc-0.8.1.tar.gz | gtar xz
mv mpc-0.8.1 mpc
curl -L http://packages.wazuh.com/utils/gcc/isl-0.14.tar.bz2 | gtar xj
mv isl-0.14 isl
unset CPLUS_INCLUDE_PATH
unset LD_LIBRARY_PATH
# Fix for solaris 10/11
if [ "$(uname -v)" = "11.3" ]; then
  ./configure --prefix=/usr/local/gcc-5.5.0 --enable-languages=c,c++ --disable-multilib --disable-libsanitizer --disable-bootstrap --with-ld=/usr/ccs/bin/ld --without-gnu-ld --with-gnu-as --with-as=/opt/csw/bin/gas
  gmake -j$(nproc) && gmake install
  echo "export PATH=/usr/local/gcc-5.5.0/bin:/usr/local/bin:/opt/csw/bin:${PATH}" >> /etc/profile
  export PATH="/usr/local/gcc-5.5.0/bin:/usr/local/bin:/opt/csw/bin:${PATH}"
  export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0
  export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib
else
  ./configure --prefix=/usr/local/gcc-5.5.0 --enable-languages=c,c++ --disable-multilib --disable-libsanitizer --disable-bootstrap --with-gnu-as --with-as=/usr/sfw/bin/gas
  gmake -j$(nproc) && gmake install
  echo "export PATH=/usr/local/gcc-5.5.0/bin:${PATH}" >> /etc/profile
  PATH="/usr/local/gcc-5.5.0/bin:${PATH}"
  export PATH
  CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0/
  export CPLUS_INCLUDE_PATH
  LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib/
  export LD_LIBRARY_PATH
fi

echo "export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0" >> /etc/profile
echo "export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib" >> /etc/profile
rm -rf gcc-*

curl -sL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz | gtar xz
cd cmake-3.18.3
./bootstrap CC=/usr/local/gcc-5.5.0/bin/gcc CXX=/usr/local/gcc-5.5.0/bin/g++
gmake -j$(nproc) && gmake install
cd .. && rm -rf cmake-3.18.3
ln -s /usr/local/bin/cmake /usr/bin/cmake


# Adds vagrant user to the sudoers as a user that can run any command without being asked to introduce the password
# Read more: https://www.vagrantup.com/docs/boxes/base.html
echo 'vagrant ALL=(ALL) NOPASSWD: ALL' >> /etc/opt/csw/sudoers



# setup the vagrant key
# you can replace this key-pair with your own generated ssh key-pair
echo "Setting the vagrant ssh pub key"
mkdir /export/home/vagrant/.ssh
chmod 750 /export/home/vagrant/.ssh
touch /export/home/vagrant/.ssh/authorized_keys
if [ -f /usr/sfw/bin/wget ] ; then
  /usr/sfw/bin/wget --no-check-certificate https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub -O /export/home/vagrant/.ssh/authorized_keys
else
  wget --no-check-certificate https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub -O /export/home/vagrant/.ssh/authorized_keys
fi
chmod 600 /export/home/vagrant/.ssh/authorized_keys
chown -R vagrant:staff /export/home/vagrant/.ssh

ln -fs /opt/csw/bin/sudo /usr/bin/sudo
ln -fs /opt/csw/bin/sudo /bin/sudo


echo "Disabling sendmail and asr-norify"
# disable the very annoying sendmail
/usr/sbin/svcadm disable sendmail
/usr/sbin/svcadm disable asr-notify

echo "Clearing log files and zeroing disk, this might take a while"
cp /dev/null /var/adm/messages
cp /dev/null /var/log/syslog
cp /dev/null /var/adm/wtmpx
cp /dev/null /var/adm/utmpx
dd if=/dev/zero of=/EMPTY bs=1024 | true
rm -f /EMPTY

echo "Post-install done"
