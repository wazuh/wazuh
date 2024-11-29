%if %{_isstage} == no
  %define _rpmfilename %%{NAME}_%%{VERSION}-%%{RELEASE}_%%{ARCH}_%{_hashcommit}.rpm
%else
  %define _rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm
%endif

Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-server
Version:     %{_version}
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(postun): /usr/sbin/groupdel /usr/sbin/userdel
AutoReqProv: no

Requires: coreutils
BuildRequires: coreutils glibc-devel automake autoconf libtool policycoreutils-python curl perl

ExclusiveOS: linux

%define _source_payload w9.xzdio
%define _binary_payload w9.xzdio

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

# Don't generate build_id links to prevent conflicts with other
# packages.
%global _build_id_links none

# Build debuginfo package
%debug_package
%package wazuh-server-debuginfo
Summary: Debug information for package %{name}.
%description wazuh-server-debuginfo
This package provides debug information for package %{name}.

%prep
%setup -q
%build
%install
# Clean BUILDROOT
rm -fr %{buildroot}
echo 'VCPKG_ROOT="/root/vcpkg"' > ./etc/preloaded-vars.conf
echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_INSTALL_TYPE="server"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="%{_localstatedir}"' >> ./etc/preloaded-vars.conf
echo 'USER_DELETE_DIR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_UPDATE="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_EMAIL="n"' >> ./etc/preloaded-vars.conf
echo 'USER_WHITE_LIST="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSLOG="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_AUTHD="y"' >> ./etc/preloaded-vars.conf
echo 'USER_SERVER_IP="MANAGER_IP"' >> ./etc/preloaded-vars.conf
echo 'USER_CA_STORE="/path/to/my_cert.pem"' >> ./etc/preloaded-vars.conf
echo 'USER_GENERATE_AUTHD_CERT="y"' >> ./etc/preloaded-vars.conf
echo 'USER_AUTO_START="n"' >> ./etc/preloaded-vars.conf
echo 'USER_CREATE_SSL_CERT="n"' >> ./etc/preloaded-vars.conf
echo 'DOWNLOAD_CONTENT="y"' >> ./etc/preloaded-vars.conf
export VCPKG_ROOT="/root/vcpkg"
export PATH="${PATH}:${VCPKG_ROOT}"
scl enable devtoolset-11 ./install.sh

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}

# Copy the installed files into RPM_BUILD_ROOT directory
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}tmp/
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}run/wazuh-server
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}var/lib/wazuh-server
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}usr/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}var/log
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/wazuh-server
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/wazuh-server/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}etc/wazuh-server

cp -p %{_localstatedir}usr/share/wazuh-server/bin/wazuh-engine ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/wazuh-server/bin/
cp -p %{_localstatedir}usr/share/wazuh-server/bin/wazuh-apid ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/wazuh-server/bin/
cp -p %{_localstatedir}usr/share/wazuh-server/bin/wazuh-comms-apid ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/wazuh-server/bin/
cp -p %{_localstatedir}usr/share/wazuh-server/bin/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/wazuh-server/bin/

cp -pr %{_localstatedir}tmp/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}tmp/
cp -pr %{_localstatedir}run/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}run/
cp -pr %{_localstatedir}var/lib/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}var/lib/
cp -pr %{_localstatedir}var/log/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}var/log/
cp -pr %{_localstatedir}usr/share/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}usr/share/
cp -pr %{_localstatedir}etc/wazuh-server ${RPM_BUILD_ROOT}%{_localstatedir}etc/

sed -i "s:WAZUH_HOME_TMP:%{_localstatedir}:g" src/init/templates/wazuh-server-rh.init
install -m 0755 src/init/templates/wazuh-server-rh.init ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-server

mkdir -p ${RPM_BUILD_ROOT}/usr/lib/systemd/system/
sed -i "s:WAZUH_HOME_TMP:%{_localstatedir}:g" src/init/templates/wazuh-server.service
install -m 0644 src/init/templates/wazuh-server.service ${RPM_BUILD_ROOT}/usr/lib/systemd/system/

%{_rpmconfigdir}/find-debuginfo.sh

%pre

# Create the wazuh group if it doesn't exists
if command -v getent > /dev/null 2>&1 && ! getent group wazuh > /dev/null 2>&1; then
  groupadd -r wazuh
elif ! getent group wazuh > /dev/null 2>&1; then
  groupadd -r wazuh
fi

# Create the wazuh user if it doesn't exists
if ! getent passwd wazuh > /dev/null 2>&1; then
  useradd -g wazuh -G wazuh -d %{_localstatedir} -r -s /sbin/nologin wazuh
fi

# Stop the services to upgrade the package
if [ $1 = 2 ]; then
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-server > /dev/null 2>&1; then
    systemctl stop wazuh-server.service > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-server status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-server stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  else
    echo "Unable to stop wazuh-server. Neither systemctl nor service are available."
  fi
fi

%post

%define _vdfilename vd_1.0.0_vd_4.10.0.tar.xz

if [[ -d /run/systemd/system ]]; then
  rm -f %{_initrddir}/wazuh-server
fi

%preun

if [ $1 = 0 ]; then

  # Stop the services before uninstall the package
  # Check for systemd
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-server > /dev/null 2>&1; then
    systemctl stop wazuh-server.service > /dev/null 2>&1
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-server status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-server stop > /dev/null 2>&1
  else
    echo "Unable to stop wazuh-server. Neither systemctl nor service are available."
  fi
fi

%postun

# If the package is been uninstalled
if [ $1 = 0 ];then
  # Remove the wazuh user if it exists
  if getent passwd wazuh > /dev/null 2>&1; then
    userdel wazuh >/dev/null 2>&1
  fi
  # Remove the wazuh group if it exists
  if command -v getent > /dev/null 2>&1 && getent group wazuh > /dev/null 2>&1; then
    groupdel wazuh >/dev/null 2>&1
  elif getent group wazuh > /dev/null 2>&1; then
    groupdel wazuh >/dev/null 2>&1
  fi

  # Remove lingering folders and files
  rm -rf %{_localstatedir}tmp/wazuh-server
  rm -rf %{_localstatedir}usr/bin/wazuh-engine
  rm -rf %{_localstatedir}usr/bin/wazuh-apid
  rm -rf %{_localstatedir}usr/bin/wazuh-comms-apid
  rm -rf %{_localstatedir}usr/bin/wazuh-server
  rm -rf %{_localstatedir}run/wazuh-server
  rm -rf %{_localstatedir}var/lib/wazuh-server
  rm -rf %{_localstatedir}usr/share/wazuh-server
  rm -rf %{_localstatedir}etc/wazuh-server
fi

# posttrans code is the last thing executed in a install/upgrade
%posttrans
if [ -f %{_sysconfdir}/systemd/system/wazuh-server.service ]; then
  rm -rf %{_sysconfdir}/systemd/system/wazuh-server.service
  systemctl daemon-reload > /dev/null 2>&1
fi

if [ -f %{_localstatedir}/tmp/wazuh.restart ]; then
  rm -f %{_localstatedir}/tmp/wazuh.restart
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
    systemctl daemon-reload > /dev/null 2>&1
    systemctl restart wazuh-server.service > /dev/null 2>&1
  elif command -v service > /dev/null 2>&1 ; then
    service wazuh-server restart > /dev/null 2>&1
  fi
fi

chown -R root:wazuh %{_localstatedir}var/lib/wazuh-server
find %{_localstatedir}var/lib/wazuh-server -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;
chown -R root:wazuh %{_localstatedir}var/log/wazuh-server
find %{_localstatedir}var/log/wazuh-server -type d -exec chmod 755 {} \; -o -type f -exec chmod 644 {} \;
chown -R root:wazuh %{_localstatedir}usr/share/wazuh-server
find %{_localstatedir}usr/share/wazuh-server -type d -exec chmod 755 {} \; -o -type f -exec chmod 644 {} \;
chown -R root:wazuh %{_localstatedir}etc/wazuh-server
find %{_localstatedir}etc/wazuh-server -type d -exec chmod 755 {} \; -o -type f -exec chmod 644 {} \;

# Fix Python permissions
chmod -R 0750 %{_localstatedir}usr/share/wazuh-server/framework/python/bin

# Fix binaries permissions
chmod -R 0750 %{_localstatedir}usr/share/wazuh-server/bin

%triggerin -- glibc

%clean
rm -fr %{buildroot}

%files
%defattr(-,root,wazuh)
%dir %attr(750, root, wazuh) %{_localstatedir}run/wazuh-server
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server/vd
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server/engine
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server/engine/tzdb
%dir %attr(750, root, wazuh) %{_localstatedir}var/log/wazuh-server
%dir %attr(750, root, wazuh) %{_localstatedir}var/log/wazuh-server/engine
%dir %attr(750, root, wazuh) %{_localstatedir}etc/wazuh-server
%dir %attr(750, root, wazuh) %{_localstatedir}etc/wazuh-server/api
%dir %attr(750, root, wazuh) %{_localstatedir}etc/wazuh-server/cluster
%dir %attr(750, root, wazuh) %{_localstatedir}etc/wazuh-server/shared
%dir %attr(750, root, wazuh) %{_localstatedir}run/wazuh-server/cluster
%dir %attr(750, root, wazuh) %{_localstatedir}run/wazuh-server/socket
%dir %attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/lib
%dir %attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/framework
%dir %attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/api
%dir %attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/apis
%{_localstatedir}var/lib/wazuh-server/engine/tzdb/*
%{_localstatedir}etc/wazuh-server/*
%{_localstatedir}usr/share/wazuh-server/lib/*
%{_localstatedir}usr/share/wazuh-server/framework/*
%{_localstatedir}usr/share/wazuh-server/api/*
%{_localstatedir}usr/share/wazuh-server/apis/*
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server/engine/store
%{_localstatedir}var/lib/wazuh-server/engine/store/*
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server/engine/kvdb
%{_localstatedir}var/lib/wazuh-server/engine/kvdb/*
%dir %attr(750, root, wazuh) %{_localstatedir}var/lib/wazuh-server/indexer-connector

%attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/bin/wazuh-engine
%attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/bin/wazuh-apid
%attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/bin/wazuh-comms-apid
%attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/bin/wazuh-server
# This will be correctly added in #26936
%attr(750, root, wazuh) %{_localstatedir}usr/share/wazuh-server/bin/rbac_control
%attr(640, root, wazuh) %{_localstatedir}tmp/wazuh-server/vd_1.0.0_vd_4.10.0.tar.xz

%config(missingok) %{_initrddir}/wazuh-server
/usr/lib/systemd/system/wazuh-server.service

%changelog
* Mon Jun 2 2025 support <info@wazuh.com> - 5.0.0
- More info: https://documentation.wazuh.com/current/release-notes/release-5-0-0.html
