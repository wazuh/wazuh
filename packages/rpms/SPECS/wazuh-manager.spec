%if %{_isstage} == no
  %define _rpmfilename %%{NAME}_%%{VERSION}-%%{RELEASE}_%%{ARCH}_%{_hashcommit}.rpm
%else
  %define _rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm
%endif

Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-manager
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
Conflicts:   ossec-hids ossec-hids-agent wazuh-agent wazuh-local
Obsoletes: wazuh-api < 4.0.0
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
%package -n wazuh-manager-debuginfo
Requires: wazuh-manager = %{_version}-%{_release}
Summary: Debug information for package %{name}.
%description -n wazuh-manager-debuginfo
This package provides debug information for package %{name}.


%prep
%setup -q

./gen_ossec.sh conf manager centos %rhel %{_localstatedir} > etc/ossec-server.conf

%build
pushd src
# Rebuild for server
make clean

# Build Wazuh sources
make deps TARGET=server
make -j%{_threads} TARGET=server USE_SELINUX=yes DEBUG=%{_debugenabled}

popd

%install
# Clean BUILDROOT
rm -fr %{buildroot}

echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_INSTALL_TYPE="server"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="%{_localstatedir}"' >> ./etc/preloaded-vars.conf
echo 'USER_DELETE_DIR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ACTIVE_RESPONSE="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ROOTCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_OPENSCAP="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_CISCAT="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCOLLECTOR="y"' >> ./etc/preloaded-vars.conf
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
./install.sh || { echo "install.sh failed! Aborting." >&2; exit 1; }

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/.ssh

# Copy the installed files into RPM_BUILD_ROOT directory
cp -pr %{_localstatedir}/* ${RPM_BUILD_ROOT}%{_localstatedir}/
sed -i "s:WAZUH_HOME_TMP:%{_localstatedir}:g" src/init/templates/ossec-hids-rh.init
install -m 0755 src/init/templates/ossec-hids-rh.init ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-manager
mkdir -p ${RPM_BUILD_ROOT}/usr/lib/systemd/system/
sed -i "s:WAZUH_HOME_TMP:%{_localstatedir}:g" src/init/templates/wazuh-manager.service
install -m 0644 src/init/templates/wazuh-manager.service ${RPM_BUILD_ROOT}/usr/lib/systemd/system/

# Clean the preinstalled configuration assesment files
rm -f ${RPM_BUILD_ROOT}%{_localstatedir}/ruleset/sca/*

# Add configuration scripts
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/
cp gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/
cp add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/centos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/rhel
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/suse
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/sles

# Install configuration assesment files and files templates
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/{applications,generic}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/{1,2,2023}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/{10,9,8,7,6,5}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/{15,16,17,18,19,20,21,22,23,24}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/{7,8,9,10,11,12}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/{9,10}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/{12,14,16,18,20,22,24}/04
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/{10,9,8,7,6,5}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/{11,12,15}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/{11,12}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sunos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/windows
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/{29,30,31,32,33,34,41}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux/{8,9,10}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky/{8,9,10}

cp -r ruleset/sca/{applications,generic,mongodb,nginx,oracledb,centos,darwin,debian,ol,rhel,sles,sunos,windows,amazon,ubuntu,rocky,almalinux} ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp

cp etc/templates/config/generic/{sca.files,sca.manager.files} ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/generic

cp etc/templates/config/amzn/1/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/1
cp etc/templates/config/amzn/2/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2
cp etc/templates/config/amzn/2023/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2023

cp etc/templates/config/centos/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos
cp etc/templates/config/centos/10/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/10
cp etc/templates/config/centos/9/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/9
cp etc/templates/config/centos/8/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/8
cp etc/templates/config/centos/7/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/7
cp etc/templates/config/centos/6/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/6
cp etc/templates/config/centos/5/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/5

cp etc/templates/config/ol/9/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/9
cp etc/templates/config/ol/10/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/10

cp etc/templates/config/rhel/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel
cp etc/templates/config/rhel/10/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/10
cp etc/templates/config/rhel/9/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/9
cp etc/templates/config/rhel/8/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/8
cp etc/templates/config/rhel/7/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/7
cp etc/templates/config/rhel/6/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/6
cp etc/templates/config/rhel/5/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/5

cp etc/templates/config/sles/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles
cp etc/templates/config/sles/11/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/11
cp etc/templates/config/sles/12/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/12
cp etc/templates/config/sles/15/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/15

cp etc/templates/config/suse/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse
cp etc/templates/config/suse/11/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/11
cp etc/templates/config/suse/12/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/12

cp etc/templates/config/fedora/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora
cp etc/templates/config/fedora/29/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/29
cp etc/templates/config/fedora/30/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/30
cp etc/templates/config/fedora/31/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/31
cp etc/templates/config/fedora/32/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/32
cp etc/templates/config/fedora/33/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/33
cp etc/templates/config/fedora/34/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/34
cp etc/templates/config/fedora/41/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/41

cp etc/templates/config/almalinux/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux
cp etc/templates/config/almalinux/8/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux/8
cp etc/templates/config/almalinux/9/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux/9
cp etc/templates/config/almalinux/10/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux/10

cp etc/templates/config/rocky/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky
cp etc/templates/config/rocky/8/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky/8
cp etc/templates/config/rocky/9/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky/9
cp etc/templates/config/rocky/10/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky/10

# Add SUSE initscript
sed -i "s:WAZUH_HOME_TMP:%{_localstatedir}:g" src/init/templates/ossec-hids-suse.init
cp -rp src/init/templates/ossec-hids-suse.init ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/src/init/

# Copy scap templates
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/generic
cp -rp  etc/templates/config/centos/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/centos
cp -rp  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/rhel

install -m 0440 VERSION.json ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/
install -m 0640 src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/manager_installation_scripts/src/init

rm ${RPM_BUILD_ROOT}%{_localstatedir}/lib/modern.bpf.o
%{_rpmconfigdir}/find-debuginfo.sh
cp %{_localstatedir}/lib/modern.bpf.o ${RPM_BUILD_ROOT}%{_localstatedir}/lib

exit 0

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
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-manager > /dev/null 2>&1; then
    systemctl stop wazuh-manager.service > /dev/null 2>&1
    %{_localstatedir}/bin/ossec-control stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-manager status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-manager stop > /dev/null 2>&1
    %{_localstatedir}/bin/ossec-control stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  elif %{_localstatedir}/bin/wazuh-control status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    touch %{_localstatedir}/tmp/wazuh.restart
  elif %{_localstatedir}/bin/ossec-control status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    touch %{_localstatedir}/tmp/wazuh.restart
  fi
  %{_localstatedir}/bin/ossec-control stop > /dev/null 2>&1 || %{_localstatedir}/bin/wazuh-control stop > /dev/null 2>&1
fi
if pgrep -f ossec-authd > /dev/null 2>&1; then
    kill -15 $(pgrep -f ossec-authd)
fi

# Remove/relocate existing SQLite databases
rm -f %{_localstatedir}/var/db/cluster.db* || true
rm -f %{_localstatedir}/var/db/.profile.db* || true
rm -rf %{_localstatedir}/var/db/agents || true

if [ -f %{_localstatedir}/var/db/global.db ]; then
  mv %{_localstatedir}/var/db/global.db %{_localstatedir}/queue/db/
  rm -f %{_localstatedir}/var/db/global.db* || true
  rm -f %{_localstatedir}/var/db/.template.db || true
fi

if [ -f %{_localstatedir}/queue/db/global.db ]; then
  chmod 640 %{_localstatedir}/queue/db/global.db*
  chown wazuh:wazuh %{_localstatedir}/queue/db/global.db*
fi

# Remove Vuln-detector database
rm -f %{_localstatedir}/queue/vulnerabilities/cve.db || true

# Remove plain-text agent information if exists
if [ -d %{_localstatedir}/queue/agent-info ]; then
  rm -rf %{_localstatedir}/queue/agent-info/* > /dev/null 2>&1
fi

if [ -d %{_localstatedir}/queue/rootcheck ]; then
  rm -rf %{_localstatedir}/queue/rootcheck/* > /dev/null 2>&1
fi

# Delete old API backups
if [ $1 = 2 ]; then
  if [ -d %{_localstatedir}/~api ]; then
    rm -rf %{_localstatedir}/~api
  fi

  if [ -f %{_sysconfdir}/ossec-init.conf ]; then
    # Import the variables from ossec-init.conf file
    . %{_sysconfdir}/ossec-init.conf
  else
    # Ask wazuh-control the version
    VERSION=$(%{_localstatedir}/bin/wazuh-control info -v)
  fi

  # Get the major and minor version
  MAJOR=$(echo $VERSION | cut -dv -f2 | cut -d. -f1)
  MINOR=$(echo $VERSION | cut -d. -f2)

  # Delete uncompatible DBs versions
  if [ $MAJOR = 3 ] && [ $MINOR -lt 7 ]; then
    rm -f %{_localstatedir}/queue/db/*.db*
    rm -f %{_localstatedir}/queue/db/.template.db
  fi

  # Delete 3.X Wazuh API service
  if [ "$MAJOR" = "3" ] && [ -d %{_localstatedir}/api ]; then
    if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
      systemctl stop wazuh-api.service > /dev/null 2>&1
      systemctl disable wazuh-api.service > /dev/null 2>&1
      rm -f /etc/systemd/system/wazuh-api.service
    elif command -v service > /dev/null 2>&1 && command -v chkconfig > /dev/null 2>&1; then
      service wazuh-api stop > /dev/null 2>&1
      chkconfig wazuh-api off > /dev/null 2>&1
      chkconfig --del wazuh-api > /dev/null 2>&1
      rm -f /etc/rc.d/init.d/wazuh-api || true
    fi
  fi
fi

%post

echo "VERSION=\"$(%{_localstatedir}/bin/wazuh-control info -v)\"" > /etc/ossec-init.conf

# Upgrade install code block
if [ $1 = 2 ]; then
  if [ -d %{_localstatedir}/logs/ossec ]; then
    rm -rf %{_localstatedir}/logs/wazuh
    cp -rp %{_localstatedir}/logs/ossec %{_localstatedir}/logs/wazuh
  fi

  if [ -d %{_localstatedir}/queue/ossec ]; then
    rm -rf %{_localstatedir}/queue/sockets
    cp -rp %{_localstatedir}/queue/ossec %{_localstatedir}/queue/sockets
  fi

  FILE_PATH="%{_localstatedir}/packages_files/manager_installation_scripts/src/init/update-indexer.sh"
  if [ -f "$FILE_PATH" ]; then
    CONFIG_INDEXER_TEMPLATE="%{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/generic/wodle-indexer.manager.template"
    . "$FILE_PATH"
    updateIndexerTemplate "%{_localstatedir}/etc/ossec.conf" $CONFIG_INDEXER_TEMPLATE
  fi
fi

%define _vdfilename vd_1.0.0_vd_4.13.0.tar.xz

# Fresh install code block
if [ $1 = 1 ]; then

  . %{_localstatedir}/packages_files/manager_installation_scripts/src/init/dist-detect.sh

  # Generating ossec.conf file
  %{_localstatedir}/packages_files/manager_installation_scripts/gen_ossec.sh conf manager ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir} > %{_localstatedir}/etc/ossec.conf

  touch %{_localstatedir}/logs/active-responses.log
  touch %{_localstatedir}/logs/integrations.log
  chown wazuh:wazuh %{_localstatedir}/logs/active-responses.log
  chown wazuh:wazuh %{_localstatedir}/logs/integrations.log
  chmod 0660 %{_localstatedir}/logs/active-responses.log
  chmod 0640 %{_localstatedir}/logs/integrations.log

  # Add default local_files to ossec.conf
  %{_localstatedir}/packages_files/manager_installation_scripts/add_localfiles.sh %{_localstatedir} >> %{_localstatedir}/etc/ossec.conf
fi

if [[ -d /run/systemd/system ]]; then
  rm -f %{_initrddir}/wazuh-manager
fi

# Generation auto-signed certificate if not exists
if [ ! -f "%{_localstatedir}/etc/sslmanager.key" ] && [ ! -f "%{_localstatedir}/etc/sslmanager.cert" ]; then
  %{_localstatedir}/bin/wazuh-authd -C 365 -B 2048 -S "/C=US/ST=California/CN=Wazuh/" -K %{_localstatedir}/etc/sslmanager.key -X %{_localstatedir}/etc/sslmanager.cert 2>/dev/null
  chmod 640 %{_localstatedir}/etc/sslmanager.key
  chmod 640 %{_localstatedir}/etc/sslmanager.cert
fi

rm -f %{_localstatedir}/etc/shared/ar.conf  >/dev/null 2>&1
rm -f %{_localstatedir}/etc/shared/merged.mg  >/dev/null 2>&1

# Set merged.mg permissions to new ones
find %{_localstatedir}/etc/shared/ -type f -name 'merged.mg' -exec chmod 644 {} \;

#AlmaLinux
if [ -r "/etc/almalinux-release" ]; then
  DIST_NAME=almalinux
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/almalinux-release`
#Rocky
elif [ -r "/etc/rocky-release" ]; then
  DIST_NAME=rocky
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/rocky-release`
# CentOS
elif [ -r "/etc/centos-release" ]; then
  if grep -q "AlmaLinux" /etc/centos-release; then
    DIST_NAME=almalinux
  elif grep -q "Rocky" /etc/centos-release; then
    DIST_NAME=almalinux
  else
    DIST_NAME="centos"
  fi
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
# Fedora
elif [ -r "/etc/fedora-release" ]; then
    DIST_NAME="fedora"
    DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/fedora-release`
# Oracle Linux
elif [ -r "/etc/oracle-release" ]; then
    DIST_NAME="ol"
    DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/oracle-release`
# RedHat
elif [ -r "/etc/redhat-release" ]; then
  if grep -q "AlmaLinux" /etc/redhat-release; then
    DIST_NAME=almalinux
  elif grep -q "Rocky" /etc/redhat-release; then
    DIST_NAME=almalinux
  elif grep -q "CentOS" /etc/redhat-release; then
      DIST_NAME="centos"
  else
      DIST_NAME="rhel"
  fi
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/redhat-release`
# SUSE
elif [ -r "/etc/SuSE-release" ]; then
  if grep -q "openSUSE" /etc/SuSE-release; then
      DIST_NAME="generic"
      DIST_VER=""
  else
      DIST_NAME="sles"
      DIST_VER=`sed -rn 's/.*VERSION = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
  fi
elif [ -r "/etc/os-release" ]; then
  . /etc/os-release
  DIST_NAME=$ID
  DIST_VER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
  if [ "X$DIST_VER" = "X" ]; then
      DIST_VER="0"
  fi
  if [ "$DIST_NAME" = "amzn" ] && [ "$DIST_VER" != "2" ] && [ "$DIST_VER" != "2023" ]; then
      DIST_VER="1"
  fi
  DIST_SUBVER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')
  if [ "X$DIST_SUBVER" = "X" ]; then
      DIST_SUBVER="0"
  fi
else
  DIST_NAME="generic"
  DIST_VER=""
fi

SCA_DIR="${DIST_NAME}/${DIST_VER}"
SCA_BASE_DIR="%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp"
mkdir -p %{_localstatedir}/ruleset/sca

SCA_TMP_DIR="${SCA_BASE_DIR}/${SCA_DIR}"

# Install the configuration files needed for this hosts
if [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}/sca.files" ]; then
  SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/sca.files" ]; then
  SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/sca.files" ]; then
  SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}"
else
  SCA_TMP_DIR="${SCA_BASE_DIR}/generic"
fi

SCA_TMP_FILE="${SCA_TMP_DIR}/sca.files"

if [ -r ${SCA_TMP_FILE} ] && [ -r ${SCA_BASE_DIR}/generic/sca.manager.files ]; then

  rm -f %{_localstatedir}/ruleset/sca/* || true

  for sca_file in $(cat ${SCA_TMP_FILE}); do
    if [ -f ${SCA_BASE_DIR}/${sca_file} ]; then
      mv ${SCA_BASE_DIR}/${sca_file} %{_localstatedir}/ruleset/sca
    fi
  done

  for sca_file in $(cat ${SCA_BASE_DIR}/generic/sca.manager.files); do
    filename=$(basename ${sca_file})
    if [ -f "${SCA_BASE_DIR}/${sca_file}" ] && [ ! -f "%{_localstatedir}/ruleset/sca/${filename}" ]; then
      mv ${SCA_BASE_DIR}/${sca_file} %{_localstatedir}/ruleset/sca/${filename}.disabled
    fi
  done
fi

# Fix sca permissions, group and owner
chmod 640 %{_localstatedir}/ruleset/sca/*
chown root:wazuh %{_localstatedir}/ruleset/sca/*
# Delete the temporary directory
rm -rf ${SCA_BASE_DIR}

# Add the SELinux policy
if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
  if [ $(getenforce) != "Disabled" ]; then
    semodule -i %{_localstatedir}/var/selinux/wazuh.pp
    semodule -e wazuh
  fi
fi

# Delete the installation files used to configure the manager
rm -rf %{_localstatedir}/packages_files

# Remove unnecessary files from default group
rm -f %{_localstatedir}/etc/shared/default/*.rpmnew

# Remove old ossec user and group if exists and change ownwership of files

if getent group ossec > /dev/null 2>&1; then
  find %{_localstatedir}/ -group ossec -user root -print0 | xargs -0 chown root:wazuh > /dev/null 2>&1 || true
  if getent passwd ossec > /dev/null 2>&1; then
    find %{_localstatedir}/ -group ossec -user ossec -print0 | xargs -0 chown wazuh:wazuh > /dev/null 2>&1 || true
    userdel ossec > /dev/null 2>&1
  fi
  if getent passwd ossecm > /dev/null 2>&1; then
    find %{_localstatedir}/ -group ossec -user ossecm -print0 | xargs -0 chown wazuh:wazuh > /dev/null 2>&1 || true
    userdel ossecm > /dev/null 2>&1
  fi
  if getent passwd ossecr > /dev/null 2>&1; then
    find %{_localstatedir}/ -group ossec -user ossecr -print0 | xargs -0 chown wazuh:wazuh > /dev/null 2>&1 || true
    userdel ossecr > /dev/null 2>&1
  fi
  if getent group ossec > /dev/null 2>&1; then
    groupdel ossec > /dev/null 2>&1
  fi
fi

%preun

if [ $1 = 0 ]; then

  # Stop the services before uninstall the package
  # Check for systemd
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-manager > /dev/null 2>&1; then
    systemctl stop wazuh-manager.service > /dev/null 2>&1
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-manager status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-manager stop > /dev/null 2>&1
  fi
  %{_localstatedir}/bin/wazuh-control stop > /dev/null 2>&1

  # Remove the SELinux policy
  if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
    if [ $(getenforce) != "Disabled" ]; then
      if (semodule -l | grep wazuh > /dev/null); then
        semodule -r wazuh > /dev/null
      fi
    fi
  fi

  # Remove SCA files
  rm -f %{_localstatedir}/ruleset/sca/*
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

  # Backup agents centralized configuration (etc/shared)
  if [ -d %{_localstatedir}/etc/shared ]; then
    find %{_localstatedir}/etc/ -type f  -name "*save" ! -name "*rpmsave" -exec rm -f {} \;
    find %{_localstatedir}/etc/ -type f ! -name "*shared*" ! -name "*rpmsave" -exec mv {} {}.save \;
  fi

  # Backup registration service certificates (sslmanager.cert,sslmanager.key)
  if [ -f %{_localstatedir}/etc/sslmanager.cert ]; then
      mv %{_localstatedir}/etc/sslmanager.cert %{_localstatedir}/etc/sslmanager.cert.save
  fi
  if [ -f %{_localstatedir}/etc/sslmanager.key ]; then
      mv %{_localstatedir}/etc/sslmanager.key %{_localstatedir}/etc/sslmanager.key.save
  fi

  # Remove lingering folders and files
  rm -rf %{_localstatedir}/queue/
  rm -rf %{_localstatedir}/framework/
  rm -rf %{_localstatedir}/api/
  rm -rf %{_localstatedir}/stats/
  rm -rf %{_localstatedir}/var/
  rm -rf %{_localstatedir}/bin/
  rm -rf %{_localstatedir}/logs/
  rm -rf %{_localstatedir}/ruleset/
  rm -rf %{_localstatedir}/tmp
  rm -rf %{_localstatedir}/engine
fi

# posttrans code is the last thing executed in a install/upgrade
%posttrans
if [ -f %{_sysconfdir}/systemd/system/wazuh-manager.service ]; then
  rm -rf %{_sysconfdir}/systemd/system/wazuh-manager.service
  systemctl daemon-reload > /dev/null 2>&1
fi

if [ -f %{_localstatedir}/tmp/wazuh.restart ]; then
  rm -f %{_localstatedir}/tmp/wazuh.restart
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
    systemctl daemon-reload > /dev/null 2>&1
    systemctl restart wazuh-manager.service > /dev/null 2>&1
  elif command -v service > /dev/null 2>&1 ; then
    service wazuh-manager restart > /dev/null 2>&1
  else
    %{_localstatedir}/bin/wazuh-control restart > /dev/null 2>&1
  fi
fi

if [ -d %{_localstatedir}/logs/ossec ]; then
  rm -rf %{_localstatedir}/logs/ossec/
fi

if [ -d %{_localstatedir}/queue/ossec ]; then
  rm -rf %{_localstatedir}/queue/ossec/
fi

if [ -f %{_sysconfdir}/ossec-init.conf ]; then
  rm -f %{_sysconfdir}/ossec-init.conf
  rm -f %{_localstatedir}/etc/ossec-init.conf
fi

# Remove groups backup files
rm -rf %{_localstatedir}/backup/groups

%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/etc
 chown root:wazuh %{_localstatedir}/etc/localtime
 chmod 0640 %{_localstatedir}/etc/localtime

%clean
rm -fr %{buildroot}

%files
%defattr(-,root,wazuh)
%config(missingok) %{_initrddir}/wazuh-manager
%attr(640, root, wazuh) %verify(not md5 size mtime) %ghost %{_sysconfdir}/ossec-init.conf
/usr/lib/systemd/system/wazuh-manager.service
%dir %attr(750, root, wazuh) %{_localstatedir}
%attr(440, wazuh, wazuh) %{_localstatedir}/VERSION.json
%dir %attr(750, root, wazuh) %{_localstatedir}/active-response
%dir %attr(750, root, wazuh) %{_localstatedir}/active-response/bin
%attr(750, root, wazuh) %{_localstatedir}/active-response/bin/*
%dir %attr(750, root, wazuh) %{_localstatedir}/api
%dir %attr(770, root, wazuh) %{_localstatedir}/api/configuration
%attr(660, root, wazuh) %config(noreplace) %{_localstatedir}/api/configuration/api.yaml
%dir %attr(770, root, wazuh) %{_localstatedir}/api/configuration/security
%dir %attr(770, root, wazuh) %{_localstatedir}/api/configuration/ssl
%dir %attr(750, root, wazuh) %{_localstatedir}/api/scripts
%attr(640, root, wazuh) %{_localstatedir}/api/scripts/*.py
%dir %attr(750, root, wazuh) %{_localstatedir}/backup
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/backup/db
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/backup/agents
%dir %attr(750, root, wazuh) %{_localstatedir}/backup/shared
%dir %attr(750, root, wazuh) %{_localstatedir}/bin
%attr(750, root, root) %{_localstatedir}/bin/agent_control
%attr(750, root, wazuh) %{_localstatedir}/bin/agent_groups
%attr(750, root, wazuh) %{_localstatedir}/bin/agent_upgrade
%attr(750, root, wazuh) %{_localstatedir}/bin/cluster_control
%attr(750, root, root) %{_localstatedir}/bin/wazuh-engine
%attr(750, root, root) %{_localstatedir}/bin/wazuh-authd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-control
%attr(750, root, root) %{_localstatedir}/bin/wazuh-execd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-logcollector
%attr(750, root, root) %{_localstatedir}/bin/wazuh-monitord
%attr(750, root, root) %{_localstatedir}/bin/wazuh-remoted
%attr(750, root, root) %{_localstatedir}/bin/wazuh-syscheckd
%attr(750, root, wazuh) %{_localstatedir}/bin/wazuh-apid
%attr(750, root, wazuh) %{_localstatedir}/bin/wazuh-clusterd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-db
%attr(750, root, root) %{_localstatedir}/bin/wazuh-modulesd
%attr(750, root, wazuh) %{_localstatedir}/bin/rbac_control
%attr(750, root, wazuh) %{_localstatedir}/bin/wazuh-keystore
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/etc
%attr(660, root, wazuh) %config(noreplace) %{_localstatedir}/etc/ossec.conf
%attr(640, wazuh, wazuh) %config(noreplace) %{_localstatedir}/etc/client.keys
%attr(640, root, wazuh) %{_localstatedir}/etc/internal_options*
%attr(640, root, wazuh) %config(noreplace) %{_localstatedir}/etc/local_internal_options.conf
%attr(640, root, wazuh) %{_localstatedir}/etc/localtime
%dir %attr(770, root, wazuh) %{_localstatedir}/etc/shared
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/etc/shared/default
%attr(660, wazuh, wazuh) %{_localstatedir}/etc/shared/agent-template.conf
%attr(660, wazuh, wazuh) %config(noreplace) %{_localstatedir}/etc/shared/default/*
%dir %attr(770, root, wazuh) %{_localstatedir}/etc/rootcheck
%attr(660, root, wazuh) %{_localstatedir}/etc/rootcheck/*.txt
%dir %attr(770, root, wazuh) %{_localstatedir}/engine
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/engine/kvdb
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/engine/store
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/engine/store/schema
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/engine/store/schema/allowed-fields
%attr(640, wazuh, wazuh) %{_localstatedir}/engine/store/schema/allowed-fields/0
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/engine/store/schema/engine-schema
%attr(640, wazuh, wazuh) %{_localstatedir}/engine/store/schema/engine-schema/0
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/engine/store/schema/wazuh-logpar-overrides
%attr(640, wazuh, wazuh) %{_localstatedir}/engine/store/schema/wazuh-logpar-overrides/0
%dir %attr(750, root, wazuh) %{_localstatedir}/framework
%dir %attr(750, root, wazuh) %{_localstatedir}/framework/python
%{_localstatedir}/framework/python/*
%dir %attr(750, root, wazuh) %{_localstatedir}/framework/scripts
%attr(640, root, wazuh) %{_localstatedir}/framework/scripts/*.py
%dir %attr(750, root, wazuh) %{_localstatedir}/framework/wazuh
%attr(640, root, wazuh) %{_localstatedir}/framework/wazuh/*.py
%dir %attr(750, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster
%attr(640, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster/*.py
%attr(640, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster/*.json
%dir %attr(750, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster/hap_helper
%attr(640, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster/hap_helper/*.py
%dir %attr(750, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster/dapi
%attr(640, root, wazuh) %{_localstatedir}/framework/wazuh/core/cluster/dapi/*.py
%dir %attr(750, root, wazuh) %{_localstatedir}/integrations
%attr(750, root, wazuh) %{_localstatedir}/integrations/*
%dir %attr(750, root, wazuh) %{_localstatedir}/lib
%attr(750, root, wazuh) %{_localstatedir}/lib/libwazuhext.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libwazuhshared.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libdbsync.so
%attr(750, root, wazuh) %{_localstatedir}/lib/librsync.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libsyscollector.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libsysinfo.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libjemalloc.so.2
%attr(750, root, wazuh) %{_localstatedir}/lib/libstdc++.so.6
%attr(750, root, wazuh) %{_localstatedir}/lib/libgcc_s.so.1
%attr(750, root, wazuh) %{_localstatedir}/lib/libfimdb.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libfimebpf.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libbpf.so
%attr(750, root, wazuh) %{_localstatedir}/lib/modern.bpf.o
%attr(750, root, wazuh) %{_localstatedir}/lib/libcontent_manager.so
%attr(750, root, wazuh) %{_localstatedir}/lib/libindexer_connector.so
%attr(750, root, wazuh) %{_localstatedir}/lib/librocksdb.so.8
%attr(750, root, wazuh) %{_localstatedir}/lib/librouter.so
%{_localstatedir}/lib/libpython3.10.so.1.0
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/logs
%attr(660, wazuh, wazuh)  %ghost %{_localstatedir}/logs/active-responses.log
%attr(660, wazuh, wazuh) %ghost %{_localstatedir}/logs/api.log
%attr(640, wazuh, wazuh) %ghost %{_localstatedir}/logs/integrations.log
%attr(660, wazuh, wazuh) %ghost %{_localstatedir}/logs/ossec.log
%attr(660, wazuh, wazuh) %ghost %{_localstatedir}/logs/ossec.json
%dir %attr(440, root, wazuh) %{_localstatedir}/templates
%attr(0440, root, wazuh) %{_localstatedir}/templates/vd_states_template.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-fim-files.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-fim-registries.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-packages.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-processes.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-system.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-hardware.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-networks.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-protocols.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-interfaces.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-hotfixes.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-ports.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-users.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-groups.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/vd_states_update_mappings.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-fim-files-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-fim-registries-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-packages-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-processes-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-system-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-hardware-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-networks-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-protocols-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-interfaces-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-hotfixes-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-ports-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-users-update.json
%attr(0440, root, wazuh) %{_localstatedir}/templates/wazuh-states-inventory-groups-update.json
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/logs/api
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/logs/archives
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/logs/alerts
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/logs/cluster
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/logs/firewall
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/logs/wazuh
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/add_localfiles.sh
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/gen_ossec.sh
%attr(440, wazuh, wazuh) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/VERSION.json
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/src/
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/src/init/
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/src/init/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/generic
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/generic/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/centos
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/centos/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/rhel
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/manager_installation_scripts/etc/templates/config/rhel/*
%attr(640, wazuh, wazuh) %missingok %{_localstatedir}/tmp/%{_vdfilename}
%dir %attr(750, root, wazuh) %{_localstatedir}/queue
%attr(600, root, wazuh) %{_localstatedir}/queue/agents-timestamp
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/queue/alerts
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/queue/cluster
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/db
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/diff
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/fim
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/fim/db
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/syscollector
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/syscollector/db
%attr(640, root, wazuh) %{_localstatedir}/queue/syscollector/norm_config.json
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/queue/rids
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/queue/tasks
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/queue/sockets
%dir %attr(660, root, wazuh) %{_localstatedir}/queue/vd
%dir %attr(660, root, wazuh) %{_localstatedir}/queue/indexer
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/queue/router
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/logcollector
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/keystore
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/queue/tzdb
%dir %attr(750, root, wazuh) %{_localstatedir}/ruleset
%dir %attr(750, root, wazuh) %{_localstatedir}/ruleset/sca
%dir %attr(770, root, wazuh) %{_localstatedir}/.ssh
%dir %attr(1770, root, wazuh) %{_localstatedir}/tmp
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/applications
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/applications/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/generic
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/generic/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/mongodb
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/mongodb/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/nginx
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/nginx/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/oracledb
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/oracledb/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/1
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/1/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2023
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2023/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/sca.files
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/5
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/5/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/6
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/6/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/7
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/7/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/8
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/8/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/9
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/9/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/10
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/10/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/15
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/15/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/16
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/16/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/17
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/17/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/18
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/18/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/19
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/19/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/20
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/20/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/21
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/21/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/22
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/22/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/23
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/23/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/24
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/24/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/9
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/9/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/10
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ol/10/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/sca.files
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/5
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/5/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/6
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/6/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/7
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/7/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/8
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/8/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/9
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/9/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/10
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/10/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/sca.files
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/11
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/11/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/12
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/12/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/15
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/15/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sunos
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sunos/*
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/sca.files
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/11
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/11/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/12
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/12/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amazon
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amazon/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/fedora/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/windows
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/windows/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/almalinux/*
%dir %attr(750, wazuh, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky
%attr(640, root, wazuh) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rocky/*
%dir %attr(750, root, wazuh) %{_localstatedir}/var
%dir %attr(770, root, wazuh) %{_localstatedir}/var/db
%dir %attr(770, root, wazuh) %{_localstatedir}/var/download
%dir %attr(770, wazuh, wazuh) %{_localstatedir}/var/multigroups
%dir %attr(770, root, wazuh) %{_localstatedir}/var/run
%dir %attr(770, root, wazuh) %{_localstatedir}/var/selinux
%attr(640, root, wazuh) %{_localstatedir}/var/selinux/*
%dir %attr(770, root, wazuh) %{_localstatedir}/var/upgrade
%dir %attr(770, root, wazuh) %{_localstatedir}/var/wodles
%dir %attr(750, root, wazuh) %{_localstatedir}/wodles
%attr(750,root, wazuh) %{_localstatedir}/wodles/*
%dir %attr(750, root, wazuh) %{_localstatedir}/wodles/aws
%attr(750, root, wazuh) %{_localstatedir}/wodles/aws/*
%dir %attr(750, root, wazuh) %{_localstatedir}/wodles/azure
%attr(750, root, wazuh) %{_localstatedir}/wodles/azure/*
%dir %attr(750, root, wazuh) %{_localstatedir}/wodles/docker
%attr(750, root, wazuh) %{_localstatedir}/wodles/docker/*
%dir %attr(750, root, wazuh) %{_localstatedir}/wodles/gcloud
%attr(750, root, wazuh) %{_localstatedir}/wodles/gcloud/*

%files -n wazuh-manager-debuginfo -f debugfiles.list

%changelog
* Thu Dec 18 2025 support <info@wazuh.com> - 5.0.0
- More info: https://documentation.wazuh.com/current/release-notes/release-5-0-0.html
* Thu Sep 25 2025 support <info@wazuh.com> - 4.14.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-14-0.html
* Wed Jul 30 2025 support <info@wazuh.com> - 4.13.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-13-1.html
* Wed Jul 16 2025 support <info@wazuh.com> - 4.13.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-13-0.html
* Wed May 07 2025 support <info@wazuh.com> - 4.12.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-12-0.html
* Tue Apr 01 2025 support <info@wazuh.com> - 4.11.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-11-2.html
* Wed Mar 12 2025 support <info@wazuh.com> - 4.11.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-11-1.html
* Wed Feb 19 2025 support <info@wazuh.com> - 4.11.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-11-0.html
* Thu Jan 16 2025 support <info@wazuh.com> - 4.10.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-10-1.html
* Thu Jan 09 2025 support <info@wazuh.com> - 4.10.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-10-0.html
* Wed Oct 30 2024 support <info@wazuh.com> - 4.9.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-9-2.html
* Thu Oct 17 2024 support <info@wazuh.com> - 4.9.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-9-1.html
* Thu Sep 05 2024 support <info@wazuh.com> - 4.9.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-9-0.html
* Wed Jul 10 2024 support <info@wazuh.com> - 4.8.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-8-1.html
* Wed Jun 12 2024 support <info@wazuh.com> - 4.8.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-8-0.html
* Thu May 30 2024 support <info@wazuh.com> - 4.7.5
- More info: https://documentation.wazuh.com/current/release-notes/release-4-7-5.html
* Thu Apr 25 2024 support <info@wazuh.com> - 4.7.4
- More info: https://documentation.wazuh.com/current/release-notes/release-4-7-4.html
* Tue Feb 27 2024 support <info@wazuh.com> - 4.7.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-7-3.html
* Tue Jan 09 2024 support <info@wazuh.com> - 4.7.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-7-2.html
* Wed Dec 13 2023 support <info@wazuh.com> - 4.7.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-7-1.html
* Tue Nov 21 2023 support <info@wazuh.com> - 4.7.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-7-0.html
* Tue Oct 31 2023 support <info@wazuh.com> - 4.6.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-6-0.html
* Tue Oct 24 2023 support <info@wazuh.com> - 4.5.4
- More info: https://documentation.wazuh.com/current/release-notes/release-4-5-4.html
* Tue Oct 10 2023 support <info@wazuh.com> - 4.5.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-5-3.html
* Thu Aug 31 2023 support <info@wazuh.com> - 4.5.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-5-2.html
* Thu Aug 24 2023 support <info@wazuh.com> - 4.5.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-5.1.html
* Thu Aug 10 2023 support <info@wazuh.com> - 4.5.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-5-0.html
* Mon Jul 10 2023 support <info@wazuh.com> - 4.4.5
- More info: https://documentation.wazuh.com/current/release-notes/release-4-4-5.html
* Tue Jun 13 2023 support <info@wazuh.com> - 4.4.4
- More info: https://documentation.wazuh.com/current/release-notes/release-4-4-4.html
* Thu May 25 2023 support <info@wazuh.com> - 4.4.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-4-3.html
* Mon May 08 2023 support <info@wazuh.com> - 4.4.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-4-2.html
* Mon Apr 24 2023 support <info@wazuh.com> - 4.3.11
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3.11.html
* Mon Apr 17 2023 support <info@wazuh.com> - 4.4.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-4-1.html
* Wed Jan 18 2023 support <info@wazuh.com> - 4.4.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-4-0.html
* Thu Nov 10 2022 support <info@wazuh.com> - 4.3.10
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-10.html
* Mon Oct 03 2022 support <info@wazuh.com> - 4.3.9
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-9.html
* Wed Sep 21 2022 support <info@wazuh.com> - 3.13.6
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-6.html
* Mon Sep 19 2022 support <info@wazuh.com> - 4.3.8
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-8.html
* Wed Aug 24 2022 support <info@wazuh.com> - 3.13.5
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-5.html
* Mon Aug 08 2022 support <info@wazuh.com> - 4.3.7
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-7.html
* Thu Jul 07 2022 support <info@wazuh.com> - 4.3.6
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-6.html
* Wed Jun 29 2022 support <info@wazuh.com> - 4.3.5
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-5.html
* Tue Jun 07 2022 support <info@wazuh.com> - 4.3.4
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-4.html
* Tue May 31 2022 support <info@wazuh.com> - 4.3.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-3.html
* Mon May 30 2022 support <info@wazuh.com> - 4.3.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-2.html
* Mon May 30 2022 support <info@wazuh.com> - 3.13.4
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-4.html
* Sun May 29 2022 support <info@wazuh.com> - 4.2.7
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-7.html
* Wed May 18 2022 support <info@wazuh.com> - 4.3.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-1.html
* Thu May 05 2022 support <info@wazuh.com> - 4.3.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-3-0.html
* Fri Mar 25 2022 support <info@wazuh.com> - 4.2.6
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-6.html
* Mon Nov 15 2021 support <info@wazuh.com> - 4.2.5
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-5.html
* Thu Oct 21 2021 support <info@wazuh.com> - 4.2.4
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-4.html
* Wed Oct 06 2021 support <info@wazuh.com> - 4.2.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-3.html
* Tue Sep 28 2021 support <info@wazuh.com> - 4.2.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-2.html
* Sat Sep 25 2021 support <info@wazuh.com> - 4.2.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-1.html
* Mon Apr 26 2021 support <info@wazuh.com> - 4.2.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-2-0.html
* Sat Apr 24 2021 support <info@wazuh.com> - 3.13.3
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-3.html
* Thu Apr 22 2021 support <info@wazuh.com> - 4.1.5
- More info: https://documentation.wazuh.com/current/release-notes/release-4-1-5.html
* Mon Mar 29 2021 support <info@wazuh.com> - 4.1.4
- More info: https://documentation.wazuh.com/current/release-notes/release-4-1-4.html
* Sat Mar 20 2021 support <info@wazuh.com> - 4.1.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-1-3.html
* Mon Mar 08 2021 support <info@wazuh.com> - 4.1.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-1-2.html
* Fri Mar 05 2021 support <info@wazuh.com> - 4.1.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-1-1.html
* Tue Jan 19 2021 support <info@wazuh.com> - 4.1.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-1-0.html
* Mon Nov 30 2020 support <info@wazuh.com> - 4.0.3
- More info: https://documentation.wazuh.com/current/release-notes/release-4-0-3.html
* Mon Nov 23 2020 support <info@wazuh.com> - 4.0.2
- More info: https://documentation.wazuh.com/current/release-notes/release-4-0-2.html
* Sat Oct 31 2020 support <info@wazuh.com> - 4.0.1
- More info: https://documentation.wazuh.com/current/release-notes/release-4-0-1.html
* Mon Oct 19 2020 support <info@wazuh.com> - 4.0.0
- More info: https://documentation.wazuh.com/current/release-notes/release-4-0-0.html
* Fri Aug 21 2020 support <info@wazuh.com> - 3.13.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-2.html
* Tue Jul 14 2020 support <info@wazuh.com> - 3.13.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-1.html
* Mon Jun 29 2020 support <info@wazuh.com> - 3.13.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-13-0.html
* Wed May 13 2020 support <info@wazuh.com> - 3.12.3
- More info: https://documentation.wazuh.com/current/release-notes/release-3-12-3.html
* Thu Apr 9 2020 support <info@wazuh.com> - 3.12.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-12-2.html
* Wed Apr 8 2020 support <info@wazuh.com> - 3.12.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-12-1.html
* Wed Mar 25 2020 support <info@wazuh.com> - 3.12.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-12-0.html
* Mon Feb 24 2020 support <info@wazuh.com> - 3.11.4
- More info: https://documentation.wazuh.com/current/release-notes/release-3-11-4.html
* Wed Jan 22 2020 support <info@wazuh.com> - 3.11.3
- More info: https://documentation.wazuh.com/current/release-notes/release-3-11-3.html
* Tue Jan 7 2020 support <info@wazuh.com> - 3.11.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-11-2.html
* Thu Dec 26 2019 support <info@wazuh.com> - 3.11.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-11-1.html
* Mon Oct 7 2019 support <info@wazuh.com> - 3.11.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-11-0.html
* Mon Sep 23 2019 support <support@wazuh.com> - 3.10.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-10-2.html
* Thu Sep 19 2019 support <support@wazuh.com> - 3.10.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-10-1.html
* Mon Aug 26 2019 support <support@wazuh.com> - 3.10.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-10-0.html
* Thu Aug 8 2019 support <support@wazuh.com> - 3.9.5
- More info: https://documentation.wazuh.com/current/release-notes/release-3-9-5.html
* Fri Jul 12 2019 support <support@wazuh.com> - 3.9.4
- More info: https://documentation.wazuh.com/current/release-notes/release-3-9-4.html
* Tue Jul 02 2019 support <support@wazuh.com> - 3.9.3
- More info: https://documentation.wazuh.com/current/release-notes/release-3-9-3.html
* Tue Jun 11 2019 support <support@wazuh.com> - 3.9.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-9-2.html
* Sat Jun 01 2019 support <support@wazuh.com> - 3.9.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-9-1.html
* Mon Feb 25 2019 support <support@wazuh.com> - 3.9.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-9-0.html
* Wed Jan 30 2019 support <support@wazuh.com> - 3.8.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-8-2.html
* Thu Jan 24 2019 support <support@wazuh.com> - 3.8.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-8-1.html
* Fri Jan 18 2019 support <support@wazuh.com> - 3.8.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-8-0.html
* Wed Nov 7 2018 support <support@wazuh.com> - 3.7.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-7-0.html
* Mon Sep 10 2018 support <info@wazuh.com> - 3.6.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-6-1.html
* Fri Sep 7 2018 support <support@wazuh.com> - 3.6.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-6-0.html
* Wed Jul 25 2018 support <support@wazuh.com> - 3.5.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-5-0.html
* Wed Jul 11 2018 support <support@wazuh.com> - 3.4.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-4-0.html
* Mon Jun 18 2018 support <support@wazuh.com> - 3.3.1
- More info: https://documentation.wazuh.com/current/release-notes/release-3-3-1.html
* Mon Jun 11 2018 support <support@wazuh.com> - 3.3.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-3-0.html
* Wed May 30 2018 support <support@wazuh.com> - 3.2.4
- More info: https://documentation.wazuh.com/current/release-notes/release-3-2-4.html
* Thu May 10 2018 support <support@wazuh.com> - 3.2.3
- More info: https://documentation.wazuh.com/current/release-notes/release-3-2-3.html
* Mon Apr 09 2018 support <support@wazuh.com> - 3.2.2
- More info: https://documentation.wazuh.com/current/release-notes/release-3-2-2.html
* Wed Feb 21 2018 support <support@wazuh.com> - 3.2.1
- More info: https://documentation.wazuh.com/current/release-notes/rerlease-3-2-1.html
* Wed Feb 07 2018 support <support@wazuh.com> - 3.2.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-2-0.html
* Thu Dec 21 2017 support <support@wazuh.com> - 3.1.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-1-0.html
* Mon Nov 06 2017 support <support@wazuh.com> - 3.0.0
- More info: https://documentation.wazuh.com/current/release-notes/release-3-0-0.html
* Tue Jun 06 2017 support <support@wazuh.com> - 2.0.1
- Changed random data generator for a secure OS-provided generator.
- Changed Windows installer file name (depending on version).
- Linux distro detection using standard os-release file.
- Changed some URLs to documentation.
- Disable synchronization with SQLite databases for Syscheck by default.
- Minor changes at Rootcheck formatter for JSON alerts.
- Added debugging messages to Integrator logs.
- Show agent ID when possible on logs about incorrectly formatted messages.
- Use default maximum inotify event queue size.
- Show remote IP on encoding format errors when unencrypting messages.
- Fix permissions in agent-info folder
- Fix permissions in rids folder.
* Fri Apr 21 2017 Jose Luis Ruiz <jose@wazuh.com> - 2.0
- Changed random data generator for a secure OS-provided generator.
- Changed Windows installer file name (depending on version).
- Linux distro detection using standard os-release file.
- Changed some URLs to documentation.
- Disable synchronization with SQLite databases for Syscheck by default.
- Minor changes at Rootcheck formatter for JSON alerts.
- Added debugging messages to Integrator logs.
- Show agent ID when possible on logs about incorrectly formatted messages.
- Use default maximum inotify event queue size.
- Show remote IP on encoding format errors when unencrypting messages.
- Fixed resource leaks at rules configuration parsing.
- Fixed memory leaks at rules parser.
- Fixed memory leaks at XML decoders parser.
- Fixed TOCTOU condition when removing directories recursively.
- Fixed insecure temporary file creation for old POSIX specifications.
- Fixed missing agentless devices identification at JSON alerts.
- Fixed FIM timestamp and file name issue at SQLite database.
- Fixed cryptographic context acquirement on Windows agents.
- Fixed debug mode for Analysisd.
- Fixed bad exclusion of BTRFS filesystem by Rootcheck.
- Fixed compile errors on macOS.
- Fixed option -V for Integrator.
- Exclude symbolic links to directories when sending FIM diffs (by Stephan Joerrens).
- Fixed daemon list for service reloading at ossec-control.
- Fixed socket waiting issue on Windows agents.
- Fixed PCI_DSS definitions grouping issue at Rootcheck controls.
