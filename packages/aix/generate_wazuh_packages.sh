#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -x

# Script configuration variables

current_path="$( cd $(dirname $0) ; pwd -P )"
install_path="/var/ossec"
reference="main"
revision="1"
target_dir="${current_path}/output/"
compute_checksums="no"
checksum_dir=""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
 echo "This script must be run as root"
 exit 1
fi

# Get AIX major and minor version
aix_version=$(oslevel)
aix_major=$(echo ${aix_version} | cut -d'.' -f 1)
aix_minor=$(echo ${aix_version} | cut -d'.' -f 2)

export PATH=$PATH:/opt/freeware/bin

show_help() {
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "    -b,  --branch <branch>        Select Git branch or tag. By default: ${reference}"
  echo "    -r,  --revision <revision>    Define package revision text/number. By default: ${revision}"
  echo "    -e,  --environment            Install all the packages necessaries to build the RPM package"
  echo "    -s,  --store  <path>          Directory to store the resulting RPM package. By default: ${target_dir}"
  echo "    -p,  --install-path <path>    Installation path for the package. By default: ${install_path}"
  echo "    -c,  --checksum <path>        Compute the SHA512 checksum of the RPM package. OpenSSL is required."
  echo "    -h,  --help                   Shows this help"
  echo
  exit $1
}

check_openssl() {
  if [[ -z "$(command -v openssl)" ]] && [[ "${compute_checksums}" = "yes" ]]; then
    echo "OpenSSL is not installed. OpenSSL is required to get the package checksum."
    return 1
  else
    return 0
  fi
}

# Function to install perl 5.10 on AIX
build_perl() {

  curl -LO http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz -k -s
  gunzip perl-5.10.1.tar.gz && tar -xf perl-5.10.1.tar
  cd perl-5.10.1 && ./Configure -des -Dcc='gcc' -Dusethreads
  make && make install
  ln -fs /usr/local/bin/perl /bin/perl
  ln -fs /usr/local/bin/perl /opt/freeware/bin/perl
  cd .. && rm -rf perl-5.10.1*

  return 0
}

build_cmake() {
  socket_lib=$(find /opt/freeware/lib/gcc/*/6.3.0/include-fixed/sys/ -name socket.h)
  mv ${socket_lib} ${socket_lib}.bkp
  mkdir -p /home/aix
  cd /home/aix
  curl -LO http://packages-dev.wazuh.com/deps/aix/precompiled-aix-cmake-3.12.4.tar.gz -k -s
  ln -s /usr/bin/make /usr/bin/gmake
  gunzip precompiled-aix-cmake-3.12.4.tar.gz
  tar -xf precompiled-aix-cmake-3.12.4.tar && cd cmake-3.12.4
  gmake install
  cd .. && rm -rf *cmake-3.12.4*
  ln -fs /usr/local/bin/cmake /usr/bin/cmake
  cd ${current_path}
}

# Function to build the compilation environment
build_environment() {

  # Resizing partitions for Site Ox boxes (used by Wazuh team)
  if grep 'www.siteox.com' /etc/motd > /dev/null 2>&1; then
    for partition in "/home" "/opt"; do
      partition_size=$(df -m | grep $partition | awk -F' ' '{print $2}' | cut -d'.' -f1)
      if [[ ${partition_size} -lt "2048" ]]; then
        echo "Resizing $partition partition to 2GB"
        chfs -a size=2048M $partition > /dev/null 2>&1
      fi
    done
  fi

  rpm="rpm -Uvh --nodeps"

  $rpm http://packages-dev.wazuh.com/deps/aix/libiconv-1.14-22.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/autoconf-2.71-1.aix6.1.noarch.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/automake-1.16.2-1.aix6.1.noarch.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/bash-4.4-4.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/bzip2-1.0.6-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/coreutils-8.25-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/expat-2.2.6-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/expat-devel-2.2.6-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/gettext-0.17-1.aix5.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/glib2-2.33.2-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/glib2-devel-2.33.2-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/gmp-6.1.1-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/gmp-devel-6.1.1-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/grep-3.0-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/gzip-1.8-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/info-6.4-1.aix5.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/libffi-3.2.1-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/libidn-1.33-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/libsigsegv-2.10-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/libtool-2.4.6-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/m4-1.4.18-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/make-4.3-1.aix5.3.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/openldap-2.4.44-6.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/openssl-1.0.2g-3.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/openssl-devel-1.0.2g-3.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/pcre-8.42-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/pkg-config-0.29.1-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/readline-7.0-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/sed-4.7-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/wget-1.19-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/zlib-1.2.11-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/popt-1.16-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/rsync-3.1.2-3.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/tar-1.32-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/curl-7.72.0-1.aix5.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/readline-devel-7.0-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/guile-1.8.8-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/unixODBC-2.3.1-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/db-4.8.24-4.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/gdbm-1.10-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/ncurses-6.2-2.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/sqlite-3.33.0-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/sqlite-libs-3.33.0-1.aix6.1.ppc.rpm || true
  $rpm http://packages-dev.wazuh.com/deps/aix/python-2.7.15-1.aix6.1.ppc.rpm || true



  if [[ "${aix_major}" = "6" ]] || [[ "${aix_major}" = "7" ]]; then
    $rpm http://packages-dev.wazuh.com/deps/aix/mpfr-3.1.4-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libmpc-1.0.3-2.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/file-5.32-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/file-libs-5.32-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/perl-5.30.3-2.aix6.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "6" ]]; then
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-cpp-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libgcc-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libstdc%2B%2B-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libstdc%2B%2B-devel-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-c%2B%2B-6.3.0-1.aix6.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "7" ]] && [[ "${aix_minor}" = "1" ]]; then
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-cpp-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libgcc-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libstdc%2B%2B-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libstdc%2B%2B-devel-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-c%2B%2B-6.3.0-1.aix7.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "7" ]] && [[ "${aix_minor}" = "2" ]]; then
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-cpp-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libgcc-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libstdc%2B%2B-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/libstdc%2B%2B-devel-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://packages-dev.wazuh.com/deps/aix/gcc-c%2B%2B-6.3.0-1.aix7.2.ppc.rpm || true
  fi

  build_perl

  if [[ "${aix_major}" = "6" ]] || [[ "${aix_major}" = "7" ]]; then
    build_cmake
  fi
  return 0
}

build_package() {

  source_code="http://api.github.com/repos/wazuh/wazuh/tarball/${reference}"

  rm -f wazuh.tar.gz && curl -L ${source_code} -k -o wazuh.tar.gz -s
  rm -rf wazuh-wazuh-* wazuh-agent-*
  extracted_directory=$(gunzip -c wazuh.tar.gz | tar -xvf - | tail -n 1 | cut -d' ' -f2 | cut -d'/' -f1)
  wazuh_version=$(awk -F'"' '/"version"[ \t]*:/ {print $4}' $extracted_directory/VERSION.json)

  # Add commit hash to the VERSION.json file
  pushd $extracted_directory
  short_commit_hash=$(curl -ks "https://api.github.com/repos/wazuh/wazuh/commits/${reference}" | awk -F '"' '/"sha":/ {print substr($4, 1, 7); exit}')
  /usr/bin/nawk -v commit="$short_commit_hash" '
  {
      lines[NR] = $0  # Store lines in an array
  }
  END {
      last_index = NR  # Save the last line index
      for (i = 1; i <= last_index; i++) {
          if (i == last_index) {  # When reaching the last line (assumed to be "}")
              if (lines[i-1] !~ /,$/)  # If the previous line does not end with a comma, add one
                  lines[i-1] = lines[i-1] ",";

              print lines[i-1];  # Print the modified previous line
              print "    \"commit\": \"" commit "\"";  # Insert commit using the passed variable
              print lines[i];  # Print the closing brace
          } else if (i < last_index - 1) {
              print lines[i];  # Print all other lines unchanged
          }
      }
  }
  ' VERSION.json > VERSION.json.tmp && mv VERSION.json.tmp VERSION.json
  cat VERSION.json

  # Remove the temporary file after processing (if any remains)
  [ -f VERSION.json.tmp ] && rm VERSION.json.tmp
  popd

  cp -pr ${extracted_directory} wazuh-agent-${wazuh_version}

  rpm_build_dir="/opt/freeware/src/packages"
  mkdir -p ${rpm_build_dir}/BUILD
  mkdir -p ${rpm_build_dir}/BUILDROOT
  mkdir -p ${rpm_build_dir}/RPMS
  mkdir -p ${rpm_build_dir}/SOURCES
  mkdir -p ${rpm_build_dir}/SPECS
  mkdir -p ${rpm_build_dir}/SRPMS

  package_name=wazuh-agent-${wazuh_version}
  tar cf ${package_name}.tar ${package_name} && gzip ${package_name}.tar
  mv ${package_name}.tar.gz ${rpm_build_dir}/SOURCES/

  cp ${current_path}/SPECS/wazuh-agent-aix.spec ${rpm_build_dir}/SPECS/${package_name}-aix.spec

  socket_lib=$(find /opt/freeware/lib/gcc/*/6.3.0/include-fixed/sys/ -name socket.h)

  if [[ ${aix_major} = "6" ]] && [[ -f ${socket_lib} ]]; then
    mv ${socket_lib} ${socket_lib}.backup
  fi

  init_scripts="/etc/rc.d/init.d"
  sysconfdir="/etc"

  rpm --define '_tmppath /tmp' --define "_topdir ${rpm_build_dir}" --define "_localstatedir ${install_path}" \
  --define "_init_scripts ${init_scripts}" --define "_sysconfdir ${sysconfdir}" --define "_version ${wazuh_version}" \
  --define "_release ${revision}" -bb ${rpm_build_dir}/SPECS/${package_name}-aix.spec

  if [[ ${aix_major} = "6" ]]; then
    mv ${ignored_lib}.backup ${ignored_lib}
  fi

  # If they exist, remove the installed files in ${install_path}
  rm -rf ${install_path} /etc/ossec-init.conf
  find /etc/ -name "*wazuh*" -exec rm {} \;

  if [[ ! -d ${target_dir} ]]; then
    mkdir -p ${target_dir}
  fi

  rpm_file=${package_name}-${revision}.aix${aix_major}.${aix_minor}.ppc.rpm
  mv ${rpm_build_dir}/RPMS/ppc/${rpm_file} ${target_dir}

  if [[ -f ${target_dir}/${rpm_file} ]]; then
    echo "Your package ${rpm_file} is stored in ${target_dir}"
    if [[ "${compute_checksums}" = "yes" ]]; then
      cd ${target_dir}
      pkg_checksum="$(openssl dgst -sha512 ${rpm_file} | cut -d' ' -f "2")"
      echo "${pkg_checksum}  ${rpm_file}" > "${checksum_dir}/${rpm_file}.sha512"
    fi
  else
    echo "Error: RPM package could not be created"
    exit 1
  fi

  return 0
}

# Main function, processes user input
main() {
  # If the script is called without arguments
  # show the help
  if [[ -z $1 ]] ; then
    show_help 0
  fi

  build_env="no"
  build_rpm="no"

  while [ -n "$1" ]
  do
    case $1 in
        "-b"|"--branch")
          if [ -n "$2" ]
          then
            reference="$2"
            build_rpm="yes"
            shift 2
          else
              show_help 1
          fi
        ;;
        "-r"|"--revision")
          if [ -n "$2" ]
          then
            revision="$2"
            shift 2
          else
              show_help 1
          fi
        ;;
        "-e"|"--environment" )
          build_environment
          exit 0
        ;;
        "-p"|"--install-path")
          if [ -n "$2" ]
          then
              install_path="$2"
              shift 2
          else
              show_help 1
          fi
        ;;
        "-s"|"--store")
          if [ -n "$2" ]
          then
              target_dir="$2"
              shift 2
          else
              show_help 1
          fi
        ;;
        "-c" | "--checksum")
            if [ -n "$2" ]; then
                checksum_dir="$2"
                compute_checksums="yes"
                shift 2
            else
                compute_checksums="yes"
                shift 1
            fi
        ;;
        "-h"|"--help")
          show_help
          exit 0
        ;;
        *)
          show_help 1
    esac
  done

  check_openssl || exit 1

  if [[ "${build_env}" = "yes" ]]; then
    build_environment || exit 1
  fi

  if [ -z "${checksum_dir}" ]; then
    checksum_dir="${target_dir}"
  fi

  if [[ "${build_rpm}" = "yes" ]]; then
    build_package || exit 1
  fi

  return 0
}

main "$@"
