#!/bin/bash
# Program to build and sign debian packages, and upload those to a public reprepro repository.
# Copyright (c) 2015 Santiago Bassett <santiago.bassett@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

#
# CONFIGURATION VARIABLES
#

ossec_version='2.8.2'
source_file="ossec-hids-${ossec_version}.tar.gz"
#packages=(ossec-hids ossec-hids-agent) # only options available
packages=(ossec-hids ossec-hids-agent)

# codenames=(sid jessie wheezy precise trusty utopic) 
codenames=(sid jessie wheezy precise trusty utopic) 

# For Debian use: sid, jessie or wheezy (hardcoded in update_changelog function)
# For Ubuntu use: lucid, precise, trusty or utopic
codenames_ubuntu=(precise trusty utopic)
codenames_debian=(sid jessie wheezy)

# architectures=(amd64 i386) only options available
architectures=(amd64 i386)

# GPG key
signing_key='XXXX'
signing_pass='XXXX'

# Debian files
debian_files_path="/home/ubuntu/debian_files"

# Setting up logfile
scriptpath=$( cd $(dirname $0) ; pwd -P )
logfile=$scriptpath/ossec_packages.log


#
# Function to write to LOG_FILE
#
write_log() 
{
  if [ ! -e "$logfile" ] ; then
    touch "$logfile"
  fi
  while read text
  do 
      local logtime=`date "+%Y-%m-%d %H:%M:%S"`
      echo $logtime": $text" | tee -a $logfile;
  done
}


#
# Check if element is in an array
# Arguments: element array
#
contains_element() {
  local e
  for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 0; done
  return 1
}


#
# Show help function
#
show_help()
{ 
  echo "
  This tool can be used to generate OSSEC packages for Ubuntu and Debian.

  CONFIGURATION: The script is currently configured with the following variables:
    * Packages: ${packages[*]}. 
    * Distributions: ${codenames[*]}. 
    * Architectures: ${architectures[*]}.
    * OSSEC version: ${ossec_version}.
    * Source file: ${source_file}.
    * Signing key: ${signing_key}.

  USAGE: Command line arguments available:
    -h | --help     Displays this help.
    -u | --update   Updates chroot environments.
    -d | --download Downloads source file and prepares source directories.
    -b | --build    Builds deb packages.
    -s | --sync     Synchronizes with the apt-get repository.
  "
}


#
# Reads latest package version from changelog file
# Argument: changelog_file
#
read_package_version()
{
  if [ ! -e "$1" ] ; then
    echo "Error: Changelog file $1 does not exist" | write_log
    exit 1
  fi
  local regex="^ossec-hids[A-Za-z-]* \([0-9]+.*[0-9]*.*[0-9]*-([0-9]+)[A-Za-z]*\)"
  while read line
  do
    if [[ $line =~ $regex ]]; then
      package_version="${BASH_REMATCH[1]}"
      break
    fi
  done < $1
  local check_regex='^[0-9]+$'
  if ! [[ ${package_version} =~ ${check_regex} ]]; then
    echo "Error: Package version could not be read from $1" | write_log
    exit 1
  fi
}


#
# Updates changelog file with new codename, date and debdist.
# Arguments: changelog_file codename
#
update_changelog()
{
  local changelog_file=$1
  local changelog_file_tmp="${changelog_file}.tmp"
  local codename=$2

  if [ ! -e "$1" ] ; then
    echo "Error: Changelog file $1 does not exist" | write_log
    exit 1
  fi

  local check_codenames=( ${codenames_debian[*]} ${codenames_ubuntu[*]} )
  if ! contains_element $codename ${check_codenames[*]} ; then
    echo "Error: Codename $codename not contained in codenames for Debian or Ubuntu" | write_log
    exit 1
  fi

  # For Debian
  if [ $codename = "sid" ]; then
    local debdist="unstable"
  elif [ $codename = "jessie" ]; then
    local debdist="testing"
  elif [ $codename = "wheezy" ]; then
    local debdist="stable"
  fi

  # For Ubuntu
  if contains_element $codename ${codenames_ubuntu[*]} ; then
    local debdist=$codename
  fi
  
  # Modifying file
  local changelogtime=$(date -R)
  local last_date_changed=0

  local regex1="^(ossec-hids[A-Za-z-]* \([0-9]+.*[0-9]*.*[0-9]*-[0-9]+)[A-Za-z]*\)"
  local regex2="( -- [[:alnum:]]*[^>]*>  )[[:alnum:]]*,"

  if [ -f ${changelog_file_tmp} ]; then
    rm -f ${changelog_file_tmp}
  fi
  touch ${changelog_file_tmp}

  IFS='' #To preserve line leading whitespaces
  while read line
  do
    if [[ $line =~ $regex1 ]]; then
      line="${BASH_REMATCH[1]}$codename) $debdist; urgency=low"
    fi
    if [[ $line =~ $regex2 ]] && [ $last_date_changed -eq 0 ]; then
      line="${BASH_REMATCH[1]}$changelogtime"
      last_date_changed=1
    fi
    echo "$line" >> ${changelog_file_tmp}
  done < ${changelog_file}

  mv ${changelog_file_tmp} ${changelog_file}
}


#
# Update chroot environments
#
update_chroots()
{
  for codename in ${codenames[@]}
  do
    for arch in ${architectures[@]}
    do
      echo "Updating chroot environment: ${codename}-${arch}" | write_log
      if sudo DIST=$codename ARCH=$arch pbuilder update ; then
        echo "Successfully updated chroot environment: ${codename}-${arch}" | write_log
      else
        echo "Error: Problem detected updating chroot environment: ${codename}-${arch}" | write_log
      fi
    done
  done
}


#
# Downloads packages and prepare source directories.
# This is needed before building the packages.
#
download_source()
{

  # Checking that Debian files exist for this version
  for package in ${packages[*]}
  do
    if [ ! -d ${debian_files_path}/${ossec_version}/$package/debian ]; then
      echo "Error: Couldn't find debian files directory for $package, version ${ossec_version}" | write_log
      exit 1
    fi
  done

  # Downloading file
  if wget -O $scriptpath/${source_file} -U ossec https://github.com/ossec/ossec-hids/archive/${ossec_version}.tar.gz ; then
    echo "Successfully downloaded source file ${source_file} from ossec.net" | write_log
  else
    echo "Error: File ${source_file} was could not be downloaded" | write_log
    exit 1
  fi

  # Uncompressing files
  tmp_directory=$(echo ${source_file} | sed -e 's/.tar.gz$//')
  if [ -d ${scriptpath}/${tmp_directory} ]; then
    echo " + Deleting previous directory ${scriptpath}/${tmp_directory}" | write_log
    sudo rm -rf ${scriptpath}/${tmp_directory}
  fi
  tar -xvzf ${scriptpath}/${source_file}
  if [ ! -d ${scriptpath}/${tmp_directory} ]; then
    echo "Error: Couldn't find uncompressed directory, named ${tmp_directory}" | write_log
    exit 1
  fi

  # Organizing directories structure
  for package in ${packages[*]}
  do
    if [ -d ${scriptpath}/$package ]; then
      echo " + Deleting previous source directory ${scriptpath}/$package" | write_log
      sudo rm -rf ${scriptpath}/$package
    fi
    mkdir $scriptpath/$package
    cp -pr $scriptpath/${tmp_directory} $scriptpath/$package/$package-${ossec_version}
    cp -p $scriptpath/${source_file} $scriptpath/$package/${package}_${ossec_version}.orig.tar.gz
    cp -pr ${debian_files_path}/${ossec_version}/$package/debian $scriptpath/$package/${package}-${ossec_version}/debian
  done
  rm -rf $scriptpath/${tmp_directory}

  echo "The packages directories for ${packages[*]} version ${ossec_version} have been successfully prepared." | write_log
}


#
# Build packages
#
build_packages()
{

for package in ${packages[@]}
do 
  for codename in ${codenames[@]}
  do
    for arch in ${architectures[@]}
    do

      echo "Building Debian package ${package} ${codename}-${arch}" | write_log

      local source_path="$scriptpath/${package}/${package}-${ossec_version}"
      local changelog_file="${source_path}/debian/changelog"
      if [ ! -f ${changelog_file} ] ; then
        echo "Error: Couldn't find changelog file for ${package}-${ossec_version}" | write_log
        exit 1
      fi
      
      # Updating changelog file with new codename, date and debdist.
      if update_changelog ${changelog_file} ${codename} ; then
        echo " + Changelog file ${changelog_file} updated for $package ${codename}-${arch}" | write_log
      else
        echo "Error: Changelog file ${changelog_file} for $package ${codename}-${arch} could not be updated" | write_log
        exit 1
      fi

      # Setting up global variable package_version, used for deb_file and changes_file
      read_package_version ${changelog_file}      
      local deb_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.deb"
      local changes_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.changes"
      local dsc_file="${package}_${ossec_version}-${package_version}${codename}.dsc"
      local results_dir="/var/cache/pbuilder/${codename}-${arch}/result/${package}"
      local base_tgz="/var/cache/pbuilder/${codename}-${arch}-base.tgz"
      local cache_dir="/var/cache/pbuilder/${codename}-${arch}/aptcache"

      # Creating results directory if it does not exist
      if [ ! -d ${results_dir} ]; then
        sudo mkdir -p ${results_dir}
      fi

      # Building the package
      cd ${source_path}
      if sudo /usr/bin/pdebuild --use-pdebuild-internal --architecture ${arch} --buildresult ${results_dir} -- --basetgz \
      ${base_tgz} --distribution ${codename} --architecture ${arch} --aptcache ${cache_dir} --override-config ; then
        echo " + Successfully built Debian package ${package} ${codename}-${arch}" | write_log
      else
        echo "Error: Could not build package $package ${codename}-${arch}" | write_log
        exit 1
      fi

      # Checking that resulting debian package exists
      if [ ! -f ${results_dir}/${deb_file} ] ; then
        echo "Error: Could not find ${results_dir}/${deb_file}" | write_log
        exit 1
      fi
      
      # Checking that package has at least 50 files to confirm it has been built correctly
      local files=$(sudo /usr/bin/dpkg --contents ${results_dir}/${deb_file} | wc -l)
      if [ "${files}" -lt "50" ]; then
        echo "Error: Package ${package} ${codename}-${arch} contains only ${files} files" | write_log
        echo "Error: Check that the Debian package has been built correctly" | write_log
        exit 1
      else
        echo " + Package ${results_dir}/${deb_file} ${codename}-${arch} contains ${files} files" | write_log
      fi

      # Signing Debian package
      if [ ! -f "${results_dir}/${changes_file}" ] || [ ! -f "${results_dir}/${dsc_file}" ] ; then
        echo "Error: Could not find dsc and changes file in ${results_dir}" | write_log
        exit 1
      fi
      sudo /usr/bin/expect -c "
        spawn sudo debsign --re-sign -k${signing_key} ${results_dir}/${changes_file}
        expect -re \".*Enter passphrase:.*\"
        send \"${signing_pass}\r\"
        expect -re \".*Enter passphrase:.*\"
        send \"${signing_pass}\r\"
        expect -re \".*Successfully signed dsc and changes files.*\"
      "
      if [ $? -eq 0 ] ; then
        echo " + Successfully signed Debian package ${changes_file} ${codename}-${arch}" | write_log
      else
        echo "Error: Could not sign Debian package ${changes_file} ${codename}-${arch}" | write_log
        exit 1
      fi

      # Verifying signed changes and dsc files
      if sudo gpg --verify "${results_dir}/${dsc_file}" && sudo gpg --verify "${results_dir}/${changes_file}" ; then
        echo " + Successfully verified GPG signature for files ${dsc_file} and ${changes_file}" | write_log
      else
        echo "Error: Could not verify GPG signature for ${dsc_file} and ${changes_file}" | write_log
        exit 1
      fi

      echo "Successfully built and signed Debian package ${package} ${codename}-${arch}" | write_log

    done
  done
done
}

# Synchronizes with the external repository, uploading new packages and ubstituting old ones.
sync_repository()
{
for package in ${packages[@]}
do
  for codename in ${codenames[@]}
  do
    for arch in ${architectures[@]}
    do

      # Reading package version from changelog file
      local source_path="$scriptpath/${package}/${package}-${ossec_version}"
      local changelog_file="${source_path}/debian/changelog"
      if [ ! -f ${changelog_file} ] ; then
        echo "Error: Couldn't find ${changelog_file} for package ${package} ${codename}-${arch}" | write_log
        exit 1
      fi

      # Setting up global variable package_version, used for deb_file and changes_file.
      read_package_version ${changelog_file}
      local deb_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.deb"
      local changes_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.changes"
      local results_dir="/var/cache/pbuilder/${codename}-${arch}/result/${package}"
      if [ ! -f ${results_dir}/${deb_file} ] || [ ! -f ${results_dir}/${changes_file} ] ; then
        echo "Error: Coudn't find ${deb_file} or ${changes_file}" | write_log
        exit 1
      fi

      # Uploading package to repository
      cd ${results_dir}
      echo "Uploading package ${changes_file} for ${codename} to OSSEC repository" | write_log
      if sudo /usr/bin/dupload --nomail -f --to ossec-repository ${changes_file} ; then
        echo " + Successfully uploaded package ${changes_file} for ${codename} to OSSEC repository" | write_log
      else
        echo "Error: Could not upload package ${changes_file} for ${codename} to the repository" | write_log
        exit 1
      fi 

      # Checking if it is an Ubuntu package
      if contains_element $codename ${codenames_ubuntu[*]} ; then
        local is_ubuntu=1
      else
        local is_ubuntu=0
      fi

      # Moving package to the right directory at the OSSEC apt repository server
      echo " + Adding package /opt/incoming/${deb_file} to server repository for ${codename} distribution" | write_log
      if [ $is_ubuntu -eq 1 ]; then 
        remove_package="cd /var/www/repos/apt/ubuntu; reprepro -A ${arch} remove ${codename} ${package}"
        include_package="cd /var/www/repos/apt/ubuntu; reprepro includedeb ${codename} /opt/incoming/${deb_file}"
      else
        remove_package="cd /var/www/repos/apt/debian; reprepro -A ${arch} remove ${codename} ${package}"
        include_package="cd /var/www/repos/apt/debian; reprepro includedeb ${codename} /opt/incoming/${deb_file}"
      fi

      /usr/bin/expect -c "
        spawn sudo ssh root@ossec-repository \"${remove_package}\"
        expect -re \"Not removed as not found.*\" { exit 1 }
        expect -re \".*enter passphrase:.*\" { send \"${signing_pass}\r\" }
        expect -re \".*enter passphrase:.*\" { send \"${signing_pass}\r\" }
        expect -re \".*deleting.*\"
      "
      
      /usr/bin/expect -c "
        spawn sudo ssh root@ossec-repository \"${include_package}\"
        expect -re \"Skipping inclusion.*\" { exit 1 }
        expect -re \".*enter passphrase:.*\"
        send \"${signing_pass}\r\"
        expect -re \".*enter passphrase:.*\"
        send \"${signing_pass}\r\"
        expect -re \".*Exporting.*\"
      "
      echo "Successfully added package ${deb_file} to server repository for ${codename} distribution" | write_log
    done
  done
done
}


# If there are no arguments, display help
if [ $# -eq 0 ]; then
  show_help
  exit 0
fi

# Reading command line arguments
while [[ $# > 0 ]]
do
key="$1"
shift

case $key in
  -h|--help)
    show_help
    exit 0
    ;;
  -u|--update)
    update_chroots
    shift
    ;;
  -d|--download)
    download_source
    shift
    ;;
  -b|--build)
    build_packages
    shift
    ;;
  -s|--sync)
    sync_repository
    shift
    ;;
  *)
    echo "Unknown command line argument."
    show_help
    exit 0
    ;;
  esac
done

# vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2
