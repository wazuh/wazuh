#!/bin/bash

detect_os_variant()
{
        # when invoked with no option, `uname` assumes -s
        case `uname` in
                Linux)
                ### RedHat and variants ###
                        if [ -f /etc/redhat-release ]
                        then
                                case `awk {'print $1'} /etc/redhat-release` in
                                        Red)
                                                DISTRO='RedHat' ;;
                                        CentOS)
                                                DISTRO='CentOS' ;;
                                esac
                                VER=`egrep -o "([[:digit:]]\.?)+" /etc/redhat-release`

				grep -q "Server" /etc/redhat-release
				if [ $? -eq 0 ]
				then
					ROLE="Server"
				else
					ROLE="Workstation"
				fi

                ### SuSE and variants ###
                        elif [ -f /etc/SuSE-release ]
                        then
                                DISTRO='SUSE'
                                VER=`grep VERSION /etc/SuSE-release | awk '{print $NF}'`.`grep PATCHLEVEL /etc/SuSE-release | awk '{print $NF}'`
                                #VER=`grep VERSION /etc/SuSE-release | awk '{print $NF}'`

		### Debian and variants ###
                        elif [ -f /etc/debian_version ]
                        then
                                DISTRO='Debian'
                                VER=`egrep -o "([[:digit:]]\.?)+" /etc/debian_version`

                                # Ubuntu appears to not use numbers...
                                if [ ! $VER ]
                                then
                                        DISTRO='Ubuntu'
                                        VER=`egrep "VERSION_ID=.*" /etc/os-release | egrep -o "([[:digit:]]\.?)+"`
                                fi
                        else
                                DISTRO='Linux'
                        fi
                ;;
                HP-UX)
                        DISTRO="HPUX"
                        VER=`uname -v | cut -d"." -f 2`
                ;;
                AIX)
                        DISTRO="AIX"
                        VER=`uname -v`.`uname -r`
                ;;
                Darwin)
                        DISTRO='OSX'
                        VER=`uname -r`
                ;;
                SunOS)
                        DISTRO='Solaris'
                        VER=`uname -r`
                        OSV=`uname -v`
                ;;

#               *)
#                       DISTRO='<Unknown_Platform>'
#                       VER='<Unknown_Version>'
        esac
}
