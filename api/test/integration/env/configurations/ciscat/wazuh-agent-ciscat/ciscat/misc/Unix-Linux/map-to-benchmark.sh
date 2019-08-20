#!/bin/bash

map_to_benchmark()
{
        _DISTRO=$1
        _VER=$2

        case $_DISTRO in
                OSX)
                        # OSX 10.5
                        if [ `expr $_VER \>= 9.0 \& $_VER \< 10.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.5_Benchmark_v.1.1.0.xml"
                                PROFILE1="Level 1 Profile"
                                PROFILE2="Level 2 Profile"
                                ARFORXML="-x"
                        fi

                        # OSX 10.6
                        if [ `expr $_VER \>= 10.0 \& $_VER \< 11.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.6_Benchmark_v.1.0.0.xml"
                                PROFILE1="Level 1 Profile"
                                PROFILE2="Level 2 Profile"
                                ARFORXML="-x"
                        fi

                        # OSX 10.8
                        if [ `expr $_VER \>= 12.0 \& $_VER \< 13.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.8_Benchmark_v1.3.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi

                        # OSX 10.9
                        if [ `expr $_VER \>= 13.0 \& $_VER \< 14.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.9_Benchmark_v1.3.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi

                        # OSX 10.10
                        if [ `expr $_VER \>= 14.0 \& $_VER \< 15.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.10_Benchmark_v1.2.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi

                        # OSX 10.11
                        if [ `expr $_VER \>= 15.0 \& $_VER \< 16.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.11_Benchmark_v1.1.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi

                        # OSX 10.12
                        if [ `expr $_VER \>= 16.0 \& $_VER \< 17.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.12_Benchmark_v1.0.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi

                        ;;
                Debian)
                        if [ `expr $_VER \>= 4 \& $_VER \< 7` -eq 1 ]
                        then
                                BENCHMARK="CIS_Debian_Linux_3_Benchmark_v1.0.0.xml"
                                PROFILE1="debian-level-1-profile"
                                PROFILE2="debian-complete-profile"
                                ARFORXML="-x"
                        fi

                        if [ `expr $_VER \>= 7 \& $_VER \< 8` -eq 1 ]
                        then
                                BENCHMARK="CIS_Debian_Linux_7_Benchmark_v1.0.0-xccdf.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                        fi

                        if [ `expr $_VER \>= 8` -eq 1 ]
                        then
                                BENCHMARK="CIS_Debian_Linux_8_Benchmark_v1.0.0-xccdf.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                        fi

                        ;;
                Ubuntu)
                	# Ubuntu 12.04
                        if [ `expr $_VER == 12.04` -eq 1 ]
                        then
				BENCHMARK="CIS_Ubuntu_12.04_LTS_Server_Benchmark_v1.1.0.xml"
				PROFILE1="Level 1"
				PROFILE2="Level 2"
                                ARFORXML="-x"
			fi
			
			# Ubuntu 14.04
                        if [ `expr $_VER == 14.04` -eq 1 ]
                        then
				BENCHMARK="CIS_Ubuntu_Linux_14.04_LTS_Benchmark_v2.0.0-xccdf.xml"
				PROFILE1="Level 1 - Server"
				PROFILE2="Level 2 - Server"
			fi
                        
                        # Ubuntu 16.04
                        if [ `expr $_VER == 16.04` -eq 1 ]
                        then
                                BENCHMARK="CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml"
                                PROFILE1="Level 1 - Server"
                                PROFILE2="Level 2 - Server"
                        fi
			
			;;
                HPUX)
                        if [ `expr $_VER \>= 11 \& $_VER \< 12` -eq 1 ]
                        then
                                BENCHMARK="CIS_HP-UX_11i_Benchmark_v1.4.2.xml"
                                PROFILE1="Level 1 Profile"
                                PROFILE2="Level 2 Profile"
                                ARFORXML="-x"
                        fi

                        ;;
                AIX)
                        # AIX 4.3 - 5.1
                        if [ `expr $_VER \>= 4.3 \& $_VER \< 5.2` -eq 1 ]
                        then
                                BENCHMARK="CIS_IBM_AIX_4.3-5.1_Benchmark_v1.0.1.xml"
                                PROFILE1="Level 1 Profile"
                                PROFILE2="Level 1 Profile"
                                ARFORXML="-x"
                        fi

                        # AIX 5.3 - 6.1
                        if [ `expr $_VER \>= 5.3 \& $_VER \< 6.2` -eq 1 ]
                        then
                                BENCHMARK="CIS_IBM_AIX_5.3-6.1_Benchmark_v1.1.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi

                        # AIX 7.1
                        if [ `expr $_VER \>= 7.1 \& $_VER \< 7.2` -eq 1 ]
                        then
                                BENCHMARK="CIS_IBM_AIX_7.1_Benchmark_v1.1.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        fi


                        ;;
                RedHat)
                        # RHEL 4
                        if [ `expr $_VER \>= 4.0 \& $_VER \< 5.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_4_Benchmark_v1.0.5.xml"
                                PROFILE1="Level 1 Profile"
                                PROFILE2="Level 1 Profile"
                                ARFORXML="-x"
                        fi

                        # RHEL 5
                        if [ `expr $_VER \>= 5.0 \& $_VER \< 6.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.2.0-xccdf.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                        fi

                        # RHEL 6
                        if [ `expr $_VER \>= 6.0 \& $_VER \< 7.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v2.0.2-xccdf.xml"
                                PROFILE1="Level 1 - ${ROLE}"
                                PROFILE2="Level 2 - ${ROLE}"
                        fi

                        # RHEL 7
                        if [ `expr $_VER \>= 7.0 \& $_VER \< 8.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v2.1.1-xccdf.xml"
                                PROFILE1="Level 1 - ${ROLE}"
                                PROFILE2="Level 2 - ${ROLE}"
                        fi

                        ;;
                CentOS)
                	# CentOS 6
			if [ `expr $_VER \>= 6.0 \& $_VER \< 7.0` -eq 1 ]
			then
				BENCHMARK="CIS_CentOS_Linux_6_Benchmark_v2.0.2-xccdf.xml"
				PROFILE1="Level 1 - ${ROLE}"
				PROFILE2="Level 2 - ${ROLE}"
			fi
			
                	# CentOS 7
			if [ `expr $_VER \>= 7.0 \& $_VER \< 8.0` -eq 1 ]
			then
				BENCHMARK="CIS_CentOS_Linux_7_Benchmark_v2.1.1-xccdf.xml"
				PROFILE1="Level 1 - ${ROLE}"
				PROFILE2="Level 2 - ${ROLE}"
			fi
			
                        ;;
                SUSE)
                        # SUSE 12
                        if [ `expr $_VER \>= 12.0 \& $_VER \< 13.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v2.0.0-xccdf.xml"
				PROFILE1="Level 1 - Workstation"
				PROFILE2="Level 2 - Workstation"
                        fi

                        # SUSE 11
                        if [ `expr $_VER \>= 11.0 \& $_VER \< 12.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v2.0.0-xccdf.xml"
                                PROFILE1="Level 1 - Workstation"
                                PROFILE2="Level 2 - Workstation"
                        fi

                        # SUSE 10
                        if [ `expr $_VER \>= 10.0 \& $_VER \< 11.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_SUSE_Linux_Enterprise_Server_10_Benchmark_v2.0.0.xml"
                                PROFILE1="profile-reduced"
                                PROFILE2="profile-complete"
                                ARFORXML="-x"
                        fi

                        # SUSE 9
                        if [ `expr $_VER \>= 9.0 \& $_VER \< 10.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_SUSE_Linux_Enterprise_Server_9_Benchmark_v1.0.0.xml"
                                PROFILE1="profile-reduced"
                                PROFILE2="profile-complete"
                                ARFORXML="-x"
                        fi

                        ;;

                Solaris)

                        # Solaris 11, 11.1, 11.2
                        if [ `expr $_VER == 5.11` -eq 1 ]
                        then
                                if [ `expr $_OSV == 11.1` -eq 1 ]
                                then
                                        BENCHMARK="CIS_Oracle_Solaris_11.1_Benchmark_v1.0.0.xml"
                                elif [ `expr $_OSV == 11.2` -eq 1 ]
                                then
                                        BENCHMARK="CIS_Oracle_Solaris_11.2_Benchmark_v1.1.0.xml"
                                else
                                        BENCHMARK="CIS_Oracle_Solaris_11_Benchmark_v1.1.0.xml"
                                fi
                                
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        
                        # Solaris 10
                        elif [ `expr $_VER == 5.10` -eq 1 ]
                        then
                                BENCHMARK="CIS_Oracle_Solaris_10_Benchmark_v5.2.0.xml"
                                PROFILE1="Level 1"
                                PROFILE2="Level 2"
                                ARFORXML="-x"
                        else
                                # Solaris 2.5.1-9
                                BENCHMARK="CIS_Oracle_Solaris_2.5.1-9_Benchmark_v1.3.0.xml"
                                PROFILE1="Level 1 Profile"
                                PROFILE2="Level 1 Profile"
                                ARFORXML="-x"
                        fi

                        ;;

                        #
                        # CIS_Slackware_Linux_10.2_Benchmark_v1.1.0.xml SlackWare benchmark is not integrated.
                        #       

#               *)
#
#
#                       ;;
        esac
}
