#!/bin/sh
# Installation script for the OSSEC HIDS
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Mar 02, 2006

# Changelog 19/03/2006 - Rafael M. Capovilla <under@underlinux.com.br>
# New function AddWhite to allow users to add more Ips in the white_list
# Minor *echos* modifications to better look
# Bug fix - When email address is blank
# Bug fix - delete INSTALLDIR - Default is yes but if the user just press enter the script wasn't deleting it as it should


### Looking up for the execution directory
LOCAL=`dirname $0`;
cd $LOCAL


### Looking for for echo -n
ECHO="echo -n"
hs=`echo -n "a"`
if [ ! "X$hs" = "Xa" ]; then
    ls "/usr/ucb/echo" > /dev/null 2>&1
    if [ $? = 0 ]; then
        ECHO="/usr/ucb/echo"
    else
        ECHO=echo
    fi
fi

# For solaris
echo "xxxx" | grep -E "xxx" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "/usr/xpg4/bin/grep" > /dev/null 2>&1
    if [ $? = 0 ]; then
        PATH=/usr/xpg4/bin:$PATH
    fi
fi


# Checking for command line arguments
if [ "X$1" = "Xdebug" ]; then
    SET_DEBUG="debug"
else
    SET_DEBUG=""    
fi    


##########
# install()
##########
Install()
{
	echo ""
	echo "5- ${installing}"
    
	echo "DIR=\"${INSTALLDIR}\"" > ${LOCATION}
    echo "CC=${CC}" >> ${LOCATION}
    
    # Changing Config.OS with the new C flags
    # Checking if debug is enabled
    if [ "X${SET_DEBUG}" = "Xdebug" ]; then
        CEXTRA="${CEXTRA} -DDEBUGAD"
    fi
        
    echo "CEXTRA=${CEXTRA}" > ./src/Config.OS
    
    # Makefile
	echo " - ${runningmake}"
    cd ./src
    make all
    
    if [ $? != 0 ]; then
        catError "0x5-build"
    fi
        
    # Building everything    
    make build

    # If update, stop ossec
    if [ "X${update_only}" = "Xyes" ]; then
        UpdateStopOSSEC
    fi    
    
    # Making the right installation type
	if [ "X$INSTYPE" = "Xserver" ]; then
		make server
	
    elif [ "X$INSTYPE" = "Xagent" ]; then 
		make agent

    elif [ "X$INSTYPE" = "Xlocal" ]; then
        make local    
	fi

    cd ../
   
   
    # Generate the /etc/ossec-init.conf
    echo "DIRECTORY=\"${INSTALLDIR}\"" > ${OSSEC_INIT}
    echo "VERSION=\"${VERSION}\"" >> ${OSSEC_INIT}
    echo "DATE=\"`date`\"" >> ${OSSEC_INIT}
    echo "TYPE=\"${INSTYPE}\"" >> ${OSSEC_INIT}
    chmod 600 ${OSSEC_INIT}
    

    # If update_rules is set, we need to tweak 
    # ossec.conf to read the new signatures.
    if [ "X${update_rules}" = "Xyes" ]; then
        UpdateOSSECRules
    fi    

    # If update, start OSSEC
    if [ "X${update_only}" = "Xyes" ]; then
        UpdateStartOSSEC    
    fi    
     
    # Calling the init script  to start ossec hids during boot
    if [ "X${update_only}" = "X" ]; then
        runInit
        if [ $? = 1 ]; then
            notmodified="yes"
        fi 
    fi       
    	
}




##########
# UseSyscheck()
##########
UseSyscheck()
{

    # Integrity check config
    echo ""
    $ECHO "  3.2- ${runsyscheck} ($yes/$no) [$yes]: "
    if [ "X${USER_ENABLE_SYSCHECK}" = "X" ]; then
        read AS
    else
        AS=${USER_ENABLE_SYSCHECK}
    fi        
    echo ""
    case $AS in
        $nomatch)
            echo "   - ${nosyscheck}."
            ;;
        *)
            SYSCHECK="yes"
            echo "   - ${yessyscheck}."
            ;;
    esac 

    # Adding to the config file
    if [ "X$SYSCHECK" = "Xyes" ]; then
        cat ${SYSCHECK_TEMPLATE} >> $NEWCONFIG
    fi
}




##########
# UseRootcheck()
##########
UseRootcheck()
{

    # Rootkit detection configuration 
    echo ""
    $ECHO "  3.3- ${runrootcheck} ($yes/$no) [$yes]: "
    
    if [ "X${USER_ENABLE_ROOTCHECK}" = "X" ]; then
        read ES
    else
        ES=${USER_ENABLE_ROOTCHECK}
    fi    
    
    echo ""
    case $ES in
        $nomatch)
            echo "   - ${norootcheck}."
            ;;
        *)
            ROOTCHECK="yes"
            echo "   - ${yesrootcheck}."
            ;;
    esac


    # Adding to the config file
    if [ "X$ROOTCHECK" = "Xyes" ]; then
        echo "" >> $NEWCONFIG
        echo "  <rootcheck>" >> $NEWCONFIG
        echo "    <rootkit_files>$INSTALLDIR/etc/shared/rootkit_files.txt</rootkit_files>" >> $NEWCONFIG
        echo "    <rootkit_trojans>$INSTALLDIR/etc/shared/rootkit_trojans.txt</rootkit_trojans>" >> $NEWCONFIG
        echo "  </rootcheck>" >> $NEWCONFIG
    fi            
}




##########
# SetupLogs()
##########
SetupLogs()
{

    NB=$1
    echo ""
    echo "  $NB- ${readlogs}"

    echo "  <!-- Files to monitor (localfiles) -->" >> $NEWCONFIG
    LOG_FILES=`cat ${SYSLOG_TEMPLATE}`
    for i in ${LOG_FILES}; do
        # If log file present, add it    
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "    -- $i"
	        echo "" >> $NEWCONFIG
	        echo "  <localfile>" >> $NEWCONFIG
    	    echo "    <log_format>syslog</log_format>" >> $NEWCONFIG
	        echo "    <location>$i</location>" >>$NEWCONFIG
	        echo "  </localfile>" >> $NEWCONFIG
        fi
    done    

    # Getting snort files
    SNORT_FILES=`cat ${SNORT_TEMPLATE}`
    for i in ${SNORT_FILES}; do
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "" >> $NEWCONFIG
            echo "  <localfile>" >> $NEWCONFIG
            
            head -n 1 $i|grep "\[**\] "|grep -v "Classification:" > /dev/null
            if [ $? = 0 ]; then
                echo "    <log_format>snort-full</log_format>" >> $NEWCONFIG
                echo "    -- $i (snort-full file)"
            else
                echo "    <log_format>snort-fast</log_format>" >> $NEWCONFIG
                echo "    -- $i (snort-fast file)"
            fi
            echo "    <location>$i</location>" >>$NEWCONFIG
            echo "  </localfile>" >> $NEWCONFIG    
        fi
    done    
    
    # Getting apache logs
    APACHE_FILES=`cat ${APACHE_TEMPLATE}`
    for i in ${APACHE_FILES}; do
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
          echo "" >> $NEWCONFIG
          echo "  <localfile>" >> $NEWCONFIG
          echo "    <log_format>apache</log_format>" >> $NEWCONFIG
          echo "    <location>$i</location>" >>$NEWCONFIG
          echo "  </localfile>" >> $NEWCONFIG
          
          echo "    -- $i (apache log)"
        fi
    done
   
    echo "" 
    catMsg "0x106-logs"


    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi
}




##########
# ConfigureClient()
##########
ConfigureClient()
{
	echo ""
	echo "3- ${configuring} $NAME."
	echo ""
  
    if [ "X${USER_AGENT_SERVER_IP}" = "X" ]; then
        # Looping and asking for server ip  
        while [ 1 ]; do
	    $ECHO "  3.1- ${serverip}: "
	        read IPANSWER
            echo $IPANSWER | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" > /dev/null 2>&1
            if [ $? = 0 ]; then
	            echo ""
                IP=$IPANSWER
	            echo "   - ${addingip} $IP"
                break;
            fi
        done
    else
        IP=${USER_AGENT_SERVER_IP}
    fi    

    echo "<ossec_config>" > $NEWCONFIG	
    echo "  <client>" >> $NEWCONFIG
	echo "    <server-ip>$IP</server-ip>" >> $NEWCONFIG
	echo "  </client>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Syscheck?
    UseSyscheck

    # Rootcheck?
    UseRootcheck

    echo ""
    $ECHO "  3.4 - ${enable_ar} ($yes/$no) [$yes]: "

    if [ "X${USER_ENABLE_ACTIVE_RESPONSE}" = "X" ]; then
        read ANY
    else
        ANY=${USER_ENABLE_ACTIVE_RESPONSE}
    fi    
    
    case $ANY in
        $nomatch)
            echo ""
            echo "   - ${noactive}."
            echo "" >> $NEWCONFIG
            echo "  <active-response>" >> $NEWCONFIG
            echo "    <disabled>yes</disabled>" >> $NEWCONFIG
            echo "  </active-response>" >> $NEWCONFIG
            echo "" >> $NEWCONFIG
            ;;
        *)
            echo ""
            ;;
    esac

    # Set up the log files
    SetupLogs "3.5"

    echo "</ossec_config>" >> $NEWCONFIG
}




##########
# ConfigureServer()
##########
ConfigureServer()
{
	echo ""
	echo "3- ${configuring} $NAME."
	
    
    # Configuring e-mail notification
	echo ""
	$ECHO "  3.1- ${mailnotify} ($yes/$no) [$yes]: "
    
    if [ "X${USER_ENABLE_EMAIL}" = "X" ]; then
	read ANSWER
    else
        ANSWER=${USER_ENABLE_EMAIL}
    fi
        
	case $ANSWER in
		$nomatch)
            echo ""
			echo "   --- ${nomail}."
			EMAILNOTIFY="no"
			;;
		*)
			EMAILNOTIFY="yes"
			$ECHO "   - ${whatsemail} "
            if [ "X${USER_EMAIL_ADDRESS}" = "X" ]; then
			
                read EMAIL
                echo "${EMAIL}" | grep -E "^[a-zA-Z0-9_.-]{1,36}@[a-zA-Z0-9_.-]{1,54}$" > /dev/null 2>&1 ;RVAL=$?;
                # Ugly e-mail validation
			    while [ "$EMAIL" = "" -o ! ${RVAL} = 0 ] ; do
				    $ECHO "   - ${whatsemail} "
				    read EMAIL
                    echo "${EMAIL}" | grep -E "^[a-zA-Z0-9_.-]{1,36}@[a-zA-Z0-9_.-]{1,54}$" > /dev/null 2>&1 ;RVAL=$?;
			    done
            else
                EMAIL=${USER_EMAIL_ADDRESS}
            fi
                    
            ls ${HOST_CMD} > /dev/null 2>&1
            if [ $? = 0 ]; then
              HOSTTMP=`${HOST_CMD} -W 5 -t mx ossec.net 2>/dev/null`
              if [ $? = 1 ]; then
                 # Trying without the -W 
                 HOSTTMP=`${HOST_CMD} -t mx ossec.net 2>/dev/null`
              fi       
              if [ "X$HOSTTMP" = "X${OSSECMX}" -o "X$HOSTTMP" = "X${OSSECMX2}" ];then
                 # Breaking down the user e-mail
                 EMAILHOST=`echo ${EMAIL} | cut -d "@" -f 2`
                 if [ "X${EMAILHOST}" = "Xlocalhost" ]; then
                    SMTPHOST="127.0.0.1"
                 else       
                    HOSTTMP=`${HOST_CMD} -W 5 -t mx ${EMAILHOST}`
                    SMTPHOST=`echo ${HOSTTMP} | cut -d " " -f 7`
                 fi   
              fi    
            fi

            if [ "X${USER_EMAIL_SMTP}" = "X" ]; then
                if [ "X${SMTPHOST}" != "X" ]; then
                    echo ""
                    echo "   - ${yoursmtp}: ${SMTPHOST}"
                    $ECHO "   - ${usesmtp} ($yes/$no) [$yes]: "
                    read EMAIL2
                    case ${EMAIL2} in
                        $nomatch)
                        echo ""
                        SMTP=""
                        ;;
                    *)
                        SMTP=${SMTPHOST}
                        echo ""
                        echo "   --- ${usingsmtp} ${SMTP}"   
                        ;;
                    esac
                fi

                if [ "X${SMTP}" = "X" ]; then
			        $ECHO "   - ${whatsmtp} "
                    read SMTP
                fi  
            else
                SMTP=${USER_EMAIL_SMTP}
            fi             
        ;;
	esac


	# Writting global parameters 
    echo "<ossec_config>" > $NEWCONFIG 
	echo "  <global>" >> $NEWCONFIG
	if [ "$EMAILNOTIFY" = "yes" ]; then
		echo "    <email_notification>yes</email_notification>" >> $NEWCONFIG
		echo "    <email_to>$EMAIL</email_to>" >> $NEWCONFIG
		echo "    <smtp_server>$SMTP</smtp_server>" >> $NEWCONFIG
		echo "    <email_from>ossecm@${HOST}</email_from>" >> $NEWCONFIG
	else
		echo "    <email_notification>no</email_notification>" >> $NEWCONFIG
	fi
    
    echo "  </global>" >> $NEWCONFIG	
	echo "" >> $NEWCONFIG
    
	# Writting rules configuration
    cat ${RULES_TEMPLATE} >> $NEWCONFIG
	echo "" >> $NEWCONFIG


    # Checking if syscheck should run
    UseSyscheck
  
    # Checking if rootcheck should run
    UseRootcheck


    # Active response
    catMsg "0x107-ar"
    $ECHO "   - ${enable_ar} ($yes/$no) [$yes]: "
    
    if [ "X${USER_ENABLE_ACTIVE_RESPONSE}" = "X" ]; then
        read AR
    else
        AR=${USER_ENABLE_ACTIVE_RESPONSE}
    fi
        
    case $AR in
        $nomatch)
            echo ""
            echo "     - ${noactive}."
            echo "" >> $NEWCONFIG
            echo "  <active-response>" >> $NEWCONFIG
            echo "    <disabled>yes</disabled>" >> $NEWCONFIG
            echo "  </active-response>" >> $NEWCONFIG
            echo "" >> $NEWCONFIG
            ;;
        *)
            ACTIVERESPONSE="yes"
            echo ""
            catMsg "0x108-ar-enabled"
            
            echo ""
            $ECHO "   - ${firewallar} ($yes/$no) [$yes]: "
            
            if [ "X${USER_ENABLE_FIREWALL_RESPONSE}" = "X" ]; then
                read HD2
            else
                HD2=${USER_ENABLE_FIREWALL_RESPONSE}
            fi
                    
            echo ""
            case $HD2 in
                $nomatch)
                    echo "     - ${nofirewall}"
                    ;;
                *)
                    echo "     - ${yesfirewall} "
                    FIREWALLDROP="yes"
                    ;;
            esac        
            echo "" >> $NEWCONFIG
            echo "  <global>" >> $NEWCONFIG
            echo "    <white_list>127.0.0.1</white_list>" >> $NEWCONFIG
            echo ""
            echo "   - ${defaultwhitelist}"
            for ip in ${NAMESERVERS} ${NAMESERVERS2};
            do
            if [ "X${ip}" != "X" ]; then
                echo "      - ${ip}"
                echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
            fi
            done
            AddWhite

            echo "  </global>" >> $NEWCONFIG
            ;;
    esac                
    
    
    if [ "X$INSTYPE" = "Xserver" ]; then
      # Configuring remote syslog  
	  echo ""
	  $ECHO "  3.5- ${syslog} ($yes/$no) [$yes]: "
      
      if [ "X${USER_ENABLE_SYSLOG}" = "X" ]; then
	    read ANSWER
      else
        ANSWER=${USER_ENABLE_SYSLOG}
      fi
              
      echo ""
      case $ANSWER in
		$nomatch)
			echo "   --- ${nosyslog}."
			;;
		*)
			echo "   - ${yessyslog}."
			RLOG="yes"
			;;
	  esac

	  # Configuring remote connections
      SLOG="yes"
	fi
    
    
    
	if [ "X$RLOG" = "Xyes" ]; then
	echo "" >> $NEWCONFIG
	echo "  <remote>" >> $NEWCONFIG
	echo "    <connection>syslog</connection>" >> $NEWCONFIG
	echo "  </remote>" >> $NEWCONFIG
	fi

	if [ "X$SLOG" = "Xyes" ]; then
	echo "" >> $NEWCONFIG
	echo "  <remote>" >> $NEWCONFIG
	echo "    <connection>secure</connection>" >> $NEWCONFIG
	echo "  </remote>" >> $NEWCONFIG
	fi


	# Email/log alerts
	echo "" >> $NEWCONFIG
	echo "  <alerts>" >> $NEWCONFIG
    echo "    <log_alert_level>1</log_alert_level>" >> $NEWCONFIG
    if [ "$EMAILNOTIFY" = "yes" ]; then
        echo "    <email_alert_level>7</email_alert_level>">> $NEWCONFIG
	fi
	echo "  </alerts>" >> $NEWCONFIG


    if [ "X$ACTIVERESPONSE" = "Xyes" ]; then
        # Add commands in here
        echo "" >> $NEWCONFIG
        cat ${HOST_DENY_TEMPLATE} >> $NEWCONFIG
        echo "" >> $NEWCONFIG
        cat ${FIREWALL_DROP_TEMPLATE} >> $NEWCONFIG
        echo "" >> $NEWCONFIG
        cat ${DISABLE_ACCOUNT_TEMPLATE} >> $NEWCONFIG
        echo "" >> $NEWCONFIG

        if [ "X$FIREWALLDROP" = "Xyes" ]; then
            echo "" >> $NEWCONFIG
            cat ${ACTIVE_RESPONSE_TEMPLATE} >> $NEWCONFIG
            echo "" >> $NEWCONFIG
        fi        
    fi
     
    # Setting up the logs
    SetupLogs "3.6"
    echo "</ossec_config>" >> $NEWCONFIG 
}




##########
# setEnv()
##########
setEnv()
{
    echo ""
    echo "2- ${settingupenv}."

    echo ""
    if [ "X${USER_DIR}" = "X" ]; then
        while [ 1 ]; do
            $ECHO " - ${wheretoinstall} [$INSTALLDIR]: "
            read ANSWER
            if [ ! "X$ANSWER" = "X" ]; then
                echo $ANSWER |grep -E "^/[a-zA-Z0-9/-]{3,128}*$">/dev/null 2>&1
                if [ $? = 0 ]; then
                    INSTALLDIR=$ANSWER;
                    WORKDIR=$ANSWER;
                    break;
                fi 
            else
                break;           
            fi  
        done
    else
        INSTALLDIR=${USER_DIR}
        WORKDIR=${USER_DIR}
    fi    

    
    CEXTRA="$CEXTRA -DDEFAULTDIR=\\\"${WORKDIR}\\\""
    
    echo ""
    echo "    - ${installat} ${INSTALLDIR} ."
    

    if [ "X$INSTYPE" = "Xagent" ]; then
        CEXTRA="$CEXTRA -DCLIENT"
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        CEXTRA="$CEXTRA -DLOCAL"    
    fi   

    ls $INSTALLDIR >/dev/null 2>&1
    if [ $? = 0 ]; then
        if [ "X${USER_DELETE_DIR}" = "X" ]; then
            echo ""
            $ECHO "    - ${deletedir} ($yes/$no) [$yes]: "
            read ANSWER
        else
            ANSWER=${USER_DELETE_DIR}
        fi
            
        case $ANSWER in
            $yesmatch)
                rm -rf $INSTALLDIR
                ;;
        esac
    fi
}




##########
# checkDependencies()
# Thanks to gabriel@macacos.org
##########
checkDependencies()
{
    echo ""
    which gcc > /dev/null 2>&1
    if [ $? -ne "0" ]; then
        which cc > /dev/null 2>&1
        if [ $? -ne "0" ]; then
        catError "0x3-dependencies"
        fi
        CC="cc"
    else
        CC="gcc"
    fi
}

##########
# AddWhite()
##########
AddWhite()
{
	while [ 1 ]
	do
        echo ""
		$ECHO "   - ${addwhite} ($yes/$no)? [$no]: "

        # If white list is set, we don't need to ask it here.
        if [ "X${USER_WHITE_LIST}" = "X" ]; then
		    read ANSWER
        else
            ANSWER=$yes
        fi
                
		if [ "X${ANSWER}" = "X" ] ; then
			ANSWER=$no
		fi
			
		case $ANSWER in
			$no)
				break;
				;;
			*)
				$ECHO "   - ${ipswhite}"
                if [ "X${USER_WHITE_LIST}" = "X" ]; then
				    read IPS
				else
                    IPS=${USER_WHITE_LIST}
                fi
                    
				for ip in ${IPS};
				do
					if [ ! "X${ip}" = "X" ]; then
                        echo $ip | grep -E "^[0-9./]{5,20}$" > /dev/null 2>&1
                        if [ $? = 0 ]; then
						echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
                        fi
					fi
				done
				
				break;
				;;
		esac
	done
}

##########
# main()
##########
main()
{
    LG="en"
    LANGUAGE="en"
    . ./src/init/shared.sh
    . ./src/init/functions.sh

    # Reading pre-defined file
    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
        . ${PREDEF_FILE}
    fi
                        
    # If user language is not set
     
    if [ "X${USER_LANGUAGE}" = "X" ]; then
    
        # Choosing the language.
        while [ 1 ]; do
        echo ""
        for i in `ls ${TEMPLATE}`; do 
            # ignore CVS (should not be there anyways and config)
            if [ "$i" = "CVS" -o "$i" = "config" ]; then continue; fi
            cat "${TEMPLATE}/$i/language.txt"
            if [ ! "$i" = "en" ]; then
                LG="${LG}/$i"
            fi    
        done
        $ECHO "  (${LG}) [en]: "
        read USER_LG;

        if [ "X${USER_LG}" = "X" ]; then
            USER_LG="en"
        fi    
    
        ls "${TEMPLATE}/${USER_LG}" > /dev/null 2>&1
        if [ $? = 0 ]; then
            break;
        fi
        done;    

        LANGUAGE=${USER_LG}
    
    else
        
        # If provided language is not valid, default to english
        ls "${TEMPLATE}/${USER_LANGUAGE}" > /dev/null 2>&1
        if [ $? = 0 ]; then
            LANGUAGE=${USER_LANGUAGE}
        else
            LANGUAGE="en"
        fi    

    fi # for USER_LANGUAGE
    
    
    . ./src/init/shared.sh
    . ./src/init/language.sh
    . ./src/init/functions.sh
    . ./src/init/init.sh
    . ${TEMPLATE}/${LANGUAGE}/messages.txt
    
    
    # Must be executed as ./install.sh
    if [ `isFile ${VERSION_FILE}` = "${FALSE}" ]; then
        catError "0x1-location";
    fi

    # Must be root
    if [ ! "X$ME" = "Xroot" ]; then
        catError "0x2-beroot";
    fi    

    # Checking dependencies
    checkDependencies

    clear
    

    # Initial message
    echo " $NAME $VERSION ${installscript} - http://www.ossec.net"
    
    catMsg "0x101-initial"

    echo "  - $system: $UNAME"
    echo "  - $user: $ME"
    echo "  - $host: $HOST"
    echo ""
    echo ""
    echo "  -- $hitanyorabort --"

    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi

    # Is this an update?
    if [ `isFile ${OSSEC_INIT}` = "${TRUE}" ]; then
        echo ""
        ct="1"
        while [ $ct = "1" ]; do
            ct="0"
            $ECHO " - ${wanttoupdate} ($yes/$no): "
            if [ "X${USER_UPDATE}" = "X" ]; then
                read ANY
            else
                ANY=$yes
            fi    

            case $ANY in
                $yes)
                    update_only="yes"
                    break;
                    ;;
                $no)
                    break;
                    ;;
                  *)
                    ct="1"
                    ;;      
            esac
        done
        

        # Do some of the update steps.
        if [ "X${update_only}" = "Xyes" ]; then
            . ./src/init/update.sh

            if [ "`doUpdatecleanup`" = "${FALSE}" ]; then
                # Disabling update
                echo ""
                echo "${unabletoupdate}"
                sleep 5;
                update_only=""
            else
                # Get update
                USER_INSTALL_TYPE=`getPreinstalled`
                USER_DIR=`getPreinstalledDir`
                USER_DELETE_DIR="$nomatch"
            fi     

            ct="1"
            
            # We dont need to update the rules on agent installs
            if [ "X${USER_INSTALL_TYPE}" = "Xagent" ]; then
                ct="0"
            fi
                
            while [ $ct = "1" ]; do
                ct="0"    
                $ECHO " - ${updaterules} ($yes/$no): "
                if [ "X${USER_UPDATE_RULES}" = "X" ]; then
                    read ANY
                else    
                    ANY=$yes
                fi
            
                case $ANY in
                    $yes)
                        update_rules="yes"
                        break;
                        ;;
                    $no)         
                        break;
                        ;;
                    *)
                        ct="1"
                        ;;
                esac 
            done
        fi    
        echo ""
    fi    
    
    serverm=`echo ${server} | cut -b 1`
    localm=`echo ${local} | cut -b 1`
    agentm=`echo ${agent} | cut -b 1`
    helpm=`echo ${help} | cut -b 1`

    # If user install type is not set, ask for it.
    if [ "X${USER_INSTALL_TYPE}" = "X" ]; then

        # Loop for the installation options
        while [ 1 ]
        do
            echo ""
            $ECHO "1- ${whattoinstall} "

            read ANSWER
            case $ANSWER in
        
                ${helpm}|${help})
                catMsg "0x102-installhelp"
	            ;;
            
                ${server}|${serverm})
                echo ""
	            echo "  - ${serverchose}."
	            INSTYPE="server"
	            break;
	            ;;
            
                ${agent}|${agentm})
                echo ""
	            echo "  - ${clientchose}."
	            INSTYPE="agent"
	            break;
	            ;;
   
                ${local}|${localm})
                echo ""
                echo "  - ${localchose}." 
                INSTYPE="local"
                break;
                ;;
            esac
        done

    else
        INSTYPE=${USER_INSTALL_TYPE}
    fi


    # Setting up the environment
    setEnv

    
    # Configuring the system (based on the installation type)
    if [ "X${update_only}" = "X" ]; then    
        if [ "X$INSTYPE" = "Xserver" ]; then	
            ConfigureServer
        elif [ "X$INSTYPE" = "Xagent" ]; then
            ConfigureClient
        elif [ "X$INSTYPE" = "Xlocal" ]; then
            ConfigureServer   
        else
            catError "0x4-installtype"
        fi
    fi    

    # Installing (calls the respective script 
    # -- InstallAgent.sh pr InstallServer.sh
    Install

    # User messages
    echo ""
    echo " - ${configurationdone}."
    echo ""
    echo " - ${tostart}:"
    echo "		$WORKDIR/bin/ossec-control start"
    echo ""
    echo " - ${tostop}:"
    echo "		$WORKDIR/bin/ossec-control stop"
    echo ""
    echo " - ${configat} $WORKDIR/etc/ossec.conf"
    echo ""


    catMsg "0x103-thanksforusing"


    if [ "X${update_only}" = "Xyes" ]; then
        echo ""
        echo " - ${updatecompleted}"
        echo ""
        exit 0;
    fi    

    
    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi


    if [ "X$INSTYPE" = "Xserver" ]; then
        echo ""        	
        echo " - ${addserveragent}"
        echo "   ${runma}:"
        echo ""
        echo "   $INSTALLDIR/bin/manage_agents"
        echo ""
        echo "   ${moreinfo}"
        echo "   http://www.ossec.net/en/manual.html#ma"
        echo ""
      
    elif [ "X$INSTYPE" = "Xagent" ]; then
        catMsg "0x104-client"	
        echo "   $WORKDIR/bin/manage_agents"
        echo ""
        echo "   ${moreinfo}"
        echo "   http://www.ossec.net/en/manual.html#ma"
        echo ""
    fi

    if [ "X$notmodified" = "Xyes" ]; then
        catMsg "0x105-noboot"
        echo "		$WORKDIR/bin/ossec-control start" 
        echo ""
    fi
}




### Calling main function where everything happens
main


exit 0



## EOF ##

