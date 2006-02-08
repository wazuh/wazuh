#!/bin/sh
# Installation script for the OSSEC HIDS
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Jan 30, 2006

### Setting up variables
VERSION=`cat ./src/VERSION`
LOCATION="./src/LOCATION"
UNAME=`uname -snr`
NUNAME=`uname`
ME=`whoami`
HOST=`hostname`
NAMESERVERS=`cat /etc/resolv.conf | grep nameserver | cut -d " " -sf 2`
NAMESERVERS2=`cat /etc/resolv.conf | grep nameserver | cut -sf 2`
HOST_CMD=`which host`
CC=""
NAME="OSSEC HIDS"
INSTYPE="server"
DEFAULT_DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
WORKDIR="$DEFAULT_DIR";
NEWCONFIG="./etc/ossec.mc"
SYSCHECK_DIRS="/etc,/usr/bin,/usr/sbin,/bin,/sbin"
CEXTRA=""




### Internal functions (follow the bottom-top order)


##########
# install()
##########
Install()
{
	echo ""
	echo "5- Installing the system"
    
	echo "DIR=\"${WORKDIR}\"" > ${LOCATION}
    echo "CC=${CC}" >> ${LOCATION}
    
    # Changing Config.OS with the new C flags
    echo "CEXTRA=${CEXTRA}" > ./src/Config.OS
    
    # Makefile
	echo " - Running the Makefile"
    cd ./src
    make all
    
    if [ $? != 0 ]; then
        echo " Error (install 1)."
        echo " Building error."
        exit 1;
    fi
        
    # Building everything    
    make build
    
    # Making the right installation type
	if [ "X$INSTYPE" = "Xserver" ]; then
		make server
	
    elif [ "X$INSTYPE" = "Xclient" ]; then 
		make agent

    elif [ "X$INSTYPE" = "Xlocal" ]; then
        make server    
	fi

    
    # Calling the init script  to start ossec hids during boot
    ./init/init.sh
    	
    cd ../
}




##########
# UseSyscheck()
##########
UseSyscheck()
{

    # Integrity check config
    echo ""
    echo "  3.2- Do you want to run the integrity check daemon?(yes/no)y"
    read AS
    case $AS in
        n|N|no|No|NO)
            echo "   - Not running syscheck (integrity check daemon)"
            ;;
        *)
            SYSCHECK="yes"
            echo "   - Running syscheck (integrity check daemon)"
            ;;
    esac                    

    # Adding to the config file
    if [ "X$SYSCHECK" = "Xyes" ]; then
        echo "" >> $NEWCONFIG
        echo "<syscheck>" >> $NEWCONFIG
        echo "  <daemon>yes</daemon>" >> $NEWCONFIG
        echo "  <directories>$SYSCHECK_DIRS</directories>" >> $NEWCONFIG
        echo "  <notify>queue</notify>" >> $NEWCONFIG
        echo "  <ignore>/etc/mtab</ignore>">> $NEWCONFIG
        echo "  <ignore>/etc/hosts.deny</ignore>">> $NEWCONFIG
        echo "</syscheck>" >> $NEWCONFIG
    fi
}




##########
# UseRootcheck()
##########
UseRootcheck()
{

    # Rootkit detection configuration 
    echo ""
    echo "  3.3- Do you want to run the rootkit detection engine?(yes/no)y"
    read ES
    case $ES in
        n|N|no|No|NO)
            echo "   - Not running rootcheck (rootkit detection)"
            ;;
        *)
            ROOTCHECK="yes"
            echo "   - Running rootcheck (rootkit detection)"
            ;;
    esac


    # Adding to the config file
    if [ "X$ROOTCHECK" = "Xyes" ]; then
        echo "" >> $NEWCONFIG
        echo "<rootcheck>" >> $NEWCONFIG
        echo "  <notify>queue</notify>" >> $NEWCONFIG
        echo "  <rootkit_files>$WORKDIR/etc/shared/rootkit_files.txt</rootkit_files>" >> $NEWCONFIG
        echo "  <rootkit_trojans>$WORKDIR/etc/shared/rootkit_trojans.txt</rootkit_trojans>" >> $NEWCONFIG
        echo "</rootcheck>" >> $NEWCONFIG
    fi            
}




##########
# SetupLogs()
##########
SetupLogs()
{

    NB=$1
    echo ""
    echo "  $NB- Setting the configuration to analyze the following logs:"

    LOG_FILES="/var/log/messages /var/log/authlog /var/log/auth.log /var/log/secure /var/log/syslog /var/log/ipfilter.log /var/adm/ipsec.log"

    for i in ${LOG_FILES}; do
        # If log file present, add it    
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "    -- $i"
	        echo "" >> $NEWCONFIG
	        echo "<localfile>" >> $NEWCONFIG
    	    echo "  <log_format>syslog</log_format>" >> $NEWCONFIG
	        echo "  <location>$i</location>" >>$NEWCONFIG
	        echo "</localfile>" >> $NEWCONFIG
        fi
    done    

    # Getting snort files
    SNORT_FILES="/var/log/snort/alert"
    for i in ${SNORT_FILES}; do
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "" >> $NEWCONFIG
            echo "<localfile>" >> $NEWCONFIG
            
            head -n 1 $i|grep "\[**\] "|grep -v "Classification:" > /dev/null
            if [ $? = 0 ]; then
                echo "  <log_format>snort-full</log_format>" >> $NEWCONFIG
                echo "    -- $i (snort-full file)"
            else
                echo "  <log_format>snort-fast</log_format>" >> $NEWCONFIG
                echo "    -- $i (snort-fast file)"
            fi
            echo "  <location>$i</location>" >>$NEWCONFIG
            echo "</localfile>" >> $NEWCONFIG    
        fi
    done    
    
    # Getting apache logs
    APACHE_FILES="/var/log/apache/error.log /var/log/apache/error_log /var/log/apache/access.log /var/log/apache/access_log /var/www/logs/access_log /var/www/logs/error_log"
    for i in ${APACHE_FILES}; do
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
          echo "" >> $NEWCONFIG
          echo "<localfile>" >> $NEWCONFIG
          echo "  <log_format>apache</log_format>" >> $NEWCONFIG
          echo "  <location>$i</location>" >>$NEWCONFIG
          echo "</localfile>" >> $NEWCONFIG
          
          echo "    -- $i (apache log)"
        fi
    done
    
    
	echo ""
	echo " - If any want to monitor any other file, just change "
	echo " - $WORKDIR/etc/ossec.conf and add a new localfile entry."
	echo " - Any questions about the configuration can be solved by "
	echo " - visiting us online at http://www.ossec.net/hids/ ."
	echo ""
	echo ""
	echo "   - Press Any Key to continue - "
	read ANY
}




##########
# ConfigureClient()
##########
ConfigureClient()
{
	echo ""
	echo "3- Configuring $NAME."
	echo ""
	echo ""
	echo "  3.1- What's the IP Address of the OSSEC HIDS server ?"
	    read IP
	    echo ""
	    echo "   - Adding Server IP: $IP"
	    echo ""

	echo "<client>" > $NEWCONFIG
	echo "  <server-ip>$IP</server-ip>" >> $NEWCONFIG
	echo "</client>" >> $NEWCONFIG

    # Syscheck?
    UseSyscheck

    # Rootcheck?
    UseRootcheck


    # Set up the log files
    SetupLogs "3.4"
                       
	
}




##########
# ConfigureClient()
##########
ConfigureServer()
{
	echo ""
	echo "3- Configuring $NAME."
	
    
    # Configuring e-mail notification
	echo ""
	echo "  3.1- Do you want e-mail notification (y/n)?y"
	read ANSWER
	case $ANSWER in
		n|N)
			echo "   --- Email Notification skipped "
			EMAILNOTIFY="no"
			;;
		*)
			EMAILNOTIFY="yes"
			echo "   - What's your e-mail address? "
			read EMAIL
            ls ${HOST_CMD} > /dev/null 2>&1
            if [ $? = 0 ]; then
              HOSTTMP=`${HOST_CMD} -W 5 -t mx ossec.net 2>/dev/null`
              if [ $? = 1 ]; then
                 # Trying without the -W 
                 HOSTTMP=`${HOST_CMD} -t mx ossec.net 2>/dev/null`
              fi       
              if [ "X$HOSTTMP" = "Xossec.net mail is handled by 10 mx.underlinux.com.br." -o "X$HOSTTMP" = "Xossec.net mail is handled (pri=10) by mx.underlinux.com.br" ]; then
                 # Breaking down the user e-mail
                 EMAILHOST=`echo ${EMAIL} | cut -d "@" -f 2`
                 if [ "X${EMAILHOST}" = "Xlocalhost" ]; then
                    SMTPHOST="127.0.0.1"
                 else       
                    HOSTTMP=`${HOST_CMD} -W 6 -t mx ${EMAILHOST}`
                    SMTPHOST=`echo ${HOSTTMP} | cut -d " " -f 7`
                 fi   
              fi    
            fi

            if [ "X${SMTPHOST}" != "X" ]; then
               echo ""
               echo "   - We found that your SMTP server is: ${SMTPHOST}"
               echo "   - Do you want to use it?(y/n)y"
               read EMAIL2
               case ${EMAIL2} in
                  n|N|no|No|NO)
                     echo ""
                     SMTP=""
                     ;;
                  *)
                     SMTP=${SMTPHOST}
                     echo "   --- Using ${SMTP} as your STMP server."   
                     echo ""
                     ;;
               esac
            fi

            if [ "X${SMTP}" = "X" ]; then
			   echo "   - What's your smtp server ip/host? "
               read SMTP
            fi   
			;;
	esac


	# Writting global parameters 
	echo "<global>" > $NEWCONFIG
	if [ "$EMAILNOTIFY" = "yes" ]; then
		echo "  <email_notification>yes</email_notification>" >> $NEWCONFIG
		echo "  <email_to>$EMAIL</email_to>" >> $NEWCONFIG
		echo "  <smtp_server>$SMTP</smtp_server>" >> $NEWCONFIG
		echo "  <email_from>ossect@${HOST}</email_from>" >> $NEWCONFIG
	else
		echo "  <email_notification>no</email_notification>" >> $NEWCONFIG
	fi
        echo "  <white_list>127.0.0.1</white_list>" >> $NEWCONFIG
        for ip in ${NAMESERVERS} ${NAMESERVERS2};
        do
            if [ "X${ip}" != "X" ]; then
              echo "  <white_list>${ip}</white_list>" >>$NEWCONFIG
            fi
        done
	echo "</global>" >> $NEWCONFIG
	echo "" >> $NEWCONFIG


	# Writting rules configuration
	echo "<rules>" >> $NEWCONFIG
    echo "  <include>rules_config.xml</include> ">> $NEWCONFIG
	echo "  <include>syslog_rules.xml</include>" >> $NEWCONFIG
	echo "  <include>pix_rules.xml</include>" >> $NEWCONFIG
	echo "  <include>named_rules.xml</include>" >> $NEWCONFIG
	echo "  <include>proftpd_rules.xml</include>" >> $NEWCONFIG
    echo "  <include>apache_rules.xml</include>" >> $NEWCONFIG
    echo "  <include>ids_rules.xml</include>" >> $NEWCONFIG
	echo "</rules>" >> $NEWCONFIG
	echo "" >> $NEWCONFIG


    # Checking if syscheck should run
    UseSyscheck
  
    # Checking if rootcheck should run
    UseRootcheck


    # Active response
    echo ""
    echo "  3.4- Active response allows you to execute a specific "
    echo "       command based on the events received. You can "
    echo "       block an IP address or disable access for a "
    echo "       specific user (for example). "
    echo "       http://www.ossec.net/hids/config.php#active-response "
    echo ""
    echo "       Do you want to have active response enabled? (yes/no)y"
    read AR
    case $AR in
        n|N|no|No|NO)
            echo "   - Active response disabled."
            ;;
        *)
            ACTIVERESPONSE="yes"
            echo "   - Active response enabled."
            echo ""
            echo "   - By default, we can enable the host-deny and the "
            echo "     and the firewall-drop responses. The first one "
            echo "     will add a host to the /etc/hosts.deny and the "
            echo "     second one will block the host on iptables (linux)"
            echo "     or on ipfilter (Solaris, FreeBSD, etc)."
            echo "   - They can be used to stop SSHD brute force scans, "
            echo "     portscans and some other forms of attacks. You can "
            echo "     also add them to block on snort events (for example)."
            echo ""
            echo "   - Do you want to enable the host-deny response?(yes/no)y"
            read HD
            case $HD in
                n|N|no|No|NO)
                    echo "     - host-deny disabled"
                    ;;
                *)    
                    echo "     - host-deny enabled (local) for levels >= 6 "
                    HOSTDENY="yes"
                    ;;
            esac
            echo ""
            echo "   - Do you want to enable the firewall-drop response?(yes/no)y"
            read HD2
            case $HD2 in
                n|N|no|No|NO)
                    echo "     - firewall-drop disabled"
                    ;;
                *)
                    echo "     - firewall-drop enabled (local) for levels >= 6 "
                    FIREWALLDROP="yes"
                    ;;
            esac        
                        
            echo ""
            echo "   - For more options and information about active response,"
            echo "     go to our website in the documentation session."
            echo ""
            ;;
    esac                
    
    
    if [ "X$INSTYPE" = "Xserver" ]; then
      # Configuring remote syslog  
	  echo ""
	  echo "  3.5- Do you want to listen for remote syslog (514 udp) (y/n)?y"
	  read ANSWER
      case $ANSWER in
		n|N)
			echo "   --- Not listening on the syslog port"
			;;
		*)
			echo "   - Listening to remote syslog messages"
			RLOG="yes"
			;;
	  esac

	  # Configuring remote connections
      SLOG="yes"
	fi
    
    
    
	if [ "X$RLOG" = "Xyes" ]; then
	echo "" >> $NEWCONFIG
	echo "<remote>" >> $NEWCONFIG
	echo "  <connection>syslog</connection>" >> $NEWCONFIG
	echo "</remote>" >> $NEWCONFIG
	fi

	if [ "X$SLOG" = "Xyes" ]; then
	echo "" >> $NEWCONFIG
	echo "<remote>" >> $NEWCONFIG
	echo "  <connection>secure</connection>" >> $NEWCONFIG
	echo "</remote>" >> $NEWCONFIG
	fi


	# Email/log alerts
	echo "" >> $NEWCONFIG
	echo "<alerts>" >> $NEWCONFIG
    echo "   <log>1</log>" >> $NEWCONFIG
    if [ "$EMAILNOTIFY" = "yes" ]; then
        echo "   <email_notification>7</email_notification>">> $NEWCONFIG
	fi
	echo "</alerts>" >> $NEWCONFIG


    if [ "X$ACTIVERESPONSE" = "Xyes" ]; then
        # Add commands in here
        echo "" >> $NEWCONFIG
        echo "<command>" >> $NEWCONFIG
        echo "  <name>host-deny</name>" >> $NEWCONFIG
        echo "  <executable>host-deny.sh</executable>" >> $NEWCONFIG
        echo "  <expect>srcip</expect>" >> $NEWCONFIG
	    echo "  <timeout_allowed>yes</timeout_allowed>" >> $NEWCONFIG
        echo "</command>" >> $NEWCONFIG
        
        echo "" >> $NEWCONFIG
        echo "<command>" >> $NEWCONFIG
        echo "  <name>firewall-drop</name>" >> $NEWCONFIG
        echo "  <executable>firewall-drop.sh</executable>" >> $NEWCONFIG
        echo "  <expect>srcip</expect>" >> $NEWCONFIG
	    echo "  <timeout_allowed>yes</timeout_allowed>" >> $NEWCONFIG
        echo "</command>" >> $NEWCONFIG
        
        echo "" >> $NEWCONFIG
        echo "<command>" >> $NEWCONFIG
        echo "  <name>disable-account</name>" >> $NEWCONFIG
        echo "  <executable>disable-account.sh</executable>" >> $NEWCONFIG
        echo "  <expect>user</expect>" >> $NEWCONFIG
	    echo "  <timeout_allowed>yes</timeout_allowed>" >> $NEWCONFIG
        echo "</command>" >> $NEWCONFIG
        
        if [ "X$HOSTDENY" = "Xyes" ]; then
            echo "" >> $NEWCONFIG
            echo "<active-response>" >> $NEWCONFIG
            echo "  <command>host-deny</command>" >> $NEWCONFIG
            echo "  <location>local</location>" >> $NEWCONFIG
            echo "  <level>6</level>" >> $NEWCONFIG
            echo "  <timeout>600</timeout>" >> $NEWCONFIG		
            echo "</active-response>" >> $NEWCONFIG
        fi
        
        if [ "X$FIREWALLDROP" = "Xyes" ]; then
            echo "" >> $NEWCONFIG
            echo "<active-response>" >> $NEWCONFIG
            echo "  <command>firewall-drop</command>" >> $NEWCONFIG
            echo "  <location>local</location>" >> $NEWCONFIG
            echo "  <level>6</level>" >> $NEWCONFIG
            echo "  <timeout>600</timeout>" >> $NEWCONFIG
            echo "</active-response>" >> $NEWCONFIG
        fi        
    else    
        echo "" >> $NEWCONFIG
        echo "<active-response>" >> $NEWCONFIG
        echo "  <disabled>yes</disabled>" >> $NEWCONFIG
        echo "</active-response> " >> $NEWCONFIG
    fi
    
    # Setting up the logs
    SetupLogs "3.6"
}




##########
# setEnv()
##########
setEnv()
{
    echo ""
    echo "2- Setting up the working environment."
    echo ""
    echo " - Where do you want to install $NAME? "
    echo " - The default location is $WORKDIR, do want to keep it ?(y/n)y"
    read ANSWER
    case $ANSWER in
        n|N)
          echo "    - Type the directory to install it:"
          read TMPDIR
          WORKDIR="$TMPDIR"
          echo "    - Installation will be made at ${WORKDIR}"
          CEXTRA="$CEXTRA -DDEFAULTDIR=\\\"${WORKDIR}\\\""
          ;;
    esac

    if [ "X$INSTYPE" = "Xclient" ]; then
        CEXTRA="$CEXTRA -DCLIENT"
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        CEXTRA="$CEXTRA -DLOCAL"    
    fi   


    ls $WORKDIR >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo " - The directory $WORKDIR already exist."
        echo " - Do you want to delete it? (y/n)n"
        read ANSWER
        case $ANSWER in
            y|Y)
                rm -rf $WORKDIR
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
    echo "- Cheking Dependencies:"
    echo ""
    echo "  - Checking for gcc"
	
    which gcc > /dev/null 2>&1
    if [ $? -ne "0" ]; then
        echo "   --- GCC Not found in PATH"
        echo "   --- Checking for cc"
        which cc > /dev/null 2>&1
        if [ $? -ne "0" ]; then
	    
        echo "   --- Not found in PATH"
	    echo ""
        
	    echo " Error(checkDependencies 1)."
        echo " You need a compiler (like gcc) to continue with the "
	    echo " with the installation. "
	    echo ""
	    exit 1
        fi
        
        CC="cc"
    else
        CC="gcc"
    fi
    
    echo "    - Found: $CC"
    echo ""
}




##########
# main()
##########
main()
{

    # Must be executed as ./install.sh
    ls ./src/VERSION >/dev/null 2>&1
    if [ $? != 0 ]; then
        echo ""
        echo " Error (main 1). "
        echo " This script can only be executed from the same directory. "
        echo " Change directory to where this script is before running it."
        echo " You must run it as ./install.sh ."
        echo ""
        exit 1;	
    fi

    
    # Must be root
    if [ ! "X$ME" = "Xroot" ]; then
	    echo ""
	    echo " Error (main 2)."
        echo " You must be root to use this script."
	    echo ""
	    exit 1
    fi


    # Checking dependencies
    checkDependencies

    
    clear
    

    # Initial message
    echo ""
    echo " $NAME $VERSION Installation Script - http://www.ossec.net/hids/"
    echo ""
    echo " You are about to start the installation process of the OSSEC HIDS."
    echo " You must have a C compiler pre-installed in your system."
    echo " Any question, suggestion or comment, please send an e-mail to"
    echo " dcid@ossec.net (or daniel.cid@gmail.com)."
    echo ""
    echo " - System: $UNAME"
    echo " - User: $ME"
    echo " - Host: $HOST"



    echo "  -- Hit any key to continue or Ctrl-C to abort  -- "
    read ANY


    # Loop with the installation options
    while [ 1 ]
    do
        echo ""
        echo "1- What kind of installation do you want (server,agent,local,help)?"

        read ANSWER
        case $ANSWER in
            h|H|Help|help|HELP)
	        echo ""
	        echo "  - You have three installation options: agent, local or server."
	        echo ""
	        echo "    - If you choose server, you will be able to analyze all  "
	        echo "      the logs, create e-mail notifications and responses,   "
	        echo "      and also receive logs from remote syslog machines and  "
	        echo "      from systems running the 'agents' (where traffic is  "
            echo "      sent encrypted).              "
	        echo ""
	        echo "    - If you choose the agent(client), you will be able to read"
	        echo "      local files (from syslog, snort, apache, etc) and forward"
	        echo "      them (encrypted) to the server for analysis.             "
	        echo ""
            echo "    - If you choose local, you will be able to do everything  "
            echo "      the server does, except receiving remote messages from  "
            echo "      the agents or external syslog devices.                  "
            echo ""
	        echo "  - Use 'server' if you are setting up a log/analysis server."
	        echo ""
	        echo "  - Use 'agent' if you have another machine to run as a log"
	        echo "    server and want to forward the logs to the server for analysis."
            echo "    (ideal for webserver, database servers ,etc)"
	        echo ""
            echo "  - Use 'local' if you are just have one system to analyze."
            echo ""
            echo "  - More info: http://www.ossec.net/hids/doc.php#starting"
            echo ""
	        ;;
            
            server|Server|S|SERVER|s)
	        echo "  - Server installation chose."
	        INSTYPE="server"
	        break;
	        ;;
            
            client|agent|Agent|Client|C|A|CLIENT|AGENT|c|a)
	        echo "  - Agent(client) installation chose."
	        INSTYPE="client"
	        break;
	        ;;
   
            local|Local|l|L|LOCAL)
            echo "  - Local installation chose." 
            INSTYPE="local"
            break;
            ;;
        esac
    done


    # Setting up the environment
    setEnv

    
    # Configuring the system (based on the installation type)
    
    if [ "X$INSTYPE" = "Xserver" ]; then	
        ConfigureServer
    elif [ "X$INSTYPE" = "Xclient" ]; then
        ConfigureClient
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        ConfigureServer   
    else
        echo " Error (main 3)."
        echo " Wrong installation type. It can only be agent, server or local."
        echo ""
        exit 1;
    fi

    # Installing (calls the respective script 
    # -- InstallAgent.sh pr InstallServer.sh
    Install

    
    # User messages
    echo ""
    echo ""
    echo ""
    echo ""
    echo " - Configuration finished properly."
    echo ""
    echo " - To start OSSEC HIDS:"
    echo "		$WORKDIR/bin/ossec-control start"
    echo ""
    echo " - To stop OSSEC HIDS:"
    echo "		$WORKDIR/bin/ossec-control stop"
    echo ""
    echo " - The configuration can be viewed or modified at $WORKDIR/etc/ossec.conf"
    echo ""


    echo "
    Thanks for using the OSSEC HIDS.
    If you have any question, suggestion or if you find any bug,
    contact us at contact@ossec.net or using our public maillist at
    ossec-list@ossec.net 
    (http://mailman.underlinux.com.br/mailman/listinfo/ossec-list).

    More information can be found at http://www.ossec.net/hids/
   
   ---  Press any key to finish (more information bellow).  ---
   "

    read ANY

    if [ "X$INSTYPE" = "Xserver" ]; then
    echo ""        	
    echo " - You need to add each agent before they are authorized to access. "
    echo "   Run the $WORKDIR/bin/manage_agents to add or remove them."
    echo "   More information at: "
    echo "   http://www.ossec.net/hids/doc.php\#ma"
    echo ""
      
    if [ "X$RLOG" = "Xyes" ]; then
    echo " - If you would like to receive syslog messages remotely, you need"
    echo "   to add in the configuration file (inside the 'global' element) the "
    echo "   IPs authorized to do so."
    echo "   The syntax should be:"
    echo "     <global>"
    echo "     .."
    echo "       <allowed-ips>10.1.1.1</allowed-ips> - To allow this ip"
    echo "       <allowed-ips>10.1.1.0/24</allowed-ips>  - To allow network 10.1.1.0/24"
    echo "     </global>"
    echo ""
    echo " --- Press any key to continue --- "

    read ANY

    fi

    elif [ "X$INSTYPE" = "Xclient" ]; then	
    echo " - To communicate with the server, you first need to add this "
    echo "   agent to it. When you have done so, you can run the "
    echo "   $WORKDIR/bin/manage_agents to import the authentication key"
    echo "   from the server. "
    echo "   More information at " 
    echo "   http://www.ossec.net/hids/doc.php\#ma"
    echo ""
    echo " --- Press any key to continue --- "

    read ANY
    fi


    echo " - Depending on your system, check if /etc/rc.d/init.d/ossec "
    echo "   or /etc/rc.local was created or modified. If not, add the following"
    echo "   line to your init script to have the OSSEC HIDS starting during boot:"
    echo ""
    echo "		$WORKDIR/bin/ossec-control start" 
    echo ""
    echo ""
}




### Calling main function where everything happens
main

exit 0



## EOF ##
