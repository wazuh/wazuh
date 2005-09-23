#!/bin/sh
# Installation script for the OSSEC HIDS
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Checking if the script is being executed correctly

ls ./src/VERSION >/dev/null 2>&1
if [ $? != 0 ]; then
   echo ""
   echo " =x= This script can only be executed from the same directory.   =x= "
   echo " =x= Change directory to where this script is before running it. =x= "
   echo " =x= ERROR. 							  =x= "
   echo ""
   exit 1;	
fi

VERSION=`cat ./src/VERSION`
LOCATION="./src/LOCATION"
UNAME=`uname -snpr`
NUNAME=`uname`
ME=`whoami`
HOST=`hostname`
CC=""
NAME="OSSEC HIDS"
INSTYPE="server"
DEFAULT_DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
DEFDIR="$DEFAULT_DIR";
FAST="";
NEWCONFIG="./etc/ossec.mc"
CEXTRA=""

checkDependencies()	# Thanks gabriel@macacos.org
  {
  echo ""
  echo "2- Cheking Dependencies:"
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
	echo " =x= You will need a compiler (like gcc) to continue	  =x= "
	echo " =x= with the installation				  =x= "
	echo " =x= Go to www.ossec.net/hids/ for more help. 		  =x= "
	echo " =x= ERROR.						  =x= "
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

setEnv()
	{
	echo ""
	echo "3- Setting up the working environment."
	echo ""
	echo " - Where do you want to install $NAME? "
	echo " - The default location is $DEFDIR, do want to keep it ?(y/n)y"
	read ANSWER
	case $ANSWER in
		n|N)
			echo "    - Type the directory to install it:"
			read TMPDIR
			DEFDIR="$TMPDIR"
			echo "    - Installation will be made at ${DEFDIR}"
            CEXTRA="$CEXTRA -DDEFAULTDIR=\\\"${DEFDIR}\\\" -DDEFAULTQPATH=\\\"${DEFDIR}/queue/ossec/queue\\\" -DDEFAULTCPATH=\\\"${DEFDIR}/etc/ossec.conf\\\""
			;;
	esac
    
    if [ "X$INSTYPE" = "Xclient" ]; then
        CEXTRA="$CEXTRA -DCLIENT"
    fi   

    ls $DEFDIR >/dev/null 2>&1
	if [ $? = 0 ]; then
		echo " - The directory $DEFDIR already exist."
		echo " - Do you want to delete it? (y/n)n"
		read ANSWER
		case $ANSWER in
			y|Y)
				rm -rf $DEFDIR
				;;
		esac
	fi
	}


ConfigureClient()
	{
	echo ""
	echo "4- Configuring $NAME."
	echo ""
	echo ""
	echo "  4.1- What's the IP Address of the OSSEC HIDS server ?"
	read IP
	echo ""
	echo "   - Adding Server IP: $IP"
	echo ""

	echo "<client>" > $NEWCONFIG
	echo "  <server-ip>$IP</server-ip>" >> $NEWCONFIG
	echo "  <group>syslog</group>" >> $NEWCONFIG
	echo "  <connection>secure</connection>" >> $NEWCONFIG
	echo "</client>" >> $NEWCONFIG

    # Integrity check config
    echo ""
    echo "  4.2- Do you want to run the integrity check daemon(yes/no)y"
    read AS
    case $AS in
        n|N|no|No|NO)
            echo "   - Not running syscheck (integrity check daemon)"
            ;;
        *)
            echo "   - Running syscheck (integrity check daemon)"
            echo "" >> $NEWCONFIG
            echo "<syscheck>" >> $NEWCONFIG
            echo "  <daemon>yes</daemon>" >> $NEWCONFIG
            echo "  <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>" >> $NEWCONFIG
            echo "  <notify>queue</notify>" >> $NEWCONFIG
            echo "</syscheck>" >> $NEWCONFIG
            ;;
    esac                    
   
    # Log files 
    echo ""
    echo " - Setting up the configuration to analyze the following logs:"

    LOG_FILES="/var/log/messages /var/log/authlog /var/log/auth.log /var/log/secure /var/log/syslog"

    for i in ${LOG_FILES}; do
        # If log file present, add it    
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "  -- $i"
	        echo "" >> $NEWCONFIG
	        echo "<localfile>" >> $NEWCONFIG
    	    echo "  <group>syslog</group>" >> $NEWCONFIG
	        echo "  <location>$i</location>" >>$NEWCONFIG
	        echo "</localfile>" >> $NEWCONFIG
        fi
    done    
	
	echo ""
	echo " - If any want to monitor any other file, just change the "
	echo " - $DEFDIR/etc/ossec.conf and add a new localfile entry."
	echo " - Any questions about the configuration can be solved by "
	echo " - reading the file etc/README.config."
	echo ""
	echo ""
	echo "   - Press Any Key to continue - "
	read ANY
	}

ConfigureServer()
	{
	echo ""
	echo "4- Configuring $NAME."
	echo ""
	# Configuring e-mail notification
	echo "  4.1- Do you want e-mail notification (y/n)?y"
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
			echo "   - What's your smtp server ip/host? "
			read SMTP
			;;
	esac

    # Integrity check config
    echo ""
    echo "  4.2- Do you want to run the integrity check daemon(yes/no)y"
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
  
    
    if [ "X$INSTYPE" = "Xserver" ]; then
      # Configuring remote syslog  
	  echo ""
	  echo "  4.3- Do you want to listen for remote syslog (514 udp) (y/n)?y"
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
	  echo ""
	  echo "  4.4- Do you want to listen for remote secure connections (1514 udp) (y/n)?y"
	  read ANSWER
	  case $ANSWER in
		n|N)
		  echo "   --- Not receiving encrypted/secure messages"
		  ;;
		*)
		  echo "   - Listening to remote secure messages."
		  echo "   - You will need to run the addagent script for each"
		  echo "     client to be added. The addagent will be inside"
		  echo "     the bin directory under the instalation directory."
          echo ""
		  echo "     Just type (after finishing the installation)"
		  echo "     $DEFDIR/bin/addagent -h for more help."
		  SLOG="yes"
		  ;;
	  esac
	fi
    
	# Writting config
	echo "<global>" > $NEWCONFIG
	if [ "$EMAILNOTIFY" = "yes" ]; then
		echo "  <mail-notify>yes</mail-notify>" >> $NEWCONFIG
		echo "  <emailto>$EMAIL</emailto>" >> $NEWCONFIG
		echo "  <smtpserver>$SMTP</smtpserver>" >> $NEWCONFIG
		echo "  <emailfrom>ossect@${HOST}</emailfrom>" >> $NEWCONFIG
	else
		echo "  <mail-notify>no</mail-notify>" >> $NEWCONFIG
	fi
        echo "  <syscheck_ignore>/etc/mtab</syscheck_ignore>">> $NEWCONFIG
	echo "</global>" >> $NEWCONFIG
	echo "" >> $NEWCONFIG
	
	# Rules configuration
	echo "<rules>" >> $NEWCONFIG
	echo "  <include>syslog.rules</include>" >> $NEWCONFIG
	echo "  <include>pix.rules</include>" >> $NEWCONFIG
	echo "  <include>named.rules</include>" >> $NEWCONFIG
	echo "  <include>proftpd.rules</include>" >> $NEWCONFIG
	echo "</rules>" >> $NEWCONFIG

    # syscheck
    if [ "X$SYSCHECK" = "Xyes" ]; then
        echo "" >> $NEWCONFIG
        echo "<syscheck>" >> $NEWCONFIG
        echo "  <daemon>yes</daemon>" >> $NEWCONFIG
        echo "  <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>" >> $NEWCONFIG
        echo "  <notify>queue</notify>" >> $NEWCONFIG
        echo "</syscheck>" >> $NEWCONFIG
    fi
    
        
	if [ "X$RLOG" = "Xyes" ]; then
	echo "" >> $NEWCONFIG
	echo "<remote>" >> $NEWCONFIG
	echo "  <group>all</group>" >> $NEWCONFIG
	echo "  <connection>syslog</connection>" >> $NEWCONFIG
	echo "</remote>" >> $NEWCONFIG
	fi

	if [ "X$SLOG" = "Xyes" ]; then
	echo "" >> $NEWCONFIG
	echo "<remote>" >> $NEWCONFIG
	echo "  <group>syslog</group>" >> $NEWCONFIG
	echo "  <connection>secure</connection>" >> $NEWCONFIG
	echo "</remote>" >> $NEWCONFIG
	fi

	# Log response
	echo "" >> $NEWCONFIG
	echo "<response>" >> $NEWCONFIG
    echo "   <log>1</log>" >> $NEWCONFIG
    if [ "$EMAILNOTIFY" = "yes" ]; then
        echo "   <mail-notification>1</mail-notification>">> $NEWCONFIG
	fi
	echo "</response>" >> $NEWCONFIG

    echo ""
    echo " - Setting up the configuration to analyze the following logs:"

    LOG_FILES="/var/log/messages /var/log/authlog /var/log/auth.log /var/log/secure /var/log/syslog"

    for i in ${LOG_FILES}; do
        # If log file present, add it    
        ls $i > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "  -- $i"
	        echo "" >> $NEWCONFIG
	        echo "<localfile>" >> $NEWCONFIG
    	    echo "  <group>syslog</group>" >> $NEWCONFIG
	        echo "  <location>$i</location>" >>$NEWCONFIG
	        echo "</localfile>" >> $NEWCONFIG
        fi
    done    

	echo ""
	echo " - Any changes you want to make ,go to $DEFDIR/etc/ossec.conf."
	echo " - Any questions about the configuration can be solved by "
	echo " - reading the file etc/README.config."
	echo ""
	echo ""
	echo "   - Press Any Key to continue - "

	read ANY
	}


Install()
	{
	echo ""
	echo "5- Creating the necessary files (to be used by Makefile, etc)"
	echo "DIR=\"${DEFDIR}\"" > ${LOCATION}
    echo "CC=${CC}" >> ${LOCATION}

    echo "CEXTRA=${CEXTRA}" > ./src/Config.OS
    
	echo " - Running the Makefile"
    
    cd ./src
	
    make all
    
    if [ $? != 0 ]; then
        echo "Building error. Exiting ..."
        exit 1;
    fi
        
    make build
    
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

######
#Main function
######
clear

USEROPT=$1

echo "
$NAME $VERSION Installation Script - http://www.ossec.net/hids/

You are about to start the installation process of the OSSEC HIDS.
You must have a C compiler pre-installed in your system.
Any question, suggestion or comment, please send an e-mail to
dcid@ossec.net (or daniel.cid@gmail.com).

- System: $UNAME
- User: $ME
- Host: $HOST"


# Must be root checking
if [ ! "X$ME" = "Xroot" ]; then
	echo ""
	echo "=x= Error. You must be root to install this script. =x="
	echo ""
	exit 1
fi


echo "
   ---  Hit any key to continue installation (or Ctrl-C to abort) --
"

read ANY

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
    echo "    (better for companies, enterprises, .gov, .edu ,etc)"
	echo ""
    echo "  - Use 'local' if you are just have one system to analyze."
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

checkDependencies
setEnv

if [ "X$INSTYPE" = "Xserver" ]; then	
   ConfigureServer
elif [ "X$INSTYPE" = "Xclient" ]; then
   ConfigureClient
elif [ "X$INSTYPE" = "Xlocal" ]; then
   ConfigureServer   
else
   echo " =x= Wrong installation type. It can only be agent,server or local =x="
   echo " =x= Error.  							  =x= "
   exit 1;
fi

Install

echo ""
echo " - Configuration finished without any problem."
echo ""
echo " - To start OSSEC HIDS:"
echo "		$DEFDIR/bin/ossec-control start"
echo ""
echo " - To stop OSSEC HIDS:"
echo "		$DEFDIR/bin/ossec-control stop"
echo ""
echo " - The configuration can be viewed or modified at $DEFDIR/etc/ossec.conf"
echo ""

if [ "X$INSTYPE" = "Xserver" ]; then	
echo " - If you are going to use encryption (secure communication between the"
echo "   client and the server), you need to run the $DEFDIR/bin/addagent for"
echo "   each client. Type $DEFDIR/bin/addagent -h for help."
echo ""
echo " - If you would like to receive syslog messages remotely, you need"
echo "   to add in the configuration file (inside the global element) the "
echo "   IPs that you want to  allow to receive messages from."
echo "   The syntax should be:"
echo "     <global>"
echo "     .."
echo "       <allowed-ips>10.1.1.1</allowed-ips> - To allow this ip"
echo "       <allowed-ips>10.1.1.</allowed-ips>  - To allow network 10.1.1.0/24"
echo "       <allowed-ips>10.1.</allowed-ips> - To allow network 10.1.0.0/16"
echo "     </global>"
echo ""
elif [ "X$INSTYPE" = "Xclient" ]; then	
echo " - You need to run the addagent script on the server now and copy " 
echo "   the client.keys-XXX file to $DEFDIR/etc/ (and rename to client.keys) "
echo ""
fi

echo " - Depending on your system, check if /etc/rc.d/init.d/ossec"
echo "   or /etc/rc.local was created/modified. If not, add the following"
echo "   line to your init script (may vary depending on the system) to"
echo "   have OSSEC HIDS starting during boot"
echo ""
echo "		$DEFDIR/bin/ossec-control start" 
echo ""
echo ""
echo " - Any question, comment, bug or patch contact daniel.cid@gmail.com"
echo " More information can be found at http://www.ossec.net/hids/"
echo ""
echo " Hope you ENJOY :)"
echo ""

## EOF ##
