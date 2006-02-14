#!/bin/sh


# Checking if it is executed from the right place
LOCATION=./LOCATION
ls ${LOCATION} > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Cannot execute. Wrong directory"
    exit 1;
fi

UNAME=`uname`;
# Getting default variables
DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
GROUP="ossec"
USER="ossec"
USER_MAIL="ossecm"
USER_EXEC="ossece"
USER_REM="ossecr"
subdirs="logs logs/archives logs/alerts logs/firewall bin stats rules queue queue/alerts queue/ossec queue/fts queue/syscheck queue/rootcheck queue/agent-info tmp var var/run etc etc/shared checksum_db active-response active-response/bin"

# ${DIR} must be set 
if [ "X${DIR}" = "X" ]; then
    echo "Error building OSSEC HIDS."
    exit 1;
fi    

    
# Creating root directory
ls ${DIR} > /dev/null 2>&1    
if [ $? != 0 ]; then mkdir -m 700 -p ${DIR}; fi
ls ${DIR} > /dev/null 2>&1    
if [ $? != 0 ]; then 
    echo "You do not have permissions to create ${DIR}. Exiting..."
    exit 1;
fi


# Creating groups/users
if [ "$UNAME" = "FreeBSD" ]; then
    /usr/sbin/pw groupadd ${GROUP}
	/usr/sbin/pw useradd ${USER} -d ${DIR} -s /sbin/nologin -g ${GROUP}
	/usr/sbin/pw useradd ${USER_MAIL} -d ${DIR} -s /sbin/nologin -g ${GROUP}
	/usr/sbin/pw useradd ${USER_EXEC} -d ${DIR} -s /sbin/nologin -g ${GROUP}
	/usr/sbin/pw useradd ${USER_REM} -d ${DIR} -s /sbin/nologin -g ${GROUP}

elif [ "$UNAME" = "SunOS" ]; then
    /usr/sbin/groupadd ${GROUP}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_MAIL}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_EXEC}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_REM}

elif [ "$UNAME" = "AIX" ]; then
    /usr/bin/mkgroup ${GROUP}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_MAIL}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_EXEC}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_REM}
            
else
	/usr/sbin/groupadd ${GROUP}
	/usr/sbin/useradd -d ${DIR} -s /sbin/nologin -g ${GROUP} ${USER}
	/usr/sbin/useradd -d ${DIR} -s /sbin/nologin -g ${GROUP} ${USER_MAIL}
	/usr/sbin/useradd -d ${DIR} -s /sbin/nologin -g ${GROUP} ${USER_EXEC}
	/usr/sbin/useradd -d ${DIR} -s /sbin/nologin -g ${GROUP} ${USER_REM}
fi


# Creating sub directories
for i in ${subdirs}; do
    ls ${DIR}/${i} > /dev/null 2>&1
    if [ $? != 0 ]; then mkdir -m 700 ${DIR}/${i}; fi
done

# Default for all directories
chmod -R 550 ${DIR}
chown -R root:${GROUP} ${DIR}

# AnalysisD needs to write to alerts: log, mail and cmds
chown -R ${USER}:${GROUP} ${DIR}/queue/alerts
chmod -R 770 ${DIR}/queue/alerts

# To the ossec queue (default for analysisd to read)
chown -R ${USER}:${GROUP} ${DIR}/queue/ossec
chmod -R 770 ${DIR}/queue/ossec

# To the ossec fts queue
chown -R ${USER}:${GROUP} ${DIR}/queue/fts
chmod -R 700 ${DIR}/queue/fts

# To the ossec syscheck/rootcheck queue
chown -R ${USER}:${GROUP} ${DIR}/queue/syscheck
chmod -R 700 ${DIR}/queue/syscheck
chown -R ${USER}:${GROUP} ${DIR}/queue/rootcheck
chmod -R 700 ${DIR}/queue/rootcheck
chown -R ${USER_REM}:${GROUP} ${DIR}/queue/agent-info
chmod -R 755 ${DIR}/queue/agent-info

# For the stats directory
chown -R ${USER}:${GROUP} ${DIR}/stats
chmod -R 750 ${DIR}/stats

# For the logging user
chown -R ${USER}:${GROUP} ${DIR}/logs
chmod -R 750 ${DIR}/logs
touch ${DIR}/logs/ossec.log
chown ${USER}:${GROUP} ${DIR}/logs/ossec.log
chmod 664 ${DIR}/logs/ossec.log

# For the rules directory
cp -pr ../etc/rules/* ${DIR}/rules/
chown -R root:${GROUP} ${DIR}/rules
chmod -R 550 ${DIR}/rules

# For the etc dir
chmod 550 ${DIR}/etc
chown -R root:${GROUP} ${DIR}/etc
ls /etc/localtime > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -pL /etc/localtime ${DIR}/etc/; 
fi

# For the /var/run
chmod 770 ${DIR}/var/run
chown root:${GROUP} ${DIR}/var/run

# Moving the binary files
cp -pr ../bin/ossec* ${DIR}/bin/
cp -pr ../bin/manage_agents ${DIR}/bin/
cp -pr ../bin/syscheck-update ${DIR}/bin/
cp -pr ./init/ossec-server ${DIR}/bin/ossec-control

# Moving the decoders
cp -pr ../etc/decoder.xml ${DIR}/etc/
cp -pr rootcheck/db/*.txt ${DIR}/etc/shared/


# Copying active response modules
cp -pr ../active-response/* ${DIR}/active-response/bin/
chmod 755 ${DIR}/active-response/bin/*


# Moving the config file
ls ${DIR}/etc/ossec.conf > /dev/null 2>&1
if [ $? = 0 ]; then
    echo "Not overwritting /etc/ossec.conf."
    exit 0;
fi

ls ../etc/ossec.mc > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -pr ../etc/ossec.mc ${DIR}/etc/ossec.conf
else    
    cp -pr ../etc/ossec-server.conf ${DIR}/etc/ossec.conf
fi


exit 0;

#EOF
