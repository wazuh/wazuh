#!/bin/sh


# Checking if it is executed from the right place
LOCATION=./LOCATION
ls ${LOCATION} > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Cannot execute. Wrong directory"
    exit 1;
fi

# Getting any argument
if [ "X$1" = "Xlocal" ]; then
    # Setting local install
    LOCAL="local"
fi
    
UNAME=`uname`;

# Getting default variables
DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
GROUP="ossec"
USER="ossec"
USER_MAIL="ossecm"
USER_REM="ossecr"
subdirs="logs logs/archives logs/alerts logs/firewall bin stats rules queue queue/alerts queue/ossec queue/fts queue/syscheck queue/rootcheck queue/diff queue/agent-info queue/agentless queue/rids tmp var var/run etc etc/shared active-response active-response/bin agentless .ssh"

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
if [ "$UNAME" = "FreeBSD" -o "$UNAME" = "DragonFly" ]; then
    grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
    /usr/sbin/pw groupadd ${GROUP}
	/usr/sbin/pw useradd ${USER} -d ${DIR} -s /sbin/nologin -g ${GROUP}
	/usr/sbin/pw useradd ${USER_MAIL} -d ${DIR} -s /sbin/nologin -g ${GROUP}
	/usr/sbin/pw useradd ${USER_REM} -d ${DIR} -s /sbin/nologin -g ${GROUP}
    fi

elif [ "$UNAME" = "SunOS" ]; then
    grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
    /usr/sbin/groupadd ${GROUP}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_MAIL}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER_REM}
    fi

elif [ "$UNAME" = "AIX" ]; then
    AIXSH=""
    ls -la /bin/false > /dev/null 2>&1
    if [ $? = 0 ]; then
        AIXSH="-s /bin/false"
    fi

    grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
    /usr/bin/mkgroup ${GROUP}
    /usr/sbin/useradd -d ${DIR} ${AIXSH} -g ${GROUP} ${USER}
    /usr/sbin/useradd -d ${DIR} ${AIXSH} -g ${GROUP} ${USER_MAIL}
    /usr/sbin/useradd -d ${DIR} ${AIXSH} -g ${GROUP} ${USER_REM}
    fi

# Thanks Chuck L. for the mac addusers    
elif [ "$UNAME" = "Darwin" ]; then
    id -u ${USER} > /dev/null 2>&1
    if [ ! $? = 0 ]; then

        # Creating for <= 10.4
        /usr/bin/sw_vers 2>/dev/null| grep "ProductVersion" | grep -E "10.2.|10.3|10.4" > /dev/null 2>&1
        if [ $? = 0 ]; then
            chmod +x ./init/darwin-addusers.pl
            ./init/darwin-addusers.pl    
        else
            chmod +x ./init/osx105-addusers.sh
            ./init/osx105-addusers.sh
        fi        
    fi    
else
    grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
	/usr/sbin/groupadd ${GROUP}

    # We first check if /sbin/nologin is present. If it is not,
    # we look for bin/false. If none of them is present, we
    # just stick with nologin (no need to fail the install for that).
    OSMYSHELL="/sbin/nologin"
    ls -la ${OSMYSHELL} > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        ls -la /bin/false > /dev/null 2>&1
        if [ $? = 0 ]; then
            OSMYSHELL="/bin/false"
        fi    
    fi    
	/usr/sbin/useradd -d ${DIR} -s ${OSMYSHELL} -g ${GROUP} ${USER}
	/usr/sbin/useradd -d ${DIR} -s ${OSMYSHELL} -g ${GROUP} ${USER_MAIL}
	/usr/sbin/useradd -d ${DIR} -s ${OSMYSHELL} -g ${GROUP} ${USER_REM}
    fi
fi


# Creating sub directories
for i in ${subdirs}; do
    ls ${DIR}/${i} > /dev/null 2>&1
    if [ $? != 0 ]; then mkdir -m 700 ${DIR}/${i}; fi
done

# Default for all directories
chmod 550 ${DIR}
chmod 550 ${DIR}/*
chown root:${GROUP} ${DIR}
chown root:${GROUP} ${DIR}/*

# AnalysisD needs to write to alerts: log, mail and cmds
chown -R ${USER}:${GROUP} ${DIR}/queue/alerts
chmod -R 770 ${DIR}/queue/alerts

# To the ossec queue (default for analysisd to read)
chown -R ${USER}:${GROUP} ${DIR}/queue/ossec
chmod -R 770 ${DIR}/queue/ossec

# To the ossec fts queue
chown -R ${USER}:${GROUP} ${DIR}/queue/fts
chmod -R 750 ${DIR}/queue/fts
chmod 750 ${DIR}/queue/fts/* > /dev/null 2>&1

# To the ossec syscheck/rootcheck queue
chown -R ${USER}:${GROUP} ${DIR}/queue/syscheck
chmod -R 750 ${DIR}/queue/syscheck
chmod 740 ${DIR}/queue/syscheck/* > /dev/null 2>&1

chown -R ${USER}:${GROUP} ${DIR}/queue/rootcheck
chmod -R 750 ${DIR}/queue/rootcheck
chmod 740 ${DIR}/queue/rootcheck/* > /dev/null 2>&1

chown ${USER}:${GROUP} ${DIR}/queue/diff
chown ${USER}:${GROUP} ${DIR}/queue/diff/* > /dev/null 2>&1
chmod 750 ${DIR}/queue/diff
chmod 740 ${DIR}/queue/diff/* > /dev/null 2>&1

chown -R ${USER_REM}:${GROUP} ${DIR}/queue/agent-info
chmod -R 750 ${DIR}/queue/agent-info
chmod 740 ${DIR}/queue/agent-info/* > /dev/null 2>&1
chown -R ${USER_REM}:${GROUP} ${DIR}/queue/rids
chmod -R 750 ${DIR}/queue/rids
chmod 740 ${DIR}/queue/rids/* > /dev/null 2>&1

chown -R ${USER}:${GROUP} ${DIR}/queue/agentless
chmod -R 750 ${DIR}/queue/agentless
chmod 740 ${DIR}/queue/agentless/* > /dev/null 2>&1


# For the stats directory
chown -R ${USER}:${GROUP} ${DIR}/stats
chmod -R 750 ${DIR}/stats

# For the logging user
chown -R ${USER}:${GROUP} ${DIR}/logs
chmod -R 750 ${DIR}/logs
touch ${DIR}/logs/ossec.log
chown ${USER}:${GROUP} ${DIR}/logs/ossec.log
chmod 660 ${DIR}/logs/ossec.log

touch ${DIR}/logs/active-responses.log
chown ${USER}:${GROUP} ${DIR}/logs/active-responses.log
chmod 660 ${DIR}/logs/active-responses.log

# For the rules directory
ls ${DIR}/rules/*.xml > /dev/null 2>&1

# Backup previous rules
if [ $? = 0 ]; then
    mkdir ${DIR}/rules/backup-rules.$$
    cp -pr ${DIR}/rules/*.xml ${DIR}/rules/backup-rules.$$/
    
    # Checking for the local rules
    ls ${DIR}/rules/local_rules.xml > /dev/null 2>&1
    if [ $? = 0 ]; then
        cp -pr ${DIR}/rules/local_rules.xml ${DIR}/rules/saved_local_rules.xml.$$
    fi    
fi
    
cp -pr ../etc/rules/* ${DIR}/rules/
find ${DIR}/rules/ -type f -exec chmod 440 {} \;

# If the local_rules is saved, moved it back
ls ${DIR}/rules/saved_local_rules.xml.$$ > /dev/null 2>&1
if [ $? = 0 ]; then
    mv ${DIR}/rules/saved_local_rules.xml.$$ ${DIR}/rules/local_rules.xml
fi    

chown -R root:${GROUP} ${DIR}/rules
chmod -R 550 ${DIR}/rules


# For the etc dir
chmod 550 ${DIR}/etc
chown -R root:${GROUP} ${DIR}/etc
ls /etc/localtime > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -pL /etc/localtime ${DIR}/etc/;
    chmod 440 ${DIR}/etc/localtime
    chown root:${GROUP} ${DIR}/etc/localtime 
fi

# Solaris Needs some extra files
if [ "$UNAME" = "SunOS" ]; then
    mkdir -p ${DIR}/usr/share/lib/zoneinfo/
    chmod -R 550 ${DIR}/usr/
    cp -pr /usr/share/lib/zoneinfo/* ${DIR}/usr/share/lib/zoneinfo/
fi

ls /etc/TIMEZONE > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -p /etc/TIMEZONE ${DIR}/etc/;
    chmod 550 ${DIR}/etc/TIMEZONE
fi
                        

# For the /var/run
chmod 770 ${DIR}/var/run
chown root:${GROUP} ${DIR}/var/run

# Moving the binary files
cp -pr addagent/manage_agents agentlessd/ossec-agentlessd \
        analysisd/ossec-analysisd logcollector/ossec-logcollector \
        monitord/ossec-monitord monitord/ossec-reportd \
        os_execd/ossec-execd os_maild/ossec-maild \
        remoted/ossec-remoted syscheckd/ossec-syscheckd \
	analysisd/ossec-logtest os_csyslogd/ossec-csyslogd \
	os_auth/ossec-authd os_dbd/ossec-dbd analysisd/ossec-makelists \
	${DIR}/bin/

cp -pr util/verify-agent-conf ${DIR}/bin/
cp -pr util/clear_stats ${DIR}/bin/
cp -pr util/list_agents ${DIR}/bin/
cp -pr util/ossec-regex ${DIR}/bin/
cp -pr util/syscheck_update ${DIR}/bin/
cp -pr util/agent_control ${DIR}/bin/
cp -pr util/syscheck_control ${DIR}/bin/
cp -pr util/rootcheck_control ${DIR}/bin/
cp -pr external/lua/src/ossec-lua ${DIR}/bin/
cp -pr external/lua/src/ossec-luac ${DIR}/bin/
cp -pr ../contrib/util.sh ${DIR}/bin/
chown root:${GROUP} ${DIR}/bin/util.sh
chmod +x ${DIR}/bin/util.sh

# Local install chosen
if [ "X$LOCAL" = "Xlocal" ]; then
    cp -pr ./init/ossec-local.sh ${DIR}/bin/ossec-control
else    
    cp -pr ./init/ossec-server.sh ${DIR}/bin/ossec-control
fi

# Moving the decoders/internal_conf file.
cp -pr ../etc/decoder.xml ${DIR}/etc/

# Copying local files.
cp -pr ../etc/local_decoder.xml ${DIR}/etc/ > /dev/null 2>&1
cp -pr ../etc/local_internal_options.conf ${DIR}/etc/ > /dev/null 2>&1
cp -pr ../etc/client.keys ${DIR}/etc/ > /dev/null 2>&1

# Copying agentless files.
cp -pr agentlessd/scripts/* ${DIR}/agentless/


# Backup currently internal_options file.
ls ${DIR}/etc/internal_options.conf > /dev/null 2>&1
if [ $? = 0 ]; then
  cp -pr ${DIR}/etc/internal_options.conf ${DIR}/etc/backup-internal_options.$$
fi
  
cp -pr ../etc/internal_options.conf ${DIR}/etc/
cp -pr rootcheck/db/*.txt ${DIR}/etc/shared/
chown root:${GROUP} ${DIR}/etc/decoder.xml
chown root:${GROUP} ${DIR}/etc/local_decoder.xml >/dev/null 2>&1
chown root:${GROUP} ${DIR}/etc/internal_options.conf
chown root:${GROUP} ${DIR}/etc/local_internal_options.conf >/dev/null 2>&1
chown root:${GROUP} ${DIR}/etc/client.keys >/dev/null 2>&1
chown root:${GROUP} ${DIR}/etc/shared/*
chown root:${GROUP} ${DIR}/agentless/*
chown ${USER}:${GROUP} ${DIR}/.ssh
chmod 440 ${DIR}/etc/decoder.xml
chmod 440 ${DIR}/etc/local_decoder.xml >/dev/null 2>&1
chmod 440 ${DIR}/etc/internal_options.conf
chmod 440 ${DIR}/etc/local_internal_options.conf >/dev/null 2>&1
chmod 440 ${DIR}/etc/client.keys >/dev/null 2>&1
chmod 550 ${DIR}/etc
chmod 770 ${DIR}/etc/shared
chmod 440 ${DIR}/etc/shared/*
chmod 550 ${DIR}/agentless/*
rm ${DIR}/etc/shared/merged.mg >/dev/null 2>&1
chmod 700 ${DIR}/.ssh


# Copying active response modules
sh ./init/fw-check.sh execute > /dev/null
cp -p ../active-response/*.sh ${DIR}/active-response/bin/
cp -p ../active-response/firewalls/*.sh ${DIR}/active-response/bin/

chmod 550 ${DIR}/active-response/bin/*
chown root:${GROUP} ${DIR}/active-response/bin/*

chown root:${GROUP} ${DIR}/bin/*
chmod 550 ${DIR}/bin/*


# Moving the config file
ls ${DIR}/etc/ossec.conf > /dev/null 2>&1
if [ $? = 0 ]; then
    exit 0;
fi

ls ../etc/ossec.mc > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -pr ../etc/ossec.mc ${DIR}/etc/ossec.conf
else    
    cp -pr ../etc/ossec-server.conf ${DIR}/etc/ossec.conf
fi
chown root:${GROUP} ${DIR}/etc/ossec.conf
chmod 440 ${DIR}/etc/ossec.conf



exit 0;

#EOF
