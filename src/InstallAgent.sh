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
subdirs="logs bin queue queue/ossec queue/alerts queue/syscheck queue/rids queue/diff var var/run etc etc/shared active-response active-response/bin agentless .ssh"


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
    grep "^${USER}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
    /usr/sbin/pw groupadd ${GROUP}
	/usr/sbin/pw useradd ${USER} -d ${DIR} -s /sbin/nologin -g ${GROUP}
    fi

elif [ "$UNAME" = "SunOS" ]; then
    grep "^${USER}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
    /usr/sbin/groupadd ${GROUP}
    /usr/sbin/useradd -d ${DIR} -s /bin/false -g ${GROUP} ${USER}
    fi

elif [ "$UNAME" = "AIX" ]; then
    AIXSH=""
    ls -la /bin/false > /dev/null 2>&1
    if [ $? = 0 ]; then
        AIXSH="-s /bin/false"
    fi
    grep "^${USER}" /etc/passwd > /dev/null 2>&1
    if [ ! $? = 0 ]; then
    /usr/bin/mkgroup ${GROUP}
    /usr/sbin/useradd -d ${DIR} ${AIXSH} -g ${GROUP} ${USER}
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
    grep "^${USER}" /etc/passwd > /dev/null 2>&1
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
    fi
fi


# Creating sub dirs
for i in ${subdirs}; do
    ls ${DIR}/${i} > /dev/null 2>&1
    if [ $? != 0 ]; then mkdir -m 700 ${DIR}/${i}; fi
done

# Default for all directories
chmod -R 550 ${DIR}
chown -R root:${GROUP} ${DIR}

# To the ossec queue (default for agentd to read)
chown -R ${USER}:${GROUP} ${DIR}/queue/ossec
chmod -R 770 ${DIR}/queue/ossec

# For the logging user
chown -R ${USER}:${GROUP} ${DIR}/logs
chmod -R 750 ${DIR}/logs
chmod -R 775 ${DIR}/queue/rids
touch ${DIR}/logs/ossec.log
chown ${USER}:${GROUP} ${DIR}/logs/ossec.log
chmod 664 ${DIR}/logs/ossec.log

chown -R ${USER}:${GROUP} ${DIR}/queue/diff
chmod -R 750 ${DIR}/queue/diff
chmod 740 ${DIR}/queue/diff/* > /dev/null 2>&1




# For the etc dir
chmod 550 ${DIR}/etc
chown -R root:${GROUP} ${DIR}/etc

ls /etc/localtime > /dev/null 2>&1
if [ $? = 0 ]; then
        cp -p /etc/localtime ${DIR}/etc/;
fi

# Solaris Needs some extra files
if [ "$UNAME" = "SunOS" ]; then
    mkdir -p ${DIR}/usr/share/lib/zoneinfo/
    chmod -R 555 ${DIR}/usr/
    cp -pr /usr/share/lib/zoneinfo/* ${DIR}/usr/share/lib/zoneinfo/
    chown -R root:${GROUP} ${DIR}/usr/
fi    

ls /etc/TIMEZONE > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -p /etc/TIMEZONE ${DIR}/etc/;
    chown root:${GROUP} ${DIR}/etc/TIMEZONE
    chmod 555 ${DIR}/etc/TIMEZONE
fi
            
        

# For the /etc/shared
cp -pr rootcheck/db/*.txt ${DIR}/etc/shared/

# Backup currently internal_options file.
ls ${DIR}/etc/internal_options.conf > /dev/null 2>&1
if [ $? = 0 ]; then
  cp -pr ${DIR}/etc/internal_options.conf ${DIR}/etc/backup-internal_options.$$
fi
      
cp -pr ../etc/internal_options.conf ${DIR}/etc/
cp -pr ../etc/local_internal_options.conf ${DIR}/etc/ > /dev/null 2>&1
cp -pr ../etc/client.keys ${DIR}/etc/ > /dev/null 2>&1
cp -pr agentlessd/scripts/* ${DIR}/agentless/

chown root:${GROUP} ${DIR}/etc/internal_options.conf
chown root:${GROUP} ${DIR}/etc/local_internal_options.conf > /dev/null 2>&1
chown root:${GROUP} ${DIR}/etc/client.keys > /dev/null 2>&1
chown root:${GROUP} ${DIR}/agentless/*
chown ${USER}:${GROUP} ${DIR}/.ssh
chown -R root:${GROUP} ${DIR}/etc/shared

chmod 550 ${DIR}/etc
chmod 440 ${DIR}/etc/internal_options.conf
chmod 440 ${DIR}/etc/local_internal_options.conf > /dev/null 2>&1
chmod 440 ${DIR}/etc/client.keys > /dev/null 2>&1
chmod -R 770 ${DIR}/etc/shared # ossec must be able to write to it
chmod 550 ${DIR}/agentless/*
chmod 700 ${DIR}/.ssh


# For the /var/run
chmod 770 ${DIR}/var/run
chown root:${GROUP} ${DIR}/var/run


# Moving the binary files
cp -pr client-agent/ossec-agentd ${DIR}/bin/
cp -pr os_auth/agent-auth ${DIR}/bin/
cp -pr logcollector/ossec-logcollector ${DIR}/bin/
cp -pr syscheckd/ossec-syscheckd ${DIR}/bin/
cp -pr os_execd/ossec-execd ${DIR}/bin/
cp -pr ./init/ossec-client.sh ${DIR}/bin/ossec-control
cp -pr addagent/manage_agents ${DIR}/bin/
cp -pr ../contrib/util.sh ${DIR}/bin/
cp -pr external/lua/src/ossec-lua ${DIR}/bin/
cp -pr external/lua/src/ossec-luac ${DIR}/bin/
chown root:${GROUP} ${DIR}/bin/util.sh
chmod +x ${DIR}/bin/util.sh

# Copying active response modules
sh ./init/fw-check.sh execute > /dev/null
cp -pr ../active-response/*.sh ${DIR}/active-response/bin/
cp -pr ../active-response/firewalls/*.sh ${DIR}/active-response/bin/
chmod 755 ${DIR}/active-response/bin/*
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
    cp -pr ../etc/ossec-agent.conf ${DIR}/etc/ossec.conf
fi
chown root:${GROUP} ${DIR}/etc/ossec.conf
chmod 440 ${DIR}/etc/ossec.conf



exit 0;

#EOF
