#!/bin/sh


# Checking if it is executed from the right place
LOCATION=./LOCATION
if [ ! -e ${LOCATION} ]; then
    echo "Cannot execute. Wrong directory"
    exit 1;
fi

UNAME=`uname`;
# Getting default variables
DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
GROUP="ossec"
USER="ossec"
subdirs="logs bin queue queue/ossec var var/run etc checksum_db"


# ${DIR} must be set 
if [ "X${DIR}" = "X" ]; then
    echo "Error building OSSEC HIDS."
    exit 1;
fi    


# Creating root directory
if [ ! -d ${DIR} ]; then mkdir -m 700 -p ${DIR}; fi
if [ ! -d ${DIR} ]; then 
    echo "You do not have permissions to create ${DIR}. Exiting..."
    exit 1;
fi


# Creating groups/users
if [ "$UNAME" = "FreeBSD" ]; then
    /usr/sbin/pw groupadd ${GROUP}
	/usr/sbin/pw useradd ${USER} -d ${DIR} -s /sbin/nologin -g ${GROUP}

else
	/usr/sbin/groupadd ${GROUP}
	/usr/sbin/useradd -d ${DIR} -s /sbin/nologin -g ${GROUP} ${USER}
fi


# Creating sub dirs
for i in ${subdirs}; do
    if [ ! -d ${DIR}/${i} ]; then mkdir -m 700 ${DIR}/${i}; fi
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

# For the etc dir
chmod 550 ${DIR}/etc
chown -R root:${GROUP} ${DIR}/etc
if [ -e /etc/localtime ]; then
    cp -pr /etc/localtime ${DIR}/etc/; 
fi

# For the /var/run
chmod 770 ${DIR}/var/run
chown root:${GROUP} ${DIR}/var/run

# Moving the binary files
cp -pr ../bin/ossec-agentd ${DIR}/bin/
cp -pr ../bin/ossec-logcollector ${DIR}/bin/
cp -pr ../bin/ossec-syscheckd ${DIR}/bin/
cp -pr ./init/ossec-client ${DIR}/bin/ossec-control
cp -pr ../bin/manage_agents ${DIR}/bin/

# Moving the config file
if [ -e ${DIR}/etc/ossec.conf ]; then
    echo "Not overwritting ${DIR}/etc/ossec.conf .."
elif [ -e ../etc/ossec.mc ]; then
    cp -pr ../etc/ossec.mc ${DIR}/etc/ossec.conf
else    
    cp -pr ../etc/ossec-agent.conf ${DIR}/etc/ossec.conf
fi

exit 0;
