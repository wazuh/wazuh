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
subdirs="logs bin queue queue/ossec var var/run etc etc/shared checksum_db"


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

else
	/usr/sbin/groupadd ${GROUP}
	/usr/sbin/useradd -d ${DIR} -s /sbin/nologin -g ${GROUP} ${USER}
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

# For the etc dir
chmod 550 ${DIR}/etc
chown -R root:${GROUP} ${DIR}/etc

ls /etc/localtime > /dev/null 2>&1
if [ $? = 0 ]; then
        cp -pL /etc/localtime ${DIR}/etc/;
fi
        

# For the /etc/shared
chmod 770 ${DIR}/etc/shared # ossec must be able to write to it


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
ls ../etc/ossec.mc > /dev/null 2>&1
if [ $? = 0 ]; then
    cp -pr ../etc/ossec.mc ${DIR}/etc/ossec.conf
else    
    cp -pr ../etc/ossec-agent.conf ${DIR}/etc/ossec.conf
fi

exit 0;

#EOF
