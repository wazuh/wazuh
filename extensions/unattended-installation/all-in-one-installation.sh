#!/bin/bash
## Check if system is based on yum or apt-get
char="#"
if [ -n "$(command -v yum)" ] 
then
    sys_type="yum"
elif [ -n "$(command -v apt-get)" ] 
then
    sys_type="apt-get"
fi

logger() {
    echo $1
}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        systemctl daemon-reload > /dev/null 2>&1
        systemctl enable $1.service > /dev/null 2>&1
        systemctl start $1.service > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        chkconfig $1 on > /dev/null 2>&1
        service $1 start > /dev/null 2>&1
        /etc/init.d/$1 start > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        /etc/rc.d/init.d/$1 start > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi             
    else
        echo "Error: ${1^} could not start. No service manager found on the system."
        exit 1;
    fi
}


## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."

    if [ $sys_type == "yum" ] 
    then
        yum install java-11-openjdk-devel -y -q > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            yum install java-1.8.0-openjdk-devel -y -q > /dev/null 2>&1
            export JAVA_HOME=/usr/
            yum install unzip wget curl libcap -y -q > /dev/null 2>&1
        else
            export JAVA_HOME=/usr/
            yum install unzip wget curl libcap -y -q > /dev/null 2>&1
        fi        
    elif [ $sys_type == "apt-get" ] 
    then
        if [ -n "$(command -v add-apt-repository)" ]
        then
            add-apt-repository ppa:openjdk-r/ppa -y > /dev/null 2>&1
        else
            echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        fi
        apt-get update -q > /dev/null 2>&1
        apt-get install openjdk-11-jdk -y -q > /dev/null 2>&1 
        export JAVA_HOME=/usr/ 
        apt-get install apt-transport-https curl unzip wget libcap2-bin -y -q > /dev/null 2>&1
    fi

    if [  "$?" != 0  ]
    then
        echo "Error: Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi   
}

## Add the Wazuh repository
addWazuhrepo() {
    logger "Adding the Wazuh repository..."

    if [ $sys_type == "yum" ] 
    then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH > /dev/null 2>&1
        echo -e '[wazuh_trash]\ngpgcheck=1\ngpgkey=https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/trash/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_pre.repo > /dev/null 2>&1
    elif [ $sys_type == "apt-get" ] 
    then
        curl -s https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH --max-time 300 | apt-key add - > /dev/null 2>&1
        echo "deb https://packages-dev.wazuh.com/trash/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_trash.list > /dev/null 2>&1
        apt-get update -q > /dev/null 2>&1
    fi    

    if [  "$?" != 0  ]
    then
        echo "Error: Wazuh repository could not be added"
        exit 1;
    else
        logger "Done"
    fi        
}

## Wazuh manager and API
installWazuh() {
    logger "Installing the Wazuh manager and the Wazuh API..."

    if [ $sys_type == "yum" ] 
    then
        curl -sL https://rpm.nodesource.com/setup_10.x --max-time 300 | bash - > /dev/null 2>&1
    elif [ $sys_type == "apt-get" ] 
    then
        curl -sL https://deb.nodesource.com/setup_10.x --max-time 300 | bash - > /dev/null 2>&1
    fi 
    $sys_type install wazuh-manager nodejs wazuh-api -y -q > /dev/null 2>&1
    if [  "$?" != 0  ]
    then
        echo "Error: Wazuh installation failed"
        exit 1;
    else
        logger "Done"
    fi     
}

## Elasticsearch
installElasticsearch() {
    logger "Installing Open Distro for Elasticsearch..."

    if [ $sys_type == "yum" ] 
    then
        yum install opendistroforelasticsearch -y -q > /dev/null 2>&1
    elif [ $sys_type == "apt-get" ] 
    then
        apt-get install elasticsearch-oss opendistroforelasticsearch -y -q > /dev/null 2>&1
    fi

    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch installation failed"
        exit 1;
    else
        logger "Done"

        logger "Configuring Elasticsearch..."

        curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/7.x/elasticsearch_all_in_one.yml --max-time 300 > /dev/null 2>&1
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles.yml --max-time 300 > /dev/null 2>&1
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles_mapping.yml --max-time 300 > /dev/null 2>&1
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/internal_users.yml --max-time 300 > /dev/null 2>&1
        rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f > /dev/null 2>&1
        mkdir /etc/elasticsearch/certs > /dev/null 2>&1
        cd /etc/elasticsearch/certs > /dev/null 2>&1
        curl -so /etc/elasticsearch/certs/search-guard-tlstool-1.7.zip https://releases.floragunn.com/search-guard-tlstool/1.7/search-guard-tlstool-1.7.zip --max-time 300 > /dev/null 2>&1
        unzip search-guard-tlstool-1.7.zip -d searchguard > /dev/null 2>&1
        curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/searchguard/search-guard-aio.yml --max-time 300 > /dev/null 2>&1
        chmod +x searchguard/tools/sgtlstool.sh > /dev/null 2>&1
        ./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/ > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            echo "Error: certificates were not created"
            exit 1;
        else
            logger "Certificates created"
        fi     
        rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.7.zip -f > /dev/null 2>&1
        
        # Configure JVM options for Elasticsearch
        ram_gb=$(free -g | awk '/^Mem:/{print $2}')
        ram=$(( ${ram_gb} / 2 ))

        if [ ${ram} -eq "0" ]; then
            ram=1;
        fi    
        sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options > /dev/null 2>&1
        sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options > /dev/null 2>&1

        jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
        if [ "$jv" == "1.8.0" ]
        then
            ln -s /usr/lib/jvm/java-1.8.0/lib/tools.jar /usr/share/elasticsearch/lib/
            echo "root hard nproc 4096" >> /etc/security/limits.conf 
            echo "root soft nproc 4096" >> /etc/security/limits.conf 
            echo "elasticsearch hard nproc 4096" >> /etc/security/limits.conf 
            echo "elasticsearch soft nproc 4096" >> /etc/security/limits.conf 
            echo "bootstrap.system_call_filter: false" >> /etc/elasticsearch/elasticsearch.yml
        fi      

        # Start Elasticsearch
        startService "elasticsearch"
        echo "Initializing Elasticsearch..."
        until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
            echo -ne $char
            sleep 10
        done    

        cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ > /dev/null 2>&1
        ./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key > /dev/null 2>&1

        echo "Done"
    fi
}

## Filebeat
installFilebeat() {
    
    logger "Installing Filebeat..."

    $sys_type install filebeat -y -q  > /dev/null 2>&1
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat installation failed"
        exit 1;
    else
        curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/filebeat/7.x/filebeat_all_in_one.yml --max-time 300  > /dev/null 2>&1
        curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.12.0/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 > /dev/null 2>&1
        chmod go+r /etc/filebeat/wazuh-template.json > /dev/null 2>&1
        curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module > /dev/null 2>&1
        mkdir /etc/filebeat/certs > /dev/null 2>&1
        cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/ > /dev/null 2>&1
        mv /etc/elasticsearch/certs/filebeat* /etc/filebeat/certs/ > /dev/null 2>&1

        # Start Filebeat
        startService "filebeat"

        logger "Done"
    fi
}

## Kibana
installKibana() {
    
    logger "Installing Open Distro for Kibana..."

    $sys_type install opendistroforelasticsearch-kibana -y -q > /dev/null 2>&1
    if [  "$?" != 0  ]
    then
        echo "Error: Kibana installation failed"
        exit 1;
    else   
        curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/kibana/7.x/kibana_all_in_one.yml --max-time 300 > /dev/null 2>&1
        cd /usr/share/kibana > /dev/null 2>&1
        sudo -u kibana bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.13.1_7.8.0.zip > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            echo "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi     
        mkdir /etc/kibana/certs > /dev/null 2>&1
        mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/ > /dev/null 2>&1
        setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node > /dev/null 2>&1

        # Start Kibana
        startService "kibana"

        logger "Done"
    fi
}

## Health check
healthCheck() {
    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')

    if [[ $cores < "2" ]] || [[ $ram_gb < "4" ]]
    then
        echo "The system must have at least 4Gb of RAM and 2 CPUs"
        exit 1;
    else
        echo "Starting the installation..."
    fi
}

checkInstallation() {
    logger "Checking the installation..."
    curl -XGET https://localhost:9200 -uadmin:admin -k --max-time 300 > /dev/null 2>&1
    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch was not successfully installed."
        exit 1;     
    else
        echo "Elasticsearch installation succeeded."
    fi
    filebeat test output > /dev/null 2>&1
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat was not successfully installed."
        exit 1;     
    else
        echo "Filebeat installation succeeded."
    fi    
    logger "Initializing Kibana (this may take a while)"
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:admin -k -s | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done    
    echo $'\nInstallation finished'
    exit 1;
}

main() {
    if [ "$1" == "-i" ] || [ "$1" == "--ignore-healthcheck" ]
    then
        echo "Health-check ignored."
        installPrerequisites
        addWazuhrepo
        installWazuh
        installElasticsearch
        installFilebeat
        installKibana
        checkInstallation
    else
        healthCheck
        installPrerequisites
        addWazuhrepo
        installWazuh
        installElasticsearch
        installFilebeat
        installKibana
        checkInstallation         
    fi 
}

main "$@"
