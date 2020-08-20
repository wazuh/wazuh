#!/bin/bash
## Check if system is based on yum or apt-get
char="#"
debug='> /dev/null 2>&1'
if [ -n "$(command -v yum)" ] 
then
    sys_type="yum"
elif [ -n "$(command -v zypper)" ] 
then
    sys_type="zypper"     
elif [ -n "$(command -v apt-get)" ] 
then
    sys_type="apt-get"   
fi

logger() {

    echo $1
    
}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload $debug"
        eval "systemctl enable $1.service $debug"
        eval "systemctl start $1.service $debug"
        if [  "$?" != 0  ]
        then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on $debug"
        eval "service $1 start $debug"
        eval "/etc/init.d/$1 start $debug"
        if [  "$?" != 0  ]
        then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start $debug"
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

## Show script usage
getHelp() {

   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-d   | --debug Shows the complete installation output"
   echo -e "\t-i   | --ignore-health-check Ignores the health-check"
   echo -e "\t-h   | --help Shows help"
   exit 1 # Exit script after printing help

}


## Install the required packages for the installation
installPrerequisites() {

    logger "Installing all necessary utilities for the installation..."

    if [ $sys_type == "yum" ]
    then
        eval "yum install curl unzip wget libcap -y -q $debug"
        eval "yum install java-11-openjdk-devel -y -q $debug"
        if [ "$?" != 0 ]
        then
            os=$(cat /etc/os-release > /dev/null 2>&1 | awk -F"ID=" '/ID=/{print $2; exit}' | tr -d \")
            if [ -z "$os" ]
            then
                os="centos"
            fi
            echo -e '[AdoptOpenJDK] \nname=AdoptOpenJDK \nbaseurl=http://adoptopenjdk.jfrog.io/adoptopenjdk/rpm/system-ver/$releasever/$basearch\nenabled=1\ngpgcheck=1\ngpgkey=https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public' | eval "tee /etc/yum.repos.d/adoptopenjdk.repo $debug"
            conf="$(awk '{sub("system-ver", "'"${os}"'")}1' /etc/yum.repos.d/adoptopenjdk.repo)"
            echo "$conf" > /etc/yum.repos.d/adoptopenjdk.repo 
            eval "yum install adoptopenjdk-11-hotspot -y -q $debug"
        fi
        export JAVA_HOME=/usr/
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install curl unzip wget $debug" 
        eval "zypper -n install libcap-progs $debug || zypper -n install libcap2 $debug"
        eval "zypper -n install java-11-openjdk-devel $debug"
        if [ "$?" != 0 ]
        then
            eval "zypper ar -f http://adoptopenjdk.jfrog.io/adoptopenjdk/rpm/opensuse/15.0/$(uname -m) adoptopenjdk $debug" | echo 'a'
            eval "zypper -n install adoptopenjdk-11-hotspot $debug "

        fi    
        export JAVA_HOME=/usr/    
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin -y -q $debug"

        if [ -n "$(command -v add-apt-repository)" ]
        then
            eval "add-apt-repository ppa:openjdk-r/ppa -y $debug"
        else
            echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        fi
        eval "apt-get update -q $debug"
        eval "apt-get install openjdk-11-jdk -y -q $debug" 
        if [  "$?" != 0  ]
        then
            logger "JDK installation falied."
            exit 1;
        fi
        export JAVA_HOME=/usr/
        
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
        eval "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH $debug"
        eval "echo -e '[wazuh_trash]\ngpgcheck=1\ngpgkey=https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/trash/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_pre.repo $debug"
    elif [ $sys_type == "zypper" ] 
    then
        eval "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH $debug"
        eval "echo -e '[wazuh_trash]\ngpgcheck=1\ngpgkey=https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/trash/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh_pre.repo $debug"            
    elif [ $sys_type == "apt-get" ] 
    then
        eval "curl -s https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH --max-time 300 | apt-key add - $debug"
        eval "echo "deb https://packages-dev.wazuh.com/trash/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_trash.list $debug"
        eval "apt-get update -q $debug"
    fi    

    logger "Done" 
}

## Wazuh manager
installWazuh() {
    
    logger "Installing the Wazuh manager..."
    if [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install wazuh-manager $debug"
    else
        eval "$sys_type install wazuh-manager -y -q $debug"
    fi
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
        eval "yum install opendistroforelasticsearch -y -q $debug"
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install opendistroforelasticsearch $debug"
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install elasticsearch-oss opendistroforelasticsearch -y -q $debug"
    fi

    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch installation failed"
        exit 1;
    else
        logger "Done"

        logger "Configuring Elasticsearch..."

        eval "curl -so /etc/elasticsearch/elasticsearch.yml https://documentation.wazuh.com/resources/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://documentation.wazuh.com/resources/open-distro/elasticsearch/roles/roles.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://documentation.wazuh.com/resources/open-distro/elasticsearch/roles/roles_mapping.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://documentation.wazuh.com/resources/open-distro/elasticsearch/roles/internal_users.yml --max-time 300 $debug"
        eval "rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f $debug"
        eval "mkdir /etc/elasticsearch/certs $debug"
        eval "cd /etc/elasticsearch/certs $debug"
        eval "curl -so /etc/elasticsearch/certs/search-guard-tlstool-1.8.zip https://maven.search-guard.com/search-guard-tlstool/1.8/search-guard-tlstool-1.8.zip --max-time 300 $debug"
        eval "unzip search-guard-tlstool-1.8.zip -d searchguard $debug"
        eval "curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml https://documentation.wazuh.com/resources/open-distro/searchguard/search-guard-aio.yml --max-time 300 $debug"
        eval "chmod +x searchguard/tools/sgtlstool.sh $debug"
        eval "./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/ $debug"
        if [  "$?" != 0  ]
        then
            echo "Error: certificates were not created"
            exit 1;
        else
            logger "Certificates created"
        fi     
        eval "rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.8.zip -f $debug"
        
        # Configure JVM options for Elasticsearch
        ram_gb=$(free -g | awk '/^Mem:/{print $2}')
        ram=$(( ${ram_gb} / 2 ))

        if [ ${ram} -eq "0" ]; then
            ram=1;
        fi    
        eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options $debug"
        eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options $debug"

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

        eval "cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ $debug"
        eval "./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key $debug"

        echo "Done"
    fi

}

## Filebeat
installFilebeat() {
    
    logger "Installing Filebeat..."
    
    if [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install filebeat $debug"
    else
        eval "$sys_type install filebeat -y -q  $debug"
    fi
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat installation failed"
        exit 1;
    else
        eval "curl -so /etc/filebeat/filebeat.yml https://documentation.wazuh.com/resources/open-distro/filebeat/7.x/filebeat_all_in_one.yml --max-time 300  $debug"
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.13.1/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 $debug"
        eval "chmod go+r /etc/filebeat/wazuh-template.json $debug"
        eval "curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module $debug"
        eval "mkdir /etc/filebeat/certs $debug"
        eval "cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/ $debug"
        eval "mv /etc/elasticsearch/certs/filebeat* /etc/filebeat/certs/ $debug"

        # Start Filebeat
        startService "filebeat"

        logger "Done"
    fi

}

## Kibana
installKibana() {
    
    logger "Installing Open Distro for Kibana..."
    if [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install opendistroforelasticsearch-kibana $debug"
    else
        eval "$sys_type install opendistroforelasticsearch-kibana -y -q $debug"
    fi
    if [  "$?" != 0  ]
    then
        echo "Error: Kibana installation failed"
        exit 1;
    else    
        eval "curl -so /etc/kibana/kibana.yml https://documentation.wazuh.com/resources/open-distro/kibana/7.x/kibana_all_in_one.yml --max-time 300 $debug"
        eval "cd /usr/share/kibana $debug"
        eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/trash/ui/kibana/wazuhapp-4.0.0_7.8.0_0.0.0.todelete.zip $debug"
        if [  "$?" != 0  ]
        then
            echo "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi     
        eval "mkdir /etc/kibana/certs $debug"
        eval "mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/ $debug"
        eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node $debug"

        # Start Kibana
        startService "kibana"

        logger "Done"
    fi

}

## Health check
healthCheck() {

    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')

    if [[ $cores < "2" ]] || [[ $ram_gb < "3700" ]]
    then
        echo "The system must have at least 4Gb of RAM and 2 CPUs"
        exit 1;
    else
        echo "Starting the installation..."
    fi

}

checkInstallation() {

    logger "Checking the installation..."
    eval "curl -XGET https://localhost:9200 -uadmin:admin -k --max-time 300 $debug"
    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch was not successfully installed."
        exit 1;     
    else
        echo "Elasticsearch installation succeeded."
    fi
    eval "filebeat test output $debug"
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat was not successfully installed."
        exit 1;     
    else
        echo "Filebeat installation succeeded."
    fi    
    logger "Initializing Kibana (this may take a while)"
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:admin -k -s --max-time 300 | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done    
    echo $'\nInstallation finished'
    exit 0;

}

main() {

    if [ -n "$1" ] 
    then      
        while [ -n "$1" ]
        do
            case "$1" in 
            "-i"|"--ignore-healthcheck") 
                i=1          
                shift 1
                ;; 
            "-d"|"--debug") 
                d=1          
                shift 1
                ;;                                 
            "-h"|"--help")        
                getHelp
                ;;                                         
            *)
                exit 1
            esac
        done    

        if [ -n "$d" ]
        then
            debug=""
        fi
        
        if [ -n "$i" ]
        then
            echo "Health-check ignored."    
        else
            healthCheck           
        fi             
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
