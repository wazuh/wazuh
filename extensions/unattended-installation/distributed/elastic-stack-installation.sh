#!/bin/bash
## Check if system is based on yum or apt-get
char="#"
debug='> /dev/null 2>&1'
if [ -n "$(command -v yum)" ] 
then
    sys_type="yum"
elif [ -n "$(command -v apt-get)" ] 
then
    sys_type="apt-get"
fi

## Prints information
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
   echo -e "\t-e   | --install-elasticsearch Install Elasticsearch"
   echo -e "\t-k   | --install-kibana Install Kibana"
   echo -e "\t-c   | --create-certificates Generates the certificates for all the indicated nodes"
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
        eval "yum install java-11-openjdk-devel -y -q $debug"
        if [  "$?" != 0  ]
        then
            eval "yum install java-1.8.0-openjdk-devel -y -q $debug"
            export JAVA_HOME=/usr/
            eval "yum install unzip curl wget libcap -y -q $debug"
        else
            export JAVA_HOME=/usr/
            eval "yum install unzip curl wget libcap -y -q $debug"
        fi        
    elif [ $sys_type == "apt-get" ] 
    then
        if [ -n "$(command -v add-apt-repository)" ]
        then
            eval "add-apt-repository ppa:openjdk-r/ppa -y $debug"
        else
            echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        fi
        eval "apt-get update -q $debug"
        eval "apt-get install openjdk-11-jdk -y -q $debug "
        export JAVA_HOME=/usr/ 
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin -y -q $debug"
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
    elif [ $sys_type == "apt-get" ] 
    then
        eval "curl -s https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH --max-time 300 | apt-key add - $debug"
        eval "echo "deb https://packages-dev.wazuh.com/trash/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_trash.list $debug"
        eval "apt-get update -q $debug"
    fi    

    logger "Done" 
}

## Elasticsearch
installElasticsearch() {


    logger "Installing Opend Distro for Elasticsearch..."

    if [ $sys_type == "yum" ] 
    then
        eval "yum install opendistroforelasticsearch -y -q $debug"
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

        eval "curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/unattended-installation/distributed/templates/elasticsearch_unattended.yml --max-time 300 $debug"
        
        awk -v RS='' '/## Elasticsearch/' ~/config.yml >> /etc/elasticsearch/elasticsearch.yml

        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles_mapping.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/internal_users.yml --max-time 300 $debug"
        eval "rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f $debug"
        eval "mkdir /etc/elasticsearch/certs $debug"
        eval "cd /etc/elasticsearch/certs $debug"

        
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

        if [ -n "$single" ]
        then
            createCertificates
        else
            logger "Done"
        fi
        
    fi
}

createCertificates() {
  

    logger "Creating the certificates..."
    eval "curl -so /etc/elasticsearch/certs/search-guard-tlstool-1.7.zip https://releases.floragunn.com/search-guard-tlstool/1.7/search-guard-tlstool-1.7.zip --max-time 300 $debug"
    eval "unzip search-guard-tlstool-1.7.zip -d searchguard $debug"
    eval "curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/unattended-installation/distributed/templates/search-guard-unattended.yml --max-time 300 $debug"

    awk -v RS='' '/## Certificates/' ~/config.yml >> /etc/elasticsearch/certs/searchguard/search-guard.yml

    eval "chmod +x searchguard/tools/sgtlstool.sh $debug"
    eval "./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/ $debug            "
    if [  "$?" != 0  ]
    then
        echo "Error: certificates were no created"
        exit 1;
    else
        logger "Certificates created"
        mv /etc/elasticsearch/certs/node-1.pem /etc/elasticsearch/certs/elasticsearch.pem
        mv /etc/elasticsearch/certs/node-1.key /etc/elasticsearch/certs/elasticsearch.key
        mv /etc/elasticsearch/certs/node-1_http.pem /etc/elasticsearch/certs/elasticsearch_http.pem
        mv /etc/elasticsearch/certs/node-1_http.key /etc/elasticsearch/certs/elasticsearch_http.key            
        eval "rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.7.zip -f $debug"
    fi

    if [[ -n "$c" ]] || [[ -n "$single" ]]
    then
        tar -cf certs.tar *
        tar --delete -f certs.tar 'searchguard'
    fi

    logger "Elasticsearch installed."  

    # Start Elasticsearch
    logger "Starting Elasticsearch..."
    startService "elasticsearch"
    logger "Initializing Elasticsearch..."
    elk=$(awk -F'network.host: ' '{print $2}' ~/config.yml | xargs)
    until $(curl -XGET https://${elk}:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
        echo -ne $char
        sleep 10
    done    

    if [ -n "$single" ]
    then
        eval "cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ $debug"
        eval "./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key -h ${elk} $debug"
    fi

    logger "Done"
}

## Kibana
installKibana() {
     
    
    logger "Installing Open Distro for Kibana..."

    eval "$sys_type install opendistroforelasticsearch-kibana -y -q $debug"
    if [  "$?" != 0  ]
    then
        echo "Error: Kibana installation failed"
        exit 1;
    else   
        eval "curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/unattended-installation/distributed/templates/kibana_unattended.yml --max-time 300 $debug"
        eval "cd /usr/share/kibana $debug"
        eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.13.1_7.8.0.zip $debug"
        eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node $debug"
        if [  "$?" != 0  ]
        then
            echo "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi     
        eval "mkdir /etc/kibana/certs $debug"
        awk -v RS='' '/## Kibana/' ~/config.yml >> /etc/kibana/kibana.yml 
        logger "Kibana installed."

        if [[ -n "$e" ]] && [[ -n "$k" ]] && [[ -n "$c" ]]
        then
            eval "mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/ $debug"
        fi

        if [[ -n "$e" ]] && [[ -n "$k" ]] && [[ -n "$single" ]]
        then
            initializeKibana
        fi
    fi

}

initializeKibana() {
    eval "mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/ $debug"
    # Start Kibana
    startService "kibana"   
    logger "Initializing Kibana (this may take a while)" 
    elk=$(awk -F'network.host: ' '{print $2}' ~/config.yml | xargs) 
    until [[ "$(curl -XGET https://${elk}/status -I -uadmin:admin -k -s | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done     
    wip=$(cat ~/config.yml | grep "url: https:")
    conf="$(awk '{sub("url: https://localhost", "'"${wip}"'")}1' /usr/share/kibana/optimize/wazuh/config/wazuh.yml)"
    echo "$conf" > /usr/share/kibana/optimize/wazuh/config/wazuh.yml   
}

## Check nodes
checkNodes() {
    head=$(head -n1 config.yml)
    if [ "${head}" == "## Multi-node configuration" ]
    then
        master=1
    else
        single=1
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

## Main

main() {

    if [ -n "$1" ] 
    then      
        while [ -n "$1" ]
        do
            case "$1" in           
            "-e"|"--install-elasticsearch")        
                e=1
                shift 1
                ;;      
            "-c"|"--create-certificates") 
                c=1  
                shift 1
                ;;                                  
            "-k"|"--install-kibana") 
                k=1          
                shift 1
                ;;
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
        checkNodes        
        if [ -n "$e" ]
        then
            installElasticsearch
        fi
        if [[ -n "$c" ]] && [[ -n "$e" ]]
        then
            createCertificates
        fi
        if [ -n "$k" ]
        then
            installKibana
        fi
    else
        getHelp
    fi
}

main "$@"
