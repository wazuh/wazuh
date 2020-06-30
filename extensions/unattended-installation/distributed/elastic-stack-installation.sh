#!/bin/bash
## Check if system is based on yum or apt-get
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


## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."

    if [ $sys_type == "yum" ] 
    then
        yum install java-11-openjdk-devel -y -q > /dev/null 2>&1 && export JAVA_HOME="/usr/" -y > /dev/null 2>&1
        if [  "$?" != 0  ]
        then
            yum install java-1.8.0-openjdk-devel -y -q > /dev/null 2>&1 && export JAVA_HOME="/usr/" && yum install unzip wget curl libcap -y -q > /dev/null 2>&1
        else
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
        apt-get install openjdk-11-jdk -y -q > /dev/null 2>&1 && export JAVA_HOME="/usr/" && apt-get install apt-transport-https curl unzip wget libcap2-bin -y -q > /dev/null 2>&1
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

    logger "Done" 
}

## Elasticsearch
installElasticsearch() {
    logger "Installing Opend Distro for Elasticsearch..."

    if [ $sys_type == "yum" ] 
    then
        yum install opendistroforelasticsearch-1.6.0 -y -q > /dev/null 2>&1
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

        if [ -n "$m" ]
        then
            curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/unattended-installation/distributed/templates/elasticsearch.yml --max-time 300 > /dev/null 2>&1
        else
        curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/7.x/elasticsearch_all_in_one.yml --max-time 300 > /dev/null 2>&1
        fi

        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles.yml --max-time 300 > /dev/null 2>&1
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles_mapping.yml --max-time 300 > /dev/null 2>&1
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/internal_users.yml --max-time 300 > /dev/null 2>&1
        rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f > /dev/null 2>&1
    
        # Configure JVM options for Elasticsearch
        ram_gb=$(free -g | awk '/^Mem:/{print $2}')
        ram=$(( ${ram_gb} / 2 ))

        if [ ${ram} -eq "0" ]; then
            ram=1;
        fi    

        conf="$(awk '{sub(/-Xms1g/,"-Xms'${ram}'g")}1' /etc/elasticsearch/jvm.options)"
        echo "$conf" > /etc/elasticsearch/jvm.options
        conf="$(awk '{sub(/-Xmx1g/,"-Xmx'${ram}'g")}1' /etc/elasticsearch/jvm.options)"
        echo "$conf" > /etc/elasticsearch/jvm.options
        logger "Done"        
    fi
}

configureElastic() {

    if [ -n "$m" ]
    then
        conf="$(awk '{sub(/127.0.0.1/,"'$ip'")}1' /etc/elasticsearch/elasticsearch.yml)"
        echo "$conf" > /etc/elasticsearch/elasticsearch.yml
    else
        conf="$(awk '{sub(/<elasticsearch_ip>/,"'$ip'")}1' /etc/elasticsearch/elasticsearch.yml)"
        echo "$conf" > /etc/elasticsearch/elasticsearch.yml
    fi

}

configureKibana() {

    conf="$(awk '{sub(/localhost/,"'$ip'")}1' /etc/kibana/kibana.yml)"
    echo "$conf" > /etc/kibana/kibana.yml
    conf="$(awk '{sub(/0.0.0.0/,"'$kip'")}1' /etc/kibana/kibana.yml)"
    echo "$conf" > /etc/kibana/kibana.yml
}

## Kibana
installKibana() {
    
    logger "Installing Open Distro for Kibana..."

    $sys_type install opendistroforelasticsearch-kibana -y -q > /dev/null 2>&1
    curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/kibana/7.x/kibana_all_in_one.yml --max-time 300 > /dev/null 2>&1
    cd /usr/share/kibana > /dev/null 2>&1
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/trash/app/kibana/wazuhapp-3.13.0-tsc-opendistro.zip > /dev/null 2>&1
    mkdir /etc/kibana/certs > /dev/null 2>&1
    mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/ > /dev/null 2>&1
    setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node > /dev/null 2>&1

    logger "Done"
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
        healthCheck
        installPrerequisites
        addWazuhrepo
    
        while [ -n "$1" ]
        do
            case "$1" in
            "-e"|"--install-elastic")        
                e=1
                installElasticsearch
                shift 1
                ;;
            "-m"|"--multi-node") 
                m=1           
                shift 1
                ;;                   
            "-k"|"--install-kibana") 
                k=1           
                installKibana
                shift 1
                ;;
            "-ip"|"--elasticsearch-ip")        
                ip=$2
                shift
                shift
                ;;
            "-kip"|"--kibana-ip")        
                kip=$2
                shift
                shift
                ;;                         
            *)
                exit 1
            esac
        done
        if [ -n "$e" ] && [ -n "$ip" ]
        then
            configureElastic $ip
        fi
        if [ -n "$k" ] && [ -n "$ip" ] && [ -n "$kip" ]
        then
            configureKibana $ip
        fi         
    else
        helpFunction
    fi
}

main "$@"
