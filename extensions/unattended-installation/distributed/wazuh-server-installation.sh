#!/bin/bash
## Check if system is based on yum or apt-get
ips=()
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

## Show script usage
getHelp() {
   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-i    | --ignore-healthcheck Ignores the healthcheck"
   echo -e "\t-ip   | --elasticsearch-ip <elasticsearch-ip> Indicates the IP of Elasticsearch. Can be added as many as necessary"
   echo -e "\t-h    | --help Shows help"
   exit 1 # Exit script after printing help
}

## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."

    if [ $sys_type == "yum" ] 
    then
        yum install curl -y -q > /dev/null 2>&1
    elif [ $sys_type == "apt-get" ] 
    then
        if [ -n "$(command -v add-apt-repository)" ]
        then
            add-apt-repository ppa:openjdk-r/ppa -y > /dev/null 2>&1
        else
            echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        fi
        apt-get update -q > /dev/null 2>&1
        apt-get install apt-transport-https curl -y -q > /dev/null 2>&1
    fi

    logger "Done"
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

    logger "Done"
}

## Filebeat
installFilebeat() {
    
    logger "Installing Filebeat..."

    $sys_type install filebeat -y -q  > /dev/null 2>&1
    curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/unattended-installation/distributed/templates/filebeat.yml --max-time 300 > /dev/null 2>&1
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.12.0/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 > /dev/null 2>&1
    chmod go+r /etc/filebeat/wazuh-template.json > /dev/null 2>&1
    curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module > /dev/null 2>&1
    mkdir /etc/filebeat/certs

    logger "Done"
}

configureFilebeat() {
    
    #conf="$(awk '{sub(/127.0.0.1/,"'$ip'")}1' /etc/filebeat/filebeat.yml)"
    #echo "$conf" > /etc/filebeat/filebeat.yml
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    for i in "${!ips[@]}"; do
        echo "  - ${ips[i]}:9200" >> /etc/filebeat/filebeat.yml
    done
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
            "-i"|"--ignore-healthcheck")        
                i=1
                shift
                ;;            
            "-ip"|"--elasticsearch-ip")        
                ips+=($2)
                shift
                shift
                ;;
            "-h"|"--help")        
                getHelp
                ;;                
            *)
                exit 1
            esac
        done

        if [ -n "$i" ]
        then
            echo "Health-check ignored."

        else
            healthCheck
        fi
        installPrerequisites
        addWazuhrepo
        installWazuh
        installFilebeat           
        configureFilebeat $ips
    else
        getHelp
    fi
}

main "$@"
