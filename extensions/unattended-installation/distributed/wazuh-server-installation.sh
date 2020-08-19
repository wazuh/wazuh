#!/bin/bash
## Check if system is based on yum or apt-get
ips=()
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

## Show script usage
getHelp() {
   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-i    | --ignore-healthcheck Ignores the healthcheck"
   echo -e "\t-ip   | --elasticsearch-ip <elasticsearch-ip> Indicates the IP of Elasticsearch. Can be added as many as necessary"
   echo -e "\t-d   | --debug Shows the complete installation output"
   echo -e "\t-h    | --help Shows help"
   exit 1 # Exit script after printing help
}

## Install the required packages for the installation
installPrerequisites() {

    logger "Installing all necessary utilities for the installation..."

    if [ $sys_type == "yum" ] 
    then
        eval "yum install curl -y -q $debug"
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install curl $debug"        
    elif [ $sys_type == "apt-get" ] 
    then
        if [ -n "$(command -v add-apt-repository)" ]
        then
            eval "add-apt-repository ppa:openjdk-r/ppa -y $debug"
        else
            echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        fi
        eval "apt-get update -q $debug"
        eval "apt-get install apt-transport-https curl -y -q $debug"
    fi

    logger "Done"

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
        eval "curl -so /etc/filebeat/filebeat.yml https://documentation.wazuh.com/resources/open-distro/unattended-installation/distributed/templates/filebeat.yml --max-time 300 $debug"
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.13.1/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 $debug"
        eval "chmod go+r /etc/filebeat/wazuh-template.json $debug"
        eval "curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module $debug"
        mkdir /etc/filebeat/certs

        logger "Done"
    fi        
}

configureFilebeat() {
    
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    for i in "${!ips[@]}"; do
        echo "  - ${ips[i]}:9200" >> /etc/filebeat/filebeat.yml
    done
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
        if [ -z "$ips" ]
        then
            getHelp
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
        installFilebeat           
        configureFilebeat $ips
    else
        getHelp
    fi
}

main "$@"
