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
        yum install java-11-openjdk-devel unzip wget curl libcap -y -q > /dev/null 2>&1
    elif [ $sys_type == "apt-get" ] 
    then
        if [ -n "$(command -v add-apt-repository)" ]
        then
            add-apt-repository ppa:openjdk-r/ppa -y > /dev/null 2>&1
        else
            echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        fi
        apt-get update -q > /dev/null 2>&1
        apt-get install openjdk-11-jdk apt-transport-https curl unzip wget libcap2-bin -y -q > /dev/null 2>&1
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
        curl -s https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - > /dev/null 2>&1
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

    logger "Done"

    logger "Configuring Elasticsearch..."

    curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/7.x/elasticsearch_all_in_one.yml > /dev/null 2>&1
    curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles.yml > /dev/null 2>&1
    curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles_mapping.yml > /dev/null 2>&1
    curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/internal_users.yml > /dev/null 2>&1
    rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f > /dev/null 2>&1
    
    if [ -n "$master" ] 
    then
        logger "Generating certificates..."
        mkdir /etc/elasticsearch/certs > /dev/null 2>&1
        cd /etc/elasticsearch/certs > /dev/null 2>&1
        wget -q https://releases.floragunn.com/search-guard-tlstool/1.7/search-guard-tlstool-1.7.zip > /dev/null 2>&1
        unzip search-guard-tlstool-1.7.zip -d searchguard > /dev/null 2>&1
        curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/searchguard/search-guard-aio.yml > /dev/null 2>&1
        chmod +x searchguard/tools/sgtlstool.sh > /dev/null 2>&1
        ./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/ > /dev/null 2>&1
        rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.7.zip -f > /dev/null 2>&1
    fi
    
    # Configure JVM options for Elasticsearch
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ${ram_gb} / 2 ))

    if [ ${ram} -eq "0" ]; then
        ram=1;
    fi    
    sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options > /dev/null 2>&1
    sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options > /dev/null 2>&1

    logger "Done"
}

configureElastic() {

    conf="$(awk '{sub(/127.0.0.1/,"'$eip'")}1' /etc/elasticsearch/elasticsearch.yml)"
    echo "$conf" > /etc/elasticsearch/elasticsearch.yml

}

configureKibana() {

    conf="$(awk '{sub(/0.0.0.0/,"'$eip'")}1' /etc/kibana/kibana.yml)"
    echo "$conf" > /etc/kibana/kibana.yml

}

## Kibana
installKibana() {
    
    logger "Installing Open Distro for Kibana..."

    $sys_type install opendistroforelasticsearch-kibana -y -q > /dev/null 2>&1
    curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/kibana/7.x/kibana_all_in_one.yml > /dev/null 2>&1
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
            "-k"|"--install-kibana") 
                k=1           
                installKibana
                shift 1
                ;;
            "-eip"|"--elasticsearch-ip")        
                eip="$2"
                if [ -n "$e" ]
                then
                    configureElastic $eip
                fi
                if [ -n "$k" ]
                then
                    configureKibana $eip
                fi
                shift
                shift
                ;;
            "-m"|"--master-node")        
                master=1
                shift
                ;;
            *)
                exit 1
            esac
        done
    else
        helpFunction
    fi
}

main "$@"
