#!/bin/bash
## Check if system is based on yum or apt-get

if [ -n "$(command -v yum)" ] 
then
    sys_type="yum"
elif [ -n "$(command -v apt-get)" ] 
then
    sys_type="apt-get"
fi


## Install the required packages for the installation
installPrerequisites() {
    if [ $sys_type == "yum" ] 
    then
        yum install java-11-openjdk-devel unzip wget curl libcap -y
    elif [ $sys_type == "apt-get" ] 
    then
        echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
        add-apt-repository ppa:openjdk-r/ppa -y
        apt update
        apt install openjdk-11-jdk apt-transport-https curl unzip wget libcap2-bin -y
    fi
}


## Wazuh manager and API
installWazuh() {
    if [ $sys_type == "yum" ] 
    then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        echo -e '[wazuh_trash]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/trash/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_pre.repo
        curl -sL https://rpm.nodesource.com/setup_10.x | bash -
    elif [ $sys_type == "apt-get" ] 
    then
        curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/trash/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_trash.list
        apt-get update
        curl -sL https://deb.nodesource.com/setup_10.x | bash -
    fi 
    $sys_type install wazuh-manager nodejs wazuh-api -y    
}

## Elasticsearch
installElasticsearch() {
    if [ $sys_type == "yum" ] 
    then
        yum install opendistroforelasticsearch-1.6.0 -y
    elif [ $sys_type == "apt-get" ] 
    then
        apt install elasticsearch-oss opendistroforelasticsearch -y
    fi

    curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/7.x/elasticsearch_all_in_one.yml
    curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles.yml
    curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/roles_mapping.yml
    curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/elasticsearch/roles/internal_users.yml
    rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f
    mkdir /etc/elasticsearch/certs
    cd /etc/elasticsearch/certs
    wget https://releases.floragunn.com/search-guard-tlstool/1.7/search-guard-tlstool-1.7.zip
    unzip search-guard-tlstool-1.7.zip -d searchguard
    curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/searchguard/search-guard-aio.yml
    chmod +x searchguard/tools/sgtlstool.sh
    ./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/
    rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.7.zip -f

    systemctl daemon-reload
    systemctl enable elasticsearch.service
    systemctl start elasticsearch.service

    cd /usr/share/elasticsearch/plugins/opendistro_security/tools/
    ./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key
}

## Filebeat
installFilebeat() {
    $sys_type install filebeat -y
    curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/filebeat/7.x/filebeat_all_in_one.yml
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.12.0/extensions/elasticsearch/7.x/wazuh-template.json
    chmod go+r /etc/filebeat/wazuh-template.json
    curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
    mkdir /etc/filebeat/certs
    cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/
    mv /etc/elasticsearch/certs/filebeat* /etc/filebeat/certs/

    systemctl daemon-reload
    systemctl enable filebeat.service
    systemctl start filebeat.service
}

## Kibana
installKibana() {
    $sys_type install opendistroforelasticsearch-kibana -y
    curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/kibana/7.x/kibana_all_in_one.yml
    cd /usr/share/kibana
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/trash/app/kibana/wazuhapp-3.13.0-tsc-opendistro.zip
    mkdir /etc/kibana/certs
    mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/
    setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node

    systemctl daemon-reload
    systemctl enable kibana.service
    systemctl start kibana.service
}

checkInstallation() {
    curl -XGET https://localhost:9200 -uadmin:admin -k
    filebeat test output
}

main() {
    installPrerequisites
    installWazuh
    installElasticsearch
    installFilebeat
    installKibana
    checkInstallation
}

main
