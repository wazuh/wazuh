#!/bin/bash
## Check if system is based on YUM or APT

if [ -n "$(command -v yum)" ] 
then
    sys_type="YUM"
elif [ -n "$(command -v apt-get)" ] 
then
    sys_type="APT"
fi


## Prerequisites
if [ $sys_type == "YUM" ] 
then
    yum install java-11-openjdk-devel unzip wget curl libcap -y
elif [ $sys_type == "APT" ] 
then
    echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
    add-apt-repository ppa:openjdk-r/ppa -y
    apt update
    apt install openjdk-11-jdk apt-transport-https curl unzip wget libcap2-bin -y
fi

## Wazuh manager and API
if [ $sys_type == "YUM" ] 
then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    echo -e '[wazuh_trash]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/trash/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_pre.repo
    yum install wazuh-manager -y 
    curl -sL https://rpm.nodesource.com/setup_10.x | bash -
    yum install nodejs wazuh-api -y
elif [ $sys_type == "APT" ] 
then
    curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/trash/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_trash.list
    apt-get update
    apt-get install wazuh-manager -y
    curl -sL https://deb.nodesource.com/setup_10.x | bash -
    apt-get install nodejs wazuh-api -y
fi 

## Elasticsearch
if [ $sys_type == "YUM" ] 
then
    yum install opendistroforelasticsearch-1.6.0 -y
elif [ $sys_type == "APT" ] 
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

if [ $sys_type == "YUM" ] 
then
    chkconfig --add elasticsearch
    service elasticsearch start
elif [ $sys_type == "APT" ] 
then
    update-rc.d elasticsearch defaults 95 10
    service elasticsearch start
fi

cd /usr/share/elasticsearch/plugins/opendistro_security/tools/
./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key


## Filebeat
if [ $sys_type == "YUM" ] 
then
    yum install filebeat -y
elif [ $sys_type == "APT" ] 
then
    apt-get install filebeat -y
fi

curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/filebeat/7.x/filebeat_all_in_one.yml
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.12.0/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
mkdir /etc/filebeat/certs
cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/
mv /etc/elasticsearch/certs/filebeat* /etc/filebeat/certs/
if [ $sys_type == "YUM" ] 
then
    chkconfig --add filebeat
    service filebeat start
elif [ $sys_type == "APT" ] 
then
    update-rc.d filebeat defaults 95 10
    service filebeat start
fi


## Kibana
if [ $sys_type == "YUM" ] 
then
    yum install opendistroforelasticsearch-kibana -y 
elif [ $sys_type == "APT" ] 
then
    apt-get install opendistroforelasticsearch-kibana -y
fi

curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/kibana/7.x/kibana_all_in_one.yml
cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/trash/app/kibana/wazuhapp-3.13.0-tsc-opendistro.zip
mkdir /etc/kibana/certs
mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/
setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
if [ -n "$(command -v yum)" ] 
then
    chkconfig --add kibana
    service kibana start
elif [ $sys_type == "APT" ] 
then
    update-rc.d kibana defaults 95 10
    service kibana start
fi

curl -XGET https://localhost:9200 -uadmin:admin -k
filebeat test output