#!/bin/bash
## Check if system is based on yum or apt-get or zypper
char="#"
debug='> /dev/null 2>&1'
password=""
passwords=""
if [ -n "$(command -v yum)" ] 
then
    sys_type="yum"
elif [ -n "$(command -v apt-get)" ] 
then
    sys_type="apt-get"
elif [ -n "$(command -v zypper)" ] 
then
    sys_type="zypper"    
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
        eval "yum install zip unzip curl -y -q $debug"   
        echo -e '[AdoptOpenJDK] \nname=AdoptOpenJDK \nbaseurl=http://adoptopenjdk.jfrog.io/adoptopenjdk/rpm/centos/$releasever/$basearch\nenabled=1\ngpgcheck=1\ngpgkey=https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public' | eval "tee /etc/yum.repos.d/adoptopenjdk.repo $debug"
        eval "yum install adoptopenjdk-11-hotspot -y -q $debug"
        export JAVA_HOME=/usr/   
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install curl apt-transport-https zip unzip lsb-release gnupg2 curl -y -q $debug"
        eval "wget -qO - https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | sudo apt-key add - $debug"
        eval "add-apt-repository --yes https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/ $debug"
        eval "apt-get update -q $debug"
        eval "apt-get install adoptopenjdk-11-hotspot -y -q $debug" 
        export JAVA_HOME=/usr/ 
        elif [ $sys_type == "zypper" ] 
    then
        eval "zypper install zip unzip curl -y -q $debug"   
        eval "zypper ar -f http://adoptopenjdk.jfrog.io/adoptopenjdk/rpm/opensuse/15.0/$(uname -m) adoptopenjdk $debug"
        eval "zypper install adoptopenjdk-11-hotspot -y -q $debug"
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

## Add the Elastic repository
addElasticrepo() {
    logger "Adding the Elasticsearch repository..."

    if [ $sys_type == "yum" ] 
    then
        eval "rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch $debug"
        echo -e '[elasticsearch-7.x]\nname=Elasticsearch repository for 7.x packages\nbaseurl=https://artifacts.elastic.co/packages/7.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md' | eval "tee /etc/yum.repos.d/elastic.repo $debug"
    elif [ $sys_type == "apt-get" ] 
    then
        eval "curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch --max-time 300 | apt-key add - $debug"
        eval "echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list $debug"
        eval "apt-get update -q $debug"
    elif [ $sys_type == "zypper" ] 
    then
        eval "rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch $debug"
        echo -e "[elasticsearch-7.x]\nname=Elasticsearch repository for 7.x packages\nbaseurl=https://artifacts.elastic.co/packages/7.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" | eval "tee /etc/yum.repos.d/elastic.repo $debug"
    fi    

    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch repository could not be added"
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

    if [  "$?" != 0  ]
    then
        echo "Error: Wazuh repository could not be added"
        exit 1;
    else
        logger "Done"
    fi        
}

## Wazuh manager
installWazuh() {
    logger "Installing the Wazuh manager..."

    eval "$sys_type install wazuh-manager -y -q $debug"
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
    logger "Installing Elasticsearch..."

    if [ $sys_type == "yum" ] 
    then
        eval "yum install elasticsearch -y -q $debug"
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install elasticsearch -y -q $debug"
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper install elasticsearch -y -q $debug"        
    fi

    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch installation failed"
        exit 1;
    else
        logger "Done"

        logger "Configuring Elasticsearch..."

        eval "curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/basic/elasticsearch/elasticsearch_all_in_one.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/instances.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/basic/instances_aio.yml $debug"
        eval "/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip $debug"
        eval "unzip ~/certs.zip -d ~/certs $debug"
        eval "mkdir /etc/elasticsearch/certs/ca -p $debug"
        eval "cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/ $debug"
        eval "chown -R elasticsearch: /etc/elasticsearch/certs $debug"
        eval "chmod -R 500 /etc/elasticsearch/certs $debug"
        eval "chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.* $debug"
        eval "rm -rf ~/certs/ ~/certs.zip -f $debug"
        if [  "$?" != 0  ]
        then
            echo "Error: certificates were not created"
            exit 1;
        else
            logger "Certificates created"
        fi     
        
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
        passwords=$(/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto -b)
        password=$(echo $passwords | awk 'NF{print $NF; exit}')
        until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
            echo -ne $char
            sleep 10
        done

        echo "Done"
    fi
}

## Filebeat
installFilebeat() {
    
    logger "Installing Filebeat..."

    eval "$sys_type install filebeat -y -q  $debug"
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat installation failed"
        exit 1;
    else
        eval "curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/basic/filebeat/filebeat_all_in_one.yml --max-time 300  $debug"
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.13.1/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 $debug"
        eval "chmod go+r /etc/filebeat/wazuh-template.json $debug"
        eval "curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module $debug"
        eval "mkdir /etc/filebeat/certs $debug"
        eval "cp -r /etc/elasticsearch/certs/ca/ /etc/filebeat/certs/ $debug"
        eval "cp /etc/elasticsearch/certs/elasticsearch.crt /etc/filebeat/certs/filebeat.crt $debug"
        eval "cp /etc/elasticsearch/certs/elasticsearch.key /etc/filebeat/certs/filebeat.key $debug"
        conf="$(awk '{sub("<elasticsearch_password>", "'"${password}"'")}1' /etc/filebeat/filebeat.yml)"
        echo "$conf" > /etc/filebeat/filebeat.yml  
        # Start Filebeat
        startService "filebeat"

        logger "Done"
    fi
}

## Kibana
installKibana() {
    
    logger "Installing Open Distro for Kibana..."

    eval "$sys_type install kibana -y -q $debug"
    if [  "$?" != 0  ]
    then
        echo "Error: Kibana installation failed"
        exit 1;
    else   
        eval "curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh/new-documentation-templates/extensions/basic/kibana/kibana_all_in_one.yml --max-time 300 $debug"
        eval "cd /usr/share/kibana $debug"
        eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/trash/app/kibana/wazuhapp-4.0.0_7.8.1.zip $debug"
        if [  "$?" != 0  ]
        then
            echo "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi     
        eval "mkdir /etc/kibana/certs/ca -p"
        eval "cp -R /etc/elasticsearch/certs/ca/ /etc/kibana/certs/"
        eval "cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key"
        eval "cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt"
        eval "chown -R kibana:kibana /etc/kibana/"
        eval "chmod -R 500 /etc/kibana/certs"
        eval "chmod 440 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*"
        eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node $debug"
        conf="$(awk '{sub("<elasticsearch_password>", "'"${password}"'")}1' /etc/kibana/kibana.yml)"
        echo "$conf" > /etc/kibana/kibana.yml         

        # Start Kibana
        startService "kibana"

        logger "Done"
    fi
}

## Health check
healthCheck() {
    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')

    if [[ $cores < "2" ]] || [[ $ram_gb < "4096" ]]
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
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:admin -k -s | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done    
    echo $'\nDuring the installation of Elasticsearch the passwords for its user were generated. Please take note of them:'
    echo $passwords
    echo $'\nInstallation finished'
    exit 1;
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
        addElasticrepo
        addWazuhrepo
        installWazuh
        installElasticsearch
        installFilebeat password
        installKibana password
        checkInstallation    
    else
        healthCheck   
        installPrerequisites
        addElasticrepo
        addWazuhrepo
        installWazuh
        installElasticsearch
        installFilebeat password
        installKibana password
        checkInstallation  
    fi 
}

main "$@"
