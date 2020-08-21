#!/bin/bash
## Check if system is based on yum or apt-get or zypper
char="#"
debug='> /dev/null 2>&1'
password=""
passwords=""
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
        eval "yum install zip unzip curl libcap -y -q $debug"   
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install zip unzip curl $debug"
        eval "zypper -n install libcap-progs $debug || zypper -n install libcap2 $debug"       
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install curl apt-transport-https zip unzip lsb-release gnupg2 libcap2-bin -y -q $debug"
        eval "apt-get update -q $debug"
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
        echo -e '[elasticsearch-7.x]\nname=Elasticsearch repository for 7.x packages\nbaseurl=https://artifacts.elastic.co/packages/7.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md' > /etc/yum.repos.d/elastic.repo
    elif [ $sys_type == "zypper" ] 
    then
        rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch > /dev/null 2>&1
		cat > /etc/zypp/repos.d/elastic.repo <<- EOF
        [elasticsearch-7.x]
        name=Elasticsearch repository for 7.x packages
        baseurl=https://artifacts.elastic.co/packages/7.x/yum
        gpgcheck=1
        gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
        enabled=1
        autorefresh=1
        type=rpm-md
		EOF
        
    elif [ $sys_type == "apt-get" ] 
    then
        eval "curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch --max-time 300 | apt-key add - $debug"
        echo 'deb https://artifacts.elastic.co/packages/7.x/apt stable main' | eval "tee /etc/apt/sources.list.d/elastic-7.x.list $debug"
        eval "apt-get update -q $debug"
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
    elif [ $sys_type == "zypper" ] 
    then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH > /dev/null 2>&1
		cat > /etc/zypp/repos.d/wazuh_pre.repo <<- EOF
		[wazuh_repo]
		gpgcheck=1
		gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
		enabled=1
		name=Wazuh repository
		baseurl=https://packages.wazuh.com/3.x/yum/
		protect=1
		EOF
    
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

    logger "Installing Elasticsearch..."

    if [ $sys_type == "yum" ] 
    then
        eval "yum install elasticsearch-7.8.1 -y -q $debug"
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install elasticsearch=7.8.1 -y -q $debug"
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install elasticsearch-7.8.1 $debug"
    fi

    if [  "$?" != 0  ]
    then
        echo "Error: Elasticsearch installation failed"
        exit 1;
    else
        logger "Done"

        logger "Configuring Elasticsearch..."

        eval "curl -so /etc/elasticsearch/elasticsearch.yml https://documentation.wazuh.com/resources/elastic-stack/elasticsearch/7.x/elasticsearch_all_in_one.yml --max-time 300 $debug"
        eval "curl -so /usr/share/elasticsearch/instances.yml https://documentation.wazuh.com/resources/elastic-stack/instances_aio.yml --max-time 300 $debug"
        eval "/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip $debug"
        eval "unzip ~/certs.zip -d ~/certs $debug"
        eval "mkdir /etc/elasticsearch/certs/ca -p $debug"
        eval "cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/ $debug"
        eval "chown -R elasticsearch: /etc/elasticsearch/certs $debug"
        eval "chmod -R 500 /etc/elasticsearch/certs $debug"
        eval "chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.* $debug"
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

        # Start Elasticsearch
        startService "elasticsearch"
        echo "Initializing Elasticsearch...(this may take a while)"
        until grep '\Security is enabled' /var/log/elasticsearch/elasticsearch.log > /dev/null
        do
            echo -ne $char
            sleep 10
        done
        echo $'\nGenerating passwords...'
        passwords=$(/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto -b)
        password=$(echo $passwords | awk 'NF{print $NF; exit}')
        until $(curl -XGET https://localhost:9200/ -elastic:"$password" -k --max-time 120 --silent --output /dev/null); do
            echo -ne $char
            sleep 10
        done

        echo "Done"
    fi

}

## Filebeat
installFilebeat() {
    
    logger "Installing Filebeat..."
    if [ $sys_type == "yum" ] 
    then
        eval "yum install filebeat-7.8.1 -y -q  $debug"    
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install filebeat-7.8.1 $debug"
    elif [ $sys_type == "apt" ] 
    then
        eval "apt-get install filebeat=7.8.1 -y -q  $debug"
    fi
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat installation failed"
        exit 1;
    else
        eval "curl -so /etc/filebeat/filebeat.yml https://documentation.wazuh.com/resources/elastic-stack/filebeat/7.x/filebeat_all_in_one.yml --max-time 300  $debug"
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
    
    logger "Installing Kibana..."
    if [ $sys_type == "yum" ] 
    then
        eval "yum install kibana-7.8.1 -y -q  $debug"    
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install kibana-7.8.1 $debug"
    elif [ $sys_type == "apt" ] 
    then
        eval "apt-get install kibana=7.8.1 -y -q  $debug"
    fi
    if [  "$?" != 0  ]
    then
        echo "Error: Kibana installation failed"
        exit 1;
    else   
        eval "curl -so /etc/kibana/kibana.yml https://documentation.wazuh.com/resources/elastic-stack/kibana/7.x/kibana_all_in_one.yml --max-time 300 $debug"
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
    eval "curl -XGET https://localhost:9200 -elastic:"$password" -k --max-time 300 $debug"
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
    until [[ "$(curl -XGET https://localhost/status -I -uelastic:"$password" -k -s | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done    
    echo $'\nDuring the installation of Elasticsearch the passwords for its user were generated. Please take note of them:'
    echo "$passwords"
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
        checkInstallation password
    fi 

}

main "$@"
