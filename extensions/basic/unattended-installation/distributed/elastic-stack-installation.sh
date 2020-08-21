#!/bin/bash
## Check if system is based on yum or apt-get
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
   echo -e "\t-e     | --install-elasticsearch Installs Open Distro for Elasticsearch (cannot be used together with option -k)"
   echo -e "\t-k     | --install-kibana Installs Open Distro for Kibana (cannot be used together with option -e)"
   echo -e "\t-kip   | --kibana-ip indicates the IP of Kibana. It can be set to 0.0.0.0 which will bind all the availables IPs"
   echo -e "\t-eip   | --elasticsearch-ip Indicates the IP of Elasticsearch. It can be set to 0.0.0.0 which will bind all the availables IPs"
   echo -e "\t-wip   | --wazuh-ip Indicates the IP of Wazuh."
   echo -e "\t-c     | --create-certificates Generates the certificates for all the indicated nodes"
   echo -e "\t-k     | --install-kibana Install Kibana"
   echo -e "\t-p     | --elastic-password Elastic user password"
   echo -e "\t-d     | --debug Shows the complete installation output"
   echo -e "\t-i     | --ignore-health-check Ignores the health-check"
   echo -e "\t-h     | --help Shows help"
   exit 1 # Exit script after printing help

}


## Install the required packages for the installation
installPrerequisites() {

    logger "Installing all necessary utilities for the installation..."

    if [ $sys_type == "yum" ] 
    then
        eval "yum install zip unzip curl -y -q $debug"   
    elif [ $sys_type == "zypper" ] 
    then
        eval "zypper -n install zip unzip curl $debug"       
    elif [ $sys_type == "apt-get" ] 
    then
        eval "apt-get install curl apt-transport-https zip unzip lsb-release libcap2-bin -y -q $debug"
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
        eval "curl -so /etc/elasticsearch/elasticsearch.yml https://documentation.wazuh.com/resources/elastic-stack/unattended-installation/distributed/templates/elasticsearch_unattended.yml --max-time 300 $debug"

        awk -v RS='' '/## Elasticsearch/' ~/config.yml >> /etc/elasticsearch/elasticsearch.yml    
        
        # Configure JVM options for Elasticsearch
        ram_gb=$(free -g | awk '/^Mem:/{print $2}')
        ram=$(( ${ram_gb} / 2 ))

        if [ ${ram} -eq "0" ]; then
            ram=1;
        fi    
        eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options $debug"
        eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options $debug"     

        # Create certificates
        if [ -n "$single" ]
        then
            createCertificates
        else
            logger "Done"
        fi      

        echo "Done"
    fi

}

createCertificates() {
  
    awk -v RS='' '/## Certificates/' ~/config.yml > /usr/share/elasticsearch/instances.yml
    eval "/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip $debug"
    if [  "$?" != 0  ]
    then
        echo "Error: certificates were no created"
        exit 1;
    else
        logger "Certificates created"
        eval "unzip ~/certs.zip -d ~/certs $debug"
        eval "mkdir /etc/elasticsearch/certs/ca -p $debug"
        eval "cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/ $debug"
        if [[ -n "$master" ]] 
        then
            eval "mv ~/certs/elasticsearch/elasticsearch.crt /etc/elasticsearch/certs/elasticsearch.crt $debug"
            eval "mv ~/certs/elasticsearch/elasticsearch.key /etc/elasticsearch/certs/elasticsearch.key $debug"
        fi
        eval "chown -R elasticsearch: /etc/elasticsearch/certs $debug"
        eval "chmod -R 500 /etc/elasticsearch/certs $debug"
        eval "chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.* $debug"
    fi

    logger "Elasticsearch installed."  

    # Start Elasticsearch
    startService "elasticsearch"
    if [[ -n "$single" ]] || [[ -n "$c" ]]
    then
        echo "Initializing Elasticsearch...(this may take a while)"
        until grep '\Security is enabled' /var/log/elasticsearch/elasticsearch.log > /dev/null
        do
            echo -ne $char
            sleep 10
        done
        echo $'\nGenerating passwords...'
        passwords=$(/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto -b)
        password=$(echo $passwords | awk 'NF{print $NF; exit}')
        elk=$(awk -F'network.host: ' '{print $2}' ~/config.yml | xargs)
        until $(curl -XGET https://${elk}:9200/ -elastic:"$password" -k --max-time 120 --silent --output /dev/null); do
            echo -ne $char
            sleep 10
        done

        logger "Done"
        echo $'\nDuring the installation of Elasticsearch the passwords for its user were generated. Please take note of them:'
        echo "$passwords"
    fi
    echo $'\nElasticsearch installation finished'
    exit 0;    

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
        eval "curl -so /etc/kibana/kibana.yml https://documentation.wazuh.com/resources/elastic-stack/unattended-installation/distributed/templates/kibana_unattended.yml --max-time 300 $debug"
        eval "cd /usr/share/kibana $debug"
        eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/trash/ui/kibana/wazuhapp-4.0.0_7.8.0_0.0.0.todelete.zip $debug"
        if [  "$?" != 0  ]
        then
            echo "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi     
        eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node $debug"
        conf="$(awk '{sub("<elasticsearch_password>", "'"${epassword}"'")}1' /etc/kibana/kibana.yml)"
        echo "$conf" > /etc/kibana/kibana.yml     
        eval "mkdir /etc/kibana/certs/ca -p"
        echo "server.host: "$kip"" >> /etc/kibana/kibana.yml
        echo "elasticsearch.hosts: https://"$eip":9200" >> /etc/kibana/kibana.yml
        logger "Kibana installed."
        
        checkKibanacerts kc
        if [[ "$kc" -eq "0" ]] && [[ -n "$single" ]]
        then
            exit
        else
            initializeKibana password
        fi
        echo -e            

        logger "Done"
    fi

}

checkKibanacerts() {

    if [ -f "/etc/elasticsearch/certs/elasticsearch.key" ]
    then
        kc=1
    else
        kc=0
    fi

}

initializeKibana() {
    
    eval "cp -R /etc/elasticsearch/certs/ca/ /etc/kibana/certs/"
    eval "cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key"
    eval "cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt"
    eval "chown -R kibana:kibana /etc/kibana/"
    eval "chmod -R 500 /etc/kibana/certs"
    eval "chmod 440 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*"    
    # Start Kibana
    startService "kibana"   
    logger "Initializing Kibana (this may take a while)" 
    until [[ "$(curl -XGET https://${eip}/status -I -uelastic:"$epassword" -k -s | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done   
    sleep 10  
    conf="$(awk '{sub("url: https://localhost", "url: https://'"${wip}"'")}1' /usr/share/kibana/optimize/wazuh/config/wazuh.yml)"
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
            "-kip"|"--kibana-ip") 
                kip=$2          
                shift
                shift
                ;;   
            "-eip"|"--elasticsearch-ip") 
                eip=$2          
                shift
                shift
                ;;   
            "-wip"|"--wazuh-ip") 
                wip=$2          
                shift
                shift
                ;;  
            "-p"|"--elastic-password") 
                epassword=$2          
                shift
                shift
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

        if [ -n "$e" ]
        then
            if [[ -n "$e" ]] && [[ -n "$k" ]]   
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
            addElasticrepo   
            checkNodes         
            installElasticsearch
            if [ -n "$c" ]
            then
                createCertificates
            fi
        fi
        if [ -n "$k" ]
        then
            if [[ -z "$kip" ]] || [[ -z "$eip" ]] || [[ -z "$wip" ]] || [[ -z "$epassword" ]]
            then
                getHelp
            fi
            if [[ -n "$e" ]] && [[ -n "$k" ]]   
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
            addElasticrepo             
            installKibana
        fi
    else
        getHelp
    fi

}

main "$@"
