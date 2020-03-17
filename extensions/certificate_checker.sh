#!/bin/bash

# Elasticsearch definitions
elasticsearch_config_folder="/etc/elasticsearch"
elasticsearch_config_file="elasticsearch.yml"

elasticsearch_settings=( "xpack.security.transport.ssl.key" 
                         "xpack.security.transport.ssl.certificate"
                         "xpack.security.transport.ssl.certificate_authorities"
                         "xpack.security.http.ssl.key"
                         "xpack.security.http.ssl.certificate"
                         "xpack.security.http.ssl.certificate_authorities"
                         )
# ------------------

# Filebeat definitions
filebeat_config_folder="/etc/filebeat" 
filebeat_config_file="filebeat.yml" 


filebeat_settings=( "output.elasticsearch.ssl.certificate" 
                               "output.elasticsearch.ssl.key"
                               "output.elasticsearch.ssl.certificate_authorities"
                               )
# ------------------

# Kibana definitions
kibana_config_folder="/etc/kibana"
kibana_config_file="kibana.yml"

kibana_settings=( "elasticsearch.ssl.certificateAuthorities" 
                             "elasticsearch.ssl.certificate"
                             "elasticsearch.ssl.key"
                             "server.ssl.certificate"
                             "server.ssl.key"
                             )
# ------------------

get_setting_path(){

    echo "$(cat $2 | grep $1: | cut -d ':' -f2 | tr -d \'\"\[\])"

}

# Check for Elasticsearch configuration file
if [ -f "${elasticsearch_config_folder}/${elasticsearch_config_file}" ]; then

    for i in "${elasticsearch_settings[@]}"
    do
        if [ ! -f $(get_setting_path "$i" "${elasticsearch_config_folder}/${elasticsearch_config_file}") ]; then
            echo "The path: $(get_setting_path "$i" "${elasticsearch_config_folder}/${elasticsearch_config_file}") does not exist"
            exit 1
        fi
    done

    echo "Paths in ${elasticsearch_config_folder}/${elasticsearch_config_file} validated."

fi

# Check for Filebeat configuration file
if [ -f "${filebeat_config_folder}/${filebeat_config_file}" ]; then

    for i in "${filebeat_settings[@]}"
    do
        if [ ! -f $(get_setting_path "$i" "${filebeat_config_folder}/${filebeat_config_file}") ]; then
            echo "The path: $(get_setting_path "$i" "${filebeat_config_folder}/${filebeat_config_file}") does not exist"
            exit 1
        fi
    done

    echo "Paths in ${filebeat_config_folder}/${filebeat_config_file} validated."

fi

# Check for Kibana configuration file
if [ -f "${kibana_config_folder}/${kibana_config_file}" ]; then

    for i in "${kibana_settings[@]}"
    do
        if [ ! -f $(get_setting_path "$i" "${kibana_config_folder}/${kibana_config_file}") ]; then
            echo "The path: $(get_setting_path "$i" "${kibana_config_folder}/${kibana_config_file}") does not exist"
            exit 1
        fi
    done

    echo "Paths in ${kibana_config_folder}/${kibana_config_file} validated."

fi
