#!/bin/sh
# preload-vars.sh, Daniel B. Cid (dcid @ ossec.net).
#
# Use this file to customize your installations.
# It will make the install.sh script pre-load some
# specific options to make it run automatically
# or with less questions.

# PLEASE NOTE:
# When we use "no" or "yes" in here, it should be changed
# to "no" or "yes" in the language your are doing the
# installation. For example, in portuguese it would
# be "sim" or "nao".


# USER_LANGUAGE defines to language to be used.
# It can be "en", "br", "tr", "it", "de" or "pl".
# In case of an invalid language, it will default
# to English "en" 
#USER_LANGUAGE="en"     # For english
#USER_LANGUAGE="br"     # For portuguese


# If USER_NO_STOP is set to anything, the confirmation
# messages are not going to be asked.
#USER_NO_STOP="y"


# USER_INSTALL_TYPE defines the installtion type to
# be used during install. It can only be "local",
# "agent" or "server".
#USER_INSTALL_TYPE="local"
#USER_INSTALL_TYPE="agent"
#USER_INSTALL_TYPE="server"


# USER_DIR defines the location to install ossec
#USER_DIR="/var/ossec"


# If USER_DELETE_DIR is set to "y", the directory
# to install OSSEC will be removed if present.
#USER_DELETE_DIR="n"


# If USER_ENABLE_ACTIVE_RESPONSE is set to "no",
# active response will be disabled.
#USER_ENABLE_ACTIVE_RESPONSE="yes"


# If USER_ENABLE_SYSCHECK is set to "yes", 
# syscheck will be enabled. Set to "no" to
# disable it.
#USER_ENABLE_SYSCHECK="yes"


# If USER_ENABLE_ROOTCHECK is set to "yes",
# rootcheck will be enabled. Set to "no" to
# disable it.
#USER_ENABLE_ROOTCHECK="yes"



### Agent Installation variables. ###

# USER_AGENT_SERVER_IP specifies the IP address of the 
# ossec server. Only used on agent installtions.
#USER_AGENT_SERVER_IP="1.2.3.4"



### Server/Local Installation variables. ###

# USER_ENABLE_EMAIL enables or disables email alerting.
#USER_ENABLE_EMAIL="yes"

# USER_EMAIL_ADDRESS defines the destination e-mail of the alerts.
#USER_EMAIL_ADDRESS="dcid@test.ossec.net"

# USER_EMAIL_SMTP defines the SMTP server to send the e-mails.
#USER_EMAIL_SMTP="test.ossec.net"


# USER_ENABLE_SYSLOG enables or disables remote syslog.
#USER_ENABLE_SYSLOG="yes"


# USER_ENABLE_FIREWALL_RESPONSE enables or disables
# the firewall response.
#USER_ENABLE_FIREWALL_RESPONSE="yes"


# USER_WHITE_LIST is a list of IPs or networks
# that are going to be set to never be blocked.
#USER_WHITE_LIST="192.168.2.1 192.168.1.0/24"


#### exit ? ###
