#!/bin/sh
# Shell script update functions for the OSSEC HIDS
# Author: Daniel B. Cid <daniel.cid@gmail.com>

FALSE="false"
TRUE="true"

isUpdate()
{
    ls -la ${OSSEC_INIT} > /dev/null 2>&1
    if [ $? = 0 ]; then
        . ${OSSEC_INIT}
        if [ "X$DIRECTORY" = "X" ]; then
            echo "# ($FUNCNAME) ERROR: The variable DIRECTORY wasn't set" 1>&2
            echo "${FALSE}"
            return 1;
        fi
        ls -la $DIRECTORY > /dev/null 2>&1
        if [ $? = 0 ]; then
            echo "${TRUE}"
            return 0;
        fi
    fi
    echo "${FALSE}"
    return 1;
}

doUpdatecleanup()
{
    . ${OSSEC_INIT}

    if [ "X$DIRECTORY" = "X" ]; then
        echo "# ($FUNCNAME) ERROR: The variable DIRECTORY wasn't set." 1>&2
        echo "${FALSE}"
        return 1;
    fi

    # Checking if the directory is valid.
    _dir_pattern_update="^/[-a-zA-Z0-9/\.-]{3,128}$"
    echo $DIRECTORY | grep -E "$_dir_pattern_update" > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "# ($FUNCNAME) ERROR: directory name ($DIRECTORY) doesn't match the pattern $_dir_pattern_update" 1>&2
        echo "${FALSE}"
        return 1;
    fi
}

getPreinstalled()
{
    . ${OSSEC_INIT}

    # agent
    cat $DIRECTORY/etc/ossec.conf | grep "<client>" > /dev/null 2>&1
    if [ $? = 0 ]; then
        echo "agent"
        return 0;
    fi

    cat $DIRECTORY/etc/ossec.conf | grep "<remote>" > /dev/null 2>&1
    if [ $? = 0 ]; then
        echo "server"
        return 0;
    fi

    echo "local"
    return 0;
}

getPreinstalledDir()
{
    . ${OSSEC_INIT}
    echo "$DIRECTORY"
    return 0;
}

UpdateStartOSSEC()
{
   . ${OSSEC_INIT}

   $DIRECTORY/bin/ossec-control start
}

UpdateStopOSSEC()
{
   . ${OSSEC_INIT}

   $DIRECTORY/bin/ossec-control stop

   # We also need to remove all syscheck queue file (format changed)
   if [ "X$VERSION" = "X0.9-3" ]; then
        rm -f $DIRECTORY/queue/syscheck/* > /dev/null 2>&1
        rm -f $DIRECTORY/queue/agent-info/* > /dev/null 2>&1
   fi
   rm -f $DIRECTORY/queue/syscheck/.* > /dev/null 2>&1
}

UpdateOSSECRules()
{
    . ${OSSEC_INIT}

    OSSEC_CONF_FILE="$DIRECTORY/etc/ossec.conf"

    # Backing up the old config
    cp -pr ${OSSEC_CONF_FILE} "${OSSEC_CONF_FILE}.$$.bak"

    # Getting rid of old rules entries
    grep -Ev "</*rules>|<include>|<list>|<decoder>|<decoder_dir|<rule_dir>|rules global entry" ${OSSEC_CONF_FILE} > "${OSSEC_CONF_FILE}.$$.tmp"

    # Customer decoder, decoder_dir, rule_dir are carried over during upgrade
    grep -E '<decoder>|<decoder_dir|<rule_dir>' ${OSSEC_CONF_FILE} | grep -v '<!--' >> "${OSSEC_CONF_FILE}.$$.tmp2"

    # Check for custom files that may have been added in <rules> element
    for i in `grep -E '<include>|<list>' ${OSSEC_CONF_FILE} | grep -v '<!--'`
    do
      grep "$i" ${RULES_TEMPLATE}>/dev/null || echo "    $i" >> "${OSSEC_CONF_FILE}.$$.tmp2"
    done

    # Putting everything back together
    cat "${OSSEC_CONF_FILE}.$$.tmp" > ${OSSEC_CONF_FILE}
    rm "${OSSEC_CONF_FILE}.$$.tmp"
    echo "" >> ${OSSEC_CONF_FILE}
    echo "<ossec_config>  <!-- rules global entry -->" >> ${OSSEC_CONF_FILE}
    grep -v '</rules>' ${RULES_TEMPLATE} >> ${OSSEC_CONF_FILE}
    cat "${OSSEC_CONF_FILE}.$$.tmp2" >> ${OSSEC_CONF_FILE}
    echo "</rules>" >> ${OSSEC_CONF_FILE}
    echo "</ossec_config>  <!-- rules global entry -->" >> ${OSSEC_CONF_FILE}
    rm "${OSSEC_CONF_FILE}.$$.tmp2"
}

