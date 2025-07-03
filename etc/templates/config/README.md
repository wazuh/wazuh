# Templates



## Manager 'ossec.conf' file


    header-comments.template

    <ossec_config>
        global.template

        logging.template

        remote-secure.template

        [remote-syslog.template]

        rootcheck.template

        wodle-openscap.template

        wodle-syscollector.template

        syscheck.template

        global-ar.template

        ar-commands.template

        ar-definitions.template

        localfile-logs*

        localfile-commands.template

        localfile-extra.template

        rules.template
    </ossec_config>

## Agent 'ossec.conf' file

    header-comments.template

    <ossec_config>
        <client>
          <server>
            <address>192.168.10.100</address>
          </server>
          <config-profile>distribution, distributionVersion</config-profile>
        </client>
        <client_buffer>
          <!-- Agent buffer options -->
          <disabled>no</disabled>
          <queue_size>5000</queue_size>
          <events_per_second>500</events_per_second>
        </client_buffer>

        logging.template

        rootcheck.template

        wodle-openscap.template

        wodle-syscollector.template

        syscheck.template

        localfile-logs*

        localfile-commands.template

        localfile-extra.template

        <active-response>
          <disabled>no</disabled>
        </active-response>
    </ossec_config>

## Search template
The script looks for the appropriate template depending on the version indicated or detected. If you specify a distribution and its version, the script will initially look for the template of that version, and in case of not finding it, it will go through the folder tree until it reaches the generic version.

Example:
    _GetTemplate "syscheck.manager.template" "centos" "7"_

        1º centos/7/syscheck.manager.template
        2º centos/7/syscheck.template
        3º centos/syscheck.template
        4º generic/syscheck.template
