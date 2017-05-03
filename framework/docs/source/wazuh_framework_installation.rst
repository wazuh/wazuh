.. _wazuh_framework_installation:

Installation
======================

In this guide, we will get the Wazuh Framework installed.

Pre-requisites
------------------------

The framework will be installed in the **same server that OSSEC Manager**. So, before you begin with this guide, you need:

 - A non-root user account with sudo privileges.
 - Wazuh HIDS Manager installed, :ref:`see installation <wazuh_installation>`.
 - Python 2.7 or newer.


Required packages
------------------------

To complete this guide, you will need the following packages:

 - pip

  - Debian and Ubuntu based Linux distributions: sudo apt-get install python-pip
  - Red Hat, CentOS and Fedora: sudo yum install python-pip

 - virtualenv

  - pip install virtualenv



Automatic installation
------------------------
We will use the script placed in the main directoy of the repository.
::

    cd ~
    git clone https://github.com/wazuh/wazuh-framework
    cd wazuh-framework
    ./install_framework.sh


Manual installation
------------------------

Download the repository:
::

    cd ~
    git clone https://github.com/wazuh/wazuh-framework.git
    cd wazuh-framework

Create the virutal environment:
::

    mkdir /var/ossec/framework
    cd /var/ossec/framework
    virtualenv env


When you want to work on this enviroment, you only have to activate it:
::

    source /var/ossec/framework/env/bin/activate

And if you want to go back to the real world, use the following command:
::

    deactivate



Install the framework:
::

    source /var/ossec/framework/env/bin/activate
    pip install ~/wazuh-framework
    deactivate



Other actions
--------------------

Upgrade:

The installation script allows to update the package, but if you prefer do it manually:

::

    source /var/ossec/framework/env/bin/activate
    pip install ~/wazuh-framework --upgrade
    deactivate

Uninstall the framework:
::

    source /var/ossec/framework/env/bin/activate
    pip uninstall wazuh
    deactivate

Remove the virtual environment:
::

    rm -rf /var/ossec/framework
