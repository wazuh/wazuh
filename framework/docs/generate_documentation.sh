#!/usr/bin/env bash

# Copyright (C) 2015-2019, Wazuh Inc.

source /var/ossec/framework/env/bin/activate
echo -e "Required packages:"
echo "------"
pip install sphinx
pip install sphinx_rtd_theme
echo "------"

echo -e "\nsphinx-apidoc:"
sphinx-apidoc --force --module-first --no-toc -H "Wazuh Framework Reference" -o source/ ../wazuh/ || exit 1

echo -e "\nEditing documentation..."
(mv source/wazuh.rst source/wazuh_framework_reference.rst && sed -i 's/=============/-------------/' source/wazuh_framework_reference.rst && sed -i '1 s/^/.. _wazuh_framework_reference:\n\nReference\n=============\n\n/' source/wazuh_framework_reference.rst) || exit 1

echo -e "\nCreating html:"
make html

if [ "X$1" != "X" ]; then
    echo -e "\nCopying to wazuh-documentation: $1"
    cp -r source/wazuh_framework* $1/source/ || exit 1
fi

`deactivate`
echo -e "\n[Done]"
