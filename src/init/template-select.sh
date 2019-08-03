#!/bin/sh

# Wazuh Template Selector
# Copyright (C) 2015-2019, Wazuh Inc.
# November 18, 2016.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

GetTemplate()
{
  #GetTemplate template(1) distrib(2) version(3) sub_version(4)
  if [ "$#" = "4" ]; then
    # /etc/templates/config/distrib/version/sub_version/template
    if [ -r "./etc/templates/config/$2/$3/$4/$1" ]; then
      echo "./etc/templates/config/$2/$3/$4/$1"
    # /etc/templates/config/distrib/version/template
    elif [ -r "./etc/templates/config/$2/$3/$1" ]; then
      echo "./etc/templates/config/$2/$3/$1"
    # /etc/templates/config/distrib/template
    elif [ -r "./etc/templates/config/$2/$1" ]; then
      echo "./etc/templates/config/$2/$1"
    # /etc/templates/common/template
    elif [ -r "./etc/templates/config/generic/$1" ]; then
      echo "./etc/templates/config/generic/$1"
    else
      echo "ERROR_NOT_FOUND"
    fi
  else
    echo "ERROR_PARAM"
  fi
}
