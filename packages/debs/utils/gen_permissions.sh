#!/usr/bin/env /bin/bash
#
# Wazuh restore permissions script generator (ver 0.1)
# Copyright (C) 2019 Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# This scripts take 2 parameters, source_dir and target_dir
# Remember: you must use gawk, be careful mawk is not compatible
#
# Usage: ./gen_permissions.sh /var/ossec/ ~/restore_permissions.sh

set -euo pipefail

# Symlinks are excluded: find reports them as mode 777 and chmod/chown on a
# symlink path dereference it, so restoring them would reset the target's
# permissions to 777 whenever the symlink entry follows the target's own.
find $1 -depth ! -type l -printf '%m:%u:%g:%p\0' | awk -v RS='\0' -F: '
BEGIN {
    print "#!/bin/sh";
    q = "\047";
}
{
    gsub(q, q q "\\" q);
    f = $0;
    sub(/^[^:]*:[^:]*:[^:]*:/, "", f);
    print "chown --", q $2 ":" $3 q, q f q, " > /dev/null 2>&1 || :";
    print "chmod", $1, q f q, " > /dev/null 2>&1 || :";
}' > $2
chmod +x $2
