#
# OSSEC 1.3 .spec file - AGENT
# Fri Aug 17 15:19:40 EDT 2007
#
#
# TODO:
#
# o Safety checks for %clean
#
# o Remove script
#
# o create an RPM_README.txt and put it in the source tree
#
#

Summary: Open Source Host-based Intrusion Detection System (Server)
Name: ossec-hids-agent-FC7
Version: 1.3
Release: 1
License: GPLv2
Group: Applications/Security
URL: http://www.ossec.net
Packager: Michael Williams (maverick@maverick.org)
Source: http://www.ossec.net/files/ossec-hids-1.3.tar.gz
Requires: /usr/sbin/useradd, /usr/sbin/groupadd, /usr/sbin/groupdel, /usr/sbin/userdel, /sbin/service, /sbin/chkconfig

%description
OSSEC is an Open Source Host-based Intrusion 
Detection System. It performs log analysis, 
integrity checking, Windows registry monitoring, 
rootkit detection, real-time alerting and active 
response.


%prep

%setup -n ossec-hids-1.3

%build
/bin/cp /usr/local/src/OSSEC-RPM/1.3/agent/preloaded-vars.conf ${RPM_BUILD_DIR}/ossec-hids-1.3/etc/

./install.sh

%clean
rm -rf $RPM_BUILD_ROOT

%pre
################################################################################
# Create OSSEC group
#
if ! grep "^ossec" /etc/group > /dev/null ; then
  /usr/sbin/groupadd ossec
fi


################################################################################
# Create OSSEC users
#
for USER in ossec ; do
  if ! grep "^${USER}" /etc/passwd > /dev/null ; then
    /usr/sbin/useradd -d /var/ossec -s /bin/false -g ossec ${USER}
  fi
done

%post



################################################################################
# Create OSSEC /etc/init.d/ossec file
#
cat <<EOF >> /etc/init.d/ossec
#!/bin/bash
#
# ossec Starts ossec
#
#
# chkconfig: 2345 12 88
# description: OSSEC is an open source host based IDS
### BEGIN INIT INFO
# Provides: $ossec
### END INIT INFO

# Source function library.
. /etc/init.d/functions

[ -f /var/ossec/bin/ossec-control ] || exit 0

RETVAL=0

umask 077

case "\$1" in
  start)
        /var/ossec/bin/ossec-control start
        ;;
  stop)
        /var/ossec/bin/ossec-control stop
        ;;
  status)
        /var/ossec/bin/ossec-control status
        ;;
  restart|reload)
        /var/ossec/bin/ossec-control restart
        ;;
  *)
        echo "Usage: /var/ossec/bin/ossec-control {start|stop|status|restart}"
        exit 1
esac

EOF

/bin/chown root.root /etc/init.d/ossec
/bin/chmod 755 /etc/init.d/ossec

################################################################################
# Set configuration so OSSEC starts on reboot
#
/sbin/chkconfig --add ossec
/sbin/chkconfig ossec on

%postun
# Run service command, make sure OSSEC is stopped
/sbin/service ossec stop

# Run chkconfig, stop ossec from starting on boot
/sbin/chkconfig ossec off
/sbin/chkconfig --del ossec

# Remove init.d file
[ -f /etc/init.d/ossec ] && rm /etc/init.d/ossec

# Remove ossec users
for USER in ossec ossecm ossecr ; do
  if grep "^${USER}" /etc/passwd > /dev/null ; then
    /usr/sbin/userdel -r ${USER}
  fi
done

# Remove ossec group
if grep "^ossec" /etc/group > /dev/null ; then
  /usr/sbin/groupdel ossec
fi


%files
%doc README BUGS CONFIG CONTRIB INSTALL LICENSE

%dir /var/ossec/
%attr(550, root, ossec) /var/ossec/
%dir /var/ossec/var
%attr(550, root, ossec) /var/ossec/var
%dir /var/ossec/var/run
%attr(770, root, ossec) /var/ossec/var/run
%dir /var/ossec/active-response
%attr(550, root, ossec) /var/ossec/active-response
%dir /var/ossec/active-response/bin
%attr(550, root, ossec) /var/ossec/active-response/bin
/var/ossec/active-response/bin/route-null.sh
%attr(755, root, ossec) /var/ossec/active-response/bin/route-null.sh
/var/ossec/active-response/bin/host-deny.sh
%attr(755, root, ossec) /var/ossec/active-response/bin/host-deny.sh
/var/ossec/active-response/bin/firewall-drop.sh
%attr(755, root, ossec) /var/ossec/active-response/bin/firewall-drop.sh
%dir /var/ossec/active-response/bin/firewalls
%attr(755, root, ossec) /var/ossec/active-response/bin/firewalls
/var/ossec/active-response/bin/firewalls/pf.sh
/var/ossec/active-response/bin/firewalls/ipfw.sh
/var/ossec/active-response/bin/firewalls/ipfw_mac.sh
/var/ossec/active-response/bin/disable-account.sh
%attr(755, root, ossec) /var/ossec/active-response/bin/disable-account.sh
%dir /var/ossec/bin
%attr(550, root, ossec) /var/ossec/bin
/var/ossec/bin/ossec-agentd
%attr(550, root, ossec) /var/ossec/bin/ossec-agentd
/var/ossec/bin/ossec-logcollector
%attr(550, root, ossec) /var/ossec/bin/ossec-logcollector
/var/ossec/bin/ossec-control
%attr(550, root, ossec) /var/ossec/bin/ossec-control
/var/ossec/bin/ossec-syscheckd
%attr(550, root, ossec) /var/ossec/bin/ossec-syscheckd
/var/ossec/bin/manage_agents
%attr(550, root, ossec) /var/ossec/bin/manage_agents
/var/ossec/bin/ossec-execd
%attr(550, root, ossec) /var/ossec/bin/ossec-execd
%dir /var/ossec/etc
%attr(550, root, ossec) /var/ossec/etc
/var/ossec/etc/internal_options.conf
%attr(440, root, ossec) /var/ossec/etc/internal_options.conf
/var/ossec/etc/localtime
%attr(644, root, root) /var/ossec/etc/localtime
%dir /var/ossec/etc/shared
%attr(770, root, ossec) /var/ossec/etc/shared
/var/ossec/etc/shared/win_malware_rcl.txt
%attr(770, root, ossec) /var/ossec/etc/shared/win_malware_rcl.txt
/var/ossec/etc/shared/win_applications_rcl.txt
%attr(770, root, ossec) /var/ossec/etc/shared/win_applications_rcl.txt
/var/ossec/etc/shared/win_audit_rcl.txt
%attr(770, root, ossec) /var/ossec/etc/shared/win_audit_rcl.txt
/var/ossec/etc/shared/rootkit_files.txt
%attr(770, root, ossec) /var/ossec/etc/shared/rootkit_files.txt
/var/ossec/etc/shared/rootkit_trojans.txt
%attr(770, root, ossec) /var/ossec/etc/shared/rootkit_trojans.txt
/var/ossec/etc/ossec.conf
%attr(440, root, ossec) /var/ossec/etc/ossec.conf
%dir /var/ossec/logs
%attr(750, ossec, ossec) /var/ossec/logs
/var/ossec/logs/ossec.log
%attr(664, ossec, ossec) /var/ossec/logs/ossec.log
%dir /var/ossec/queue
%attr(550, root, ossec) /var/ossec/queue
%dir /var/ossec/queue/rids
%attr(775, root, ossec) /var/ossec/queue/rids
%dir /var/ossec/queue/alerts
%attr(550, root, ossec) /var/ossec/queue/alerts
%dir /var/ossec/queue/syscheck
%attr(550, root, ossec) /var/ossec/queue/syscheck
%dir /var/ossec/queue/ossec
%attr(770, ossec, ossec) /var/ossec/queue/ossec

