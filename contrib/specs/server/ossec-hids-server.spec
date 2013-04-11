#
# OSSEC 1.3 .spec file - SERVER
# Fri Aug 17 15:13:32 EDT 2007
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
Name: ossec-hids-server-FC7
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
/bin/cp /usr/local/src/OSSEC-RPM/1.3/server/preloaded-vars.conf ${RPM_BUILD_DIR}/ossec-hids-1.3/etc/

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
for USER in ossec ossecm ossecr ; do
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
%dir /var/ossec/stats
%attr(750, ossec, ossec) /var/ossec/stats
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
/var/ossec/active-response/bin/disable-account.sh
%attr(755, root, ossec) /var/ossec/active-response/bin/disable-account.sh
%dir /var/ossec/tmp
%attr(550, root, ossec) /var/ossec/tmp
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
/var/ossec/bin/ossec-remoted
%attr(550, root, ossec) /var/ossec/bin/ossec-remoted
/var/ossec/bin/ossec-monitord
%attr(550, root, ossec) /var/ossec/bin/ossec-monitord
/var/ossec/bin/list_agents
%attr(550, root, ossec) /var/ossec/bin/list_agents
/var/ossec/bin/clear_stats
%attr(550, root, ossec) /var/ossec/bin/clear_stats
/var/ossec/bin/ossec-execd
%attr(550, root, ossec) /var/ossec/bin/ossec-execd
/var/ossec/bin/ossec-maild
%attr(550, root, ossec) /var/ossec/bin/ossec-maild
/var/ossec/bin/ossec-analysisd
%attr(550, root, ossec) /var/ossec/bin/ossec-analysisd
/var/ossec/bin/syscheck_update
%attr(550, root, ossec) /var/ossec/bin/syscheck_update
%dir /var/ossec/etc
%attr(550, root, ossec) /var/ossec/etc
/var/ossec/etc/internal_options.conf
%attr(440, root, ossec) /var/ossec/etc/internal_options.conf
/var/ossec/etc/localtime
%attr(555, root, ossec) /var/ossec/etc/localtime
%dir /var/ossec/etc/shared
%attr(550, root, ossec) /var/ossec/etc/shared
/var/ossec/etc/shared/win_malware_rcl.txt
%attr(440, root, ossec) /var/ossec/etc/shared/win_malware_rcl.txt
/var/ossec/etc/shared/win_applications_rcl.txt
%attr(440, root, ossec) /var/ossec/etc/shared/win_applications_rcl.txt
/var/ossec/etc/shared/win_audit_rcl.txt
%attr(440, root, ossec) /var/ossec/etc/shared/win_audit_rcl.txt
/var/ossec/etc/shared/rootkit_files.txt
%attr(440, root, ossec) /var/ossec/etc/shared/rootkit_files.txt
/var/ossec/etc/shared/rootkit_trojans.txt
%attr(440, root, ossec) /var/ossec/etc/shared/rootkit_trojans.txt
/var/ossec/etc/ossec.conf
%attr(440, root, ossec) /var/ossec/etc/ossec.conf
/var/ossec/etc/decoder.xml
%attr(440, root, ossec) /var/ossec/etc/decoder.xml
%dir /var/ossec/rules
%attr(550, root, ossec) /var/ossec/rules
/var/ossec/rules/ms_ftpd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/ms_ftpd_rules.xml
/var/ossec/rules/zeus_rules.xml
%attr(550, root, ossec) /var/ossec/rules/zeus_rules.xml
/var/ossec/rules/squid_rules.xml
%attr(550, root, ossec) /var/ossec/rules/squid_rules.xml
/var/ossec/rules/racoon_rules.xml
%attr(550, root, ossec) /var/ossec/rules/racoon_rules.xml
/var/ossec/rules/smbd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/smbd_rules.xml
/var/ossec/rules/proftpd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/proftpd_rules.xml
/var/ossec/rules/msauth_rules.xml
%attr(550, root, ossec) /var/ossec/rules/msauth_rules.xml
/var/ossec/rules/ms-exchange_rules.xml
%attr(550, root, ossec) /var/ossec/rules/ms-exchange_rules.xml
/var/ossec/rules/symantec-ws_rules.xml
%attr(550, root, ossec) /var/ossec/rules/symantec-ws_rules.xml
/var/ossec/rules/sendmail_rules.xml
%attr(550, root, ossec) /var/ossec/rules/sendmail_rules.xml
/var/ossec/rules/web_rules.xml
%attr(550, root, ossec) /var/ossec/rules/web_rules.xml
/var/ossec/rules/netscreenfw_rules.xml
%attr(550, root, ossec) /var/ossec/rules/netscreenfw_rules.xml
/var/ossec/rules/attack_rules.xml
%attr(550, root, ossec) /var/ossec/rules/attack_rules.xml
/var/ossec/rules/hordeimp_rules.xml
%attr(550, root, ossec) /var/ossec/rules/hordeimp_rules.xml
/var/ossec/rules/postfix_rules.xml
%attr(550, root, ossec) /var/ossec/rules/postfix_rules.xml
/var/ossec/rules/rules_config.xml
%attr(550, root, ossec) /var/ossec/rules/rules_config.xml
/var/ossec/rules/spamd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/spamd_rules.xml
/var/ossec/rules/cisco-ios_rules.xml
%attr(550, root, ossec) /var/ossec/rules/cisco-ios_rules.xml
/var/ossec/rules/local_rules.xml
%attr(550, root, ossec) /var/ossec/rules/local_rules.xml
/var/ossec/rules/apache_rules.xml
%attr(550, root, ossec) /var/ossec/rules/apache_rules.xml
/var/ossec/rules/mailscanner_rules.xml
%attr(550, root, ossec) /var/ossec/rules/mailscanner_rules.xml
/var/ossec/rules/vpn_concentrator_rules.xml
%attr(550, root, ossec) /var/ossec/rules/vpn_concentrator_rules.xml
/var/ossec/rules/firewall_rules.xml
%attr(550, root, ossec) /var/ossec/rules/firewall_rules.xml
/var/ossec/rules/named_rules.xml
%attr(550, root, ossec) /var/ossec/rules/named_rules.xml
/var/ossec/rules/ossec_rules.xml
%attr(550, root, ossec) /var/ossec/rules/ossec_rules.xml
/var/ossec/rules/courier_rules.xml
%attr(550, root, ossec) /var/ossec/rules/courier_rules.xml
/var/ossec/rules/vsftpd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/vsftpd_rules.xml
/var/ossec/rules/vpopmail_rules.xml
%attr(550, root, ossec) /var/ossec/rules/vpopmail_rules.xml
/var/ossec/rules/pure-ftpd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/pure-ftpd_rules.xml
/var/ossec/rules/telnetd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/telnetd_rules.xml
/var/ossec/rules/pix_rules.xml
%attr(550, root, ossec) /var/ossec/rules/pix_rules.xml
/var/ossec/rules/ftpd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/ftpd_rules.xml
/var/ossec/rules/ids_rules.xml
%attr(550, root, ossec) /var/ossec/rules/ids_rules.xml
/var/ossec/rules/symantec-av_rules.xml
%attr(550, root, ossec) /var/ossec/rules/symantec-av_rules.xml
/var/ossec/rules/arpwatch_rules.xml
%attr(550, root, ossec) /var/ossec/rules/arpwatch_rules.xml
/var/ossec/rules/policy_rules.xml
%attr(550, root, ossec) /var/ossec/rules/policy_rules.xml
/var/ossec/rules/sshd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/sshd_rules.xml
/var/ossec/rules/syslog_rules.xml
%attr(550, root, ossec) /var/ossec/rules/syslog_rules.xml
/var/ossec/rules/pam_rules.xml
%attr(550, root, ossec) /var/ossec/rules/pam_rules.xml
/var/ossec/rules/imapd_rules.xml
%attr(550, root, ossec) /var/ossec/rules/imapd_rules.xml
%dir /var/ossec/logs
%attr(750, ossec, ossec) /var/ossec/logs
%dir /var/ossec/logs/alerts
%attr(750, ossec, ossec) /var/ossec/logs/alerts
%dir /var/ossec/logs/firewall
%attr(750, ossec, ossec) /var/ossec/logs/firewall
%dir /var/ossec/logs/archives
%attr(750, ossec, ossec) /var/ossec/logs/archives
/var/ossec/logs/ossec.log
%attr(664, ossec, ossec) /var/ossec/logs/ossec.log
%dir /var/ossec/queue
%attr(550, root, ossec) /var/ossec/queue
%dir /var/ossec/queue/fts
%attr(750, ossec, ossec) /var/ossec/queue/fts
%dir /var/ossec/queue/rids
%attr(755, ossecr, ossec) /var/ossec/queue/rids
%dir /var/ossec/queue/alerts
%attr(770, ossec, ossec) /var/ossec/queue/alerts
%dir /var/ossec/queue/rootcheck
%attr(750, ossec, ossec) /var/ossec/queue/rootcheck
%dir /var/ossec/queue/agent-info
%attr(755, ossecr, ossec) /var/ossec/queue/agent-info
%dir /var/ossec/queue/syscheck
%attr(750, ossec, ossec) /var/ossec/queue/syscheck
%dir /var/ossec/queue/ossec
%attr(770, ossec, ossec) /var/ossec/queue/ossec

