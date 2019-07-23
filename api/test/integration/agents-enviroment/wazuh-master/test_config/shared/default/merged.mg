#default
!77 ar.conf
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
!76 agent.conf
<agent_config>

  <!-- Shared agent configuration here -->

</agent_config>
!28416 cis_apache2224_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2017
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry , use "->" to look for a specific entry and another
# "->" to look for the value.
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Apache Https Server 
# Based on Center for Internet Security Benchmark for Apache HttpSserver 2.4 v1.3.1 and Apache HttpsServer 2.2 v3.4.1 (https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308)
#
#
$main-conf=/etc/apache2/apache2.conf,/etc/httpd/conf/httpd.conf;
$conf-dirs=/etc/apache2/conf-enabled,/etc/apache2/mods-enabled,/etc/apache2/sites-enabled,/etc/httpd/conf.d,/etc/httpd/modsecurity.d;
$ssl-confs=/etc/apache2/mods-enabled/ssl.conf,/etc/httpd/conf.d/ssl.conf;
$mods-en=/etc/apache2/mods-enabled;
$request-confs=/etc/httpd/conf/httpd.conf,/etc/apache2/mods-enabled/reqtimeout.conf;
$traceen=/etc/apache2/apache2.conf,/etc/httpd/conf/httpd.conf,/etc/apache2/conf-enabled/security.conf;
#
#
#2.3 Disable WebDAV Modules
[CIS - Apache Configuration - 2.3: WebDAV Modules are enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\sdav;
d:$conf-dirs -> load -> !r:^# && r:loadmodule\sdav;
f:/etc/httpd/conf.d -> !r:^# && r:loadmodule\sdav;
d:$mods-en -> dav.load;
#
#
#2.4 Disable Status Module
[CIS - Apache Configuration - 2.4: Status Module is enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\sstatus;
d:$conf-dirs -> load -> !r:^# && r:loadmodule\sstatus;
f:/etc/httpd/conf.d -> !r:^# && r:loadmodule\sstatus;
d:$mods-en -> status.load;
#
#
#2.5 Disable Autoindex Module
[CIS - Apache Configuration - 2.5: Autoindex Module is enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\sautoindex;
d:$conf-dirs -> load -> !r:^# && r:loadmodule\sautoindex;
f:/etc/httpd/conf.d -> !r:^# && r:loadmodule\sautoindex;
d:$mods-en -> autoindex.load;
#
#
#2.6 Disable Proxy Modules
[CIS - Apache Configuration - 2.6: Proxy Modules are enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\sproxy;
d:$conf-dirs -> load -> !r:^# && r:loadmodule\sproxy;
f:/etc/httpd/conf.d -> !r:^# && r:loadmodule\sproxy;
d:$mods-en -> proxy.load;
#
#
#2.7 Disable User Directories Modules
[CIS - Apache Configuration - 2.7: User Directories Modules are enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\suserdir;
d:$conf-dirs -> load -> !r:^# && r:loadmodule\suserdir;
f:/etc/httpd/conf.d -> !r:^# && r:loadmodule\suserdir;
d:$mods-en -> userdir.load;
#
#
#2.8 Disable Info Module
[CIS - Apache Configuration - 2.8: Info Module is enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\sinfo;
d:$conf-dirs -> load -> !r:^# && r:loadmodule\sinfo;
d:$conf-dirs -> conf -> !r:^# && r:loadmodule\sinfo;
d:$mods-en -> info.load;
#
#
#3.2 Give the Apache User Account an Invalid Shell 
[CIS - Apache Configuration - 3.2: Apache User Account has got a valid shell] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/passwd -> r:/var/www && !r:\.*/bin/false$|/sbin/nologin$;
#
#
#3.3 Lock the Apache User Account
[CIS - Apache Configuration - 3.3: Lock the Apache User Account] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/shadow -> r:^daemon|^wwwrun|^www-data|^apache && !r:\p!\.*$; 
#
#
#4.4 Restrict Override for All Directories
[CIS - Apache Configuration - 4.4: Restrict Override for All Directories] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && !r:\w+ && r:allowoverride && !r:none$;
d:$conf-dirs -> conf -> !r:^# && !r:\w+ && r:allowoverridelist;
f:$main-conf -> !r:^# && !r:\w+ && r:allowoverride && !r:none$;
f:$main-conf -> !r:^# && !r:\w+ && r:allowoverridelist;
#
#
#5.3 Minimize Options for Other Directories
[CIS - Apache Configuration - 5.3: Minimize Options for other directories] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:options\sincludes;
f:$main-conf -> !r:^# && r:options\sincludes;
#
#
#5.4.1 Remove default index.html sites
[CIS - Apache Configuration - 5.4.1: Remove default index.html sites] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:/var/www -> index.html;
d:/var/www/html -> index.html;
#
#
#5.4.2 Remove the Apache user manual
[CIS - Apache Configuration - 5.4.2: Remove the Apache user manual] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:/etc/httpd/conf.d -> manual.conf; 
d:/etc/apache2/conf-enabled -> apache2-doc.conf;
#
#
#5.4.5 Verify that no Handler is enabled 
[CIS - Apache Configuration - 5.4.5: A Handler is configured] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:/wsethandler;
f:$main-conf -> !r:^# && r:/wsethandler;
#
#
#5.5 Remove default CGI content printenv 
[CIS - Apache Configuration - 5.5: Remove default CGI content printenv] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:/var/www/cgi-bin -> printenv;
d:/usr/lib/cgi-bin -> printenv;
#
#
#5.6 Remove default CGI content test-cgi 
[CIS - Apache Configuration - 5.6: Remove default CGI content test-cgi] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:/var/www/cgi-bin -> test-cgi;
d:/usr/lib/cgi-bin -> test-cgi;
#
#
#5.7 Limit HTTP Request Method
[CIS - Apache Configuration - 5.7: Disable HTTP Request Method] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:<limitexcept\sget\spost\soptions>;
#
#
#5.8 Disable HTTP Trace Method
[CIS - Apache Configuration - 5.8: Disable HTTP Trace Method] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$traceen -> !r:^# && r:traceenable\s+on\s*$;
#
#
#5.9 Restrict HTTP Protocol Versions
[CIS - Apache Configuration - 5.9: Restrict HTTP Protocol Versions] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/httpd/conf/httpd.conf -> !r:loadmodule\srewrite;
d:$mods-en -> !f:rewrite.load;
f:$main-conf -> !r:rewriteengine\son;
f:$main-conf -> !r:rewritecond && !r:%{THE_REQUEST} && !r:!HTTP/1\\.1\$; 
f:$main-conf -> !r:rewriterule && !r:.* - [F];
#
#
#5.12 Deny IP Address Based Requests
[CIS - Apache Configuration - 5.12: Deny IP Address Based Requests] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/httpd/conf/httpd.conf -> !r:loadmodule\srewrite;
d:$mods-en -> !f:rewrite.load;
f:$main-conf -> !r:rewriteengine\son;
f:$main-conf -> !r:rewritecond && !r:%{HTTP_HOST} && !r:www\\.\w+\\.\w+ [NC]$;
f:$main-conf -> !r:rewritecond && !r:%{REQUEST_URI} && !r:/error [NC]$; 
f:$main-conf -> !r:rewriterule && !r:.\(.*\) - [L,F]$;
#
#
#5.13 Restrict Listen Directive 
[CIS - Apache Configuration - 5.13: Restrict Listen Directive] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:listen\s80$;
d:$conf-dirs -> conf -> !r:^# && r:listen\s0.0.0.0\p80;
d:$conf-dirs -> conf -> !r:^# && r:listen\s[\p\pffff\p0.0.0.0]\p80;
f:$main-conf -> !r:^# && r:listen\s80$;
f:$main-conf -> !r:^# && r:listen\s0.0.0.0\p\d*;
f:$main-conf -> !r:^# && r:listen\s[\p\pffff\p0.0.0.0]\p\d*; 
f:/etc/apache2/sites-enabled/000-default.conf -> !r:^# && r:listen\s80$;
f:/etc/apache2/sites-enabled/000-default.conf -> !r:^# && r:listen\s0.0.0.0\p\d*;
f:/etc/apache2/sites-enabled/000-default.conf -> !r:^# && r:listen\s[\p\pffff\p0.0.0.0]\p\d*;
f:/etc/apache2/ports.conf -> !r:^# && r:listen\s80$;
f:/etc/apache2/ports.conf -> !r:^# && r:listen\s0.0.0.0\p\d*;
f:/etc/apache2/ports.conf -> !r:^# && r:listen\s[\p\pffff\p0.0.0.0]\p\d*;
#
#
#5.14 Restrict Browser Frame Options 
[CIS - Apache Configuration - 5.14: Restrict Browser Frame Options] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:header\salways\sappend\sx-frame-options && !r:sameorigin|deny; 
#
#
#6.1 Configure the Error Log to notice at least
[CIS - Apache Configuration - 6.1: Configure the Error Log to notice at least] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^# && r:loglevel\snotice\score\p && r:warn|emerg|alert|crit|error|notice;
f:$main-conf -> !r:loglevel\snotice\score\p && !r:info|debug;
#
#
#6.2 Configure a Syslog facility for Error Log 
[CIS - Apache Configuration - 6.2: Configure a Syslog facility for Error Log] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:errorlog\s+\p*syslog\p\.*\p*;
#
#
#7.6 Disable SSL Insecure Renegotiation 
[CIS - Apache Configuration - 7.6: Disable SSL Insecure Renegotiation] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$ssl-confs -> !r:^\t*\s*# && r:sslinsecurerenegotiation\s+on\s*;
f:$ssl-confs -> !r:^\t*\s*# && r:sslinsecurerenegotiation\s*$;
#
#
#7.7 Ensure SSL Compression is not enabled 
[CIS - Apache Configuration - 7.7: Ensure SSL Compression is not enabled] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$ssl-confs -> !r:^\t*\s*# && r:sslcompression\s+on\s*;
f:$ssl-confs -> !r:^\t*\s*# && r:sslcompression\s*$;
#
#
#7.8 Disable SSL TLS v1.0 Protocol
[CIS - Apache Configuration - 7.8: Disable insecure TLS Protocol] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$ssl-confs -> !r:^\t*\s*sslprotocol;
f:$ssl-confs -> !r:^\t*\s*# && r:sslprotocol\s+all;
f:$ssl-confs -> !r:^\t*\s*# && r:sslprotocol\s+\.*tlsv1\P\s*;
f:$ssl-confs -> !r:^\t*\s*# && r:sslprotocol\s+\.*sslv2\P\s*;
f:$ssl-confs -> !r:^\t*\s*# && r:sslprotocol\s+\.*sslv3\P\s*;
#
#
#7.9 Enable OCSP Stapling
[CIS - Apache Configuration - 7.9: Enable OCSP Stapling] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/httpd/conf/httpd.conf -> !r:^loadmodule\s+ssl;
d:$mods-en -> !f:ssl.load;
f:$ssl-confs -> !r:\t*\s*# && r:sslusestapling\s+off;
f:$ssl-confs -> !r:\t*\s*sslusestapling\s+on;
f:$ssl-confs -> !r:\t*\s*sslstaplingcache\s+\.+;
#
#
#7.10 Enable HTTP Strict Transport Security 
[CIS - Apache Configuration - 7.10: Enable HTTP Strict Transport Security] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/apache2/apache2.conf -> !r:Header\salways\sset\sStrict-Transport-Security\s"max-age=\d\d\d\d*";
f:/etc/apache2/apache2.conf -> !r:^# && r:Header\salways\sset\sStrict-Transport-Security\s"max-age=1\d\d";
f:/etc/apache2/apache2.conf -> !r:^# && r:Header\salways\sset\sStrict-Transport-Security\s"max-age=2\d\d";
f:/etc/apache2/apache2.conf -> !r:^# && r:Header\salways\sset\sStrict-Transport-Security\s"max-age=3\d\d";
f:/etc/apache2/apache2.conf -> !r:^# && r:Header\salways\sset\sStrict-Transport-Security\s"max-age=4\d\d";
f:/etc/apache2/apache2.conf -> !r:^# && r:Header\salways\sset\sStrict-Transport-Security\s"max-age=5\d\d";
#
#
#8.1 Set ServerToken to Prod or ProductOnly 
[CIS - Apache Configuration - 8.1: Set ServerToken to Prod or ProductOnly] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:servertokens\s+major;
d:$conf-dirs -> conf -> !r:^# && r:servertokens\s+minor;
d:$conf-dirs -> conf -> !r:^# && r:servertokens\s+min;
d:$conf-dirs -> conf -> !r:^# && r:servertokens\s+minimal;
d:$conf-dirs -> conf -> !r:^# && r:servertokens\s+os;
d:$conf-dirs -> conf -> !r:^# && r:servertokens\s+full;
#
#
#8.2: Set ServerSignature to Off
[CIS - Apache Configuration - 8.2: Set ServerSignature to Off] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^# && r:serversignature\s+email;
d:$conf-dirs -> conf -> !r:^# && r:serversignature\s+on;
#
#
#8.3: Prevent Information Leakage via Default Apache Content 
[CIS - Apache Configuration - 8.3: Prevent Information Leakage via Default Apache Content] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
d:$conf-dirs -> conf -> !r:^\t*\s*# && r:include\s*\w*httpd-autoindex.conf;
d:$conf-dirs -> conf -> !r:^\t*\s*# && r:alias\s*/icons/\s*\.*;
#
#
#9.1:Set TimeOut to 10 or less 
[CIS - Apache Configuration - 9.1: Set TimeOut to 10 or less] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^# && r:timeout\s+9\d;
f:$main-conf -> !r:^# && r:timeout\s+8\d;
f:$main-conf -> !r:^# && r:timeout\s+7\d;
f:$main-conf -> !r:^# && r:timeout\s+6\d;
f:$main-conf -> !r:^# && r:timeout\s+5\d;
f:$main-conf -> !r:^# && r:timeout\s+4\d;
f:$main-conf -> !r:^# && r:timeout\s+3\d;
f:$main-conf -> !r:^# && r:timeout\s+2\d;
f:$main-conf -> !r:^# && r:timeout\s+11;
f:$main-conf -> !r:^# && r:timeout\s+12;
f:$main-conf -> !r:^# && r:timeout\s+13;
f:$main-conf -> !r:^# && r:timeout\s+14;
f:$main-conf -> !r:^# && r:timeout\s+15;
f:$main-conf -> !r:^# && r:timeout\s+16;
f:$main-conf -> !r:^# && r:timeout\s+17;
f:$main-conf -> !r:^# && r:timeout\s+18;
f:$main-conf -> !r:^# && r:timeout\s+19;
f:$main-conf -> !r:^timeout\s+\d\d*;
f:$main-conf -> !r:^# && r:timeout\s+\d\d\d+;
#
#
#9.2:Set the KeepAlive directive to On 
[CIS - Apache Configuration - 9.2: Set the KeepAlive directive to On] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^# && r:keepalive\s+off;
f:$main-conf -> !r:keepalive\s+on;
#
#
#9.3:Set MaxKeepAliveRequests to 100 or greater
[CIS - Apache Configuration - 9.3: Set MaxKeepAliveRequest to 100 or greater] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^maxkeepaliverequests\s+\d\d\d+;
#
#
#9.4: Set KeepAliveTimeout Low to Mitigate Denial of Service
[CIS - Apache Configuration - 9.4: Set KeepAliveTimeout Low] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:keepalivetimeout\s+\d\d*;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+16;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+17;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+18;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+19;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+2\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+3\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+4\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+5\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+6\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+7\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+8\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+9\d;
f:$main-conf -> !r:^# && r:keepalivetimeout\s+\d\d\d+;
#
#
#9.5 Set Timeout Limits for Request Headers
[CIS - Apache Configuration - 9.5: Set Timeout Limits for Request Headers] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/httpd/conf/httpd.conf -> !r:^loadmodule\s+reqtimeout;
d:$mods-en -> !f:reqtimeout.load;
f:$request-confs -> !r:^\t*\s*requestreadtimeout\.+header\p\d\d*\D\d\d*;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D41;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D42;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D43;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D44;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D45;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D46;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D47;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D48;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D49;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D5\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D6\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D7\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D8\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D9\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+header\p\d\d\D\d\d\d+;
#
#
#9.6 Set Timeout Limits for Request Body 
[CIS - Apache Configuration - 9.6: Set Timeout Limits for Request Body] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:/etc/httpd/conf/httpd.conf -> !r:^loadmodule\s+reqtimeout;
d:$mods-en -> !f:reqtimeout.load;
f:$request-confs -> !r:\t*\s*requestreadtimeout\.+body\p\d\d*;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p21;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p22;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p23;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p24;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p25;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p26;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p27;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p28;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p29;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p3\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p4\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p5\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p6\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p7\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p8\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p9\d;
f:$request-confs -> !r:^\t*\s*# && r:\t*\s*requestreadtimeout\.+body\p\d\d\d+;
#
#
#10.1 Set the LimitRequestLine directive to 512 or less
[CIS - Apache Configuration - 10.1: Set LimitRequestLine to 512 or less] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^limitrequestline\s+\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\13;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\14;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\15;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\16;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\17;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\18;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\19;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\2\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\3\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\4\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\5\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\6\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\7\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\8\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+5\9\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+6\d\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+7\d\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+8\d\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+9\d\d;
f:$main-conf -> !r:^# && r:limitrequestline\s+\d\d\d\d+;
#
#
#10.2 Set the LimitRequestFields directive to 100 or less
[CIS - Apache Configuration - 10.2: Set LimitRequestFields to 100 or less] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^limitrequestfields\s\d\d*;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d1;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d2;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d3;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d4;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d5;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d6;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d7;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d8;
f:$main-conf -> !r:^# && r:limitrequestfields\s+1\d9;
f:$main-conf -> !r:^# && r:limitrequestfields\s+11\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+12\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+13\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+14\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+15\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+16\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+17\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+18\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+19\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+2\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+3\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+4\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+5\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+6\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+7\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+8\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+9\d\d;
f:$main-conf -> !r:^# && r:limitrequestfields\s+\d\d\d\d+;
#
#
#10.3 Set the LimitRequestFieldsize directive to 1024 or less
[CIS - Apache Configuration - 10.3: Set LimitRequestFieldsize to 1024 or less] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^limitrequestfieldsize\s+\d\d*;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d25;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d26;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d27;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d28;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d29;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d3\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d4\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d5\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d6\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d7\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d8\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+1\d9\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+11\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+12\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+13\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+14\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+15\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+16\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+17\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+18\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+19\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+2\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+3\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+4\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+5\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+6\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+7\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+8\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+9\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestfieldsize\s+\d\d\d\d\d+;
#
#
#10.4 Set the LimitRequestBody directive to 102400 or less
[CIS - Apache Configuration - 10.4: Set LimitRequestBody to 102400 or less] [any] [https://workbench.cisecurity.org/benchmarks/307, https://workbench.cisecurity.org/benchmarks/308]
f:$main-conf -> !r:^limitrequestbody\s+\d\d*;
f:$main-conf -> !r:^# && r:limitrequestbody\s+0\s*$;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d1;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d2;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d3;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d4;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d5;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d6;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d7;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d8;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d24\d9;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d241\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d242\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d243\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d244\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d245\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d246\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d247\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d248\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d249\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d25\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d26\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d27\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d28\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d29\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d3\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d4\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d5\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d6\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d7\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d8\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+1\d9\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+11\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+12\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+13\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+14\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+15\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+16\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+17\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+18\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+19\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+2\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+3\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+4\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+5\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+6\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+7\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+8\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+9\d\d\d\d\d;
f:$main-conf -> !r:^# && r:limitrequestbody\s+\d\d\d\d\d\d\d+;
!12581 cis_debian_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2008 Daniel B. Cid - dcid@ossec.net
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Debian/Ubuntu
# Based on Center for Internet Security Benchmark for Debian Linux v1.0

# Main one. Only valid for Debian/Ubuntu.
[CIS - Testing against the CIS Debian Linux Benchmark v1.0] [all required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/debian_version;
f:/proc/sys/kernel/ostype -> Linux;


# Section 1.4 - Partition scheme.
[CIS - Debian Linux - 1.4 - Robust partition scheme - /tmp is not on its own partition {CIS: 1.4 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:/tmp;

[CIS - Debian Linux - 1.4 - Robust partition scheme - /opt is not on its own partition {CIS: 1.4 Debian Linux}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/opt;
f:/etc/fstab -> !r:/opt;

[CIS - Debian Linux - 1.4 - Robust partition scheme - /var is not on its own partition {CIS: 1.4 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:/var;


# Section 2.3 - SSH configuration
[CIS - Debian Linux - 2.3 - SSH Configuration - Protocol version 1 enabled {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

[CIS - Debian Linux - 2.3 - SSH Configuration - IgnoreRHosts disabled {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

[CIS - Debian Linux - 2.3 - SSH Configuration - Empty passwords permitted {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;

[CIS - Debian Linux - 2.3 - SSH Configuration - Host based authentication enabled {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

[CIS - Debian Linux - 2.3 - SSH Configuration - Root login allowed {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;


# Section 2.4 Enable system accounting
#[CIS - Debian Linux - 2.4 - System Accounting - Sysstat not installed {CIS: 2.4 Debian Linux}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
#f:!/etc/default/sysstat;
#f:!/var/log/sysstat;

#[CIS - Debian Linux - 2.4 - System Accounting - Sysstat not enabled {CIS: 2.4 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
#f:!/etc/default/sysstat;
#f:/etc/default/sysstat -> !r:^# && r:ENABLED="false";


# Section 2.5 Install and run Bastille
#[CIS - Debian Linux - 2.5 - System harderning - Bastille is not installed {CIS: 2.5 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
#f:!/etc/Bastille;


# Section 2.6 Ensure sources.list Sanity
[CIS - Debian Linux - 2.6 - Sources list sanity - Security updates not enabled {CIS: 2.6 Debian Linux} {PCI_DSS: 6.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:!/etc/apt/sources.list;
f:!/etc/apt/sources.list -> !r:^# && r:http://security.debian|http://security.ubuntu;


# Section 3 - Minimize inetd services
[CIS - Debian Linux - 3.3 - Telnet enabled on inetd {CIS: 3.3 Debian Linux} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:telnet;

[CIS - Debian Linux - 3.4 - FTP enabled on inetd {CIS: 3.4 Debian Linux} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:/ftp;

[CIS - Debian Linux - 3.5 - rsh/rlogin/rcp enabled on inetd {CIS: 3.5 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:shell|login;

[CIS - Debian Linux - 3.6 - tftpd enabled on inetd {CIS: 3.6 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:tftp;

[CIS - Debian Linux - 3.7 - imap enabled on inetd {CIS: 3.7 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:imap;

[CIS - Debian Linux - 3.8 - pop3 enabled on inetd {CIS: 3.8 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:pop;

[CIS - Debian Linux - 3.9 - Ident enabled on inetd {CIS: 3.9 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inetd.conf -> !r:^# && r:ident;


# Section 4 - Minimize boot services
[CIS - Debian Linux - 4.1 - Disable inetd - Inetd enabled but no services running {CIS: 4.1 Debian Linux} {PCI_DSS: 2.2.2}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
p:inetd;
f:!/etc/inetd.conf -> !r:^# && r:wait;

[CIS - Debian Linux - 4.3 - GUI login enabled {CIS: 4.3 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/inittab -> !r:^# && r:id:5;

[CIS - Debian Linux - 4.6 - Disable standard boot services - Samba Enabled {CIS: 4.6 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/samba;

[CIS - Debian Linux - 4.7 - Disable standard boot services - NFS Enabled {CIS: 4.7 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/nfs-common;
f:/etc/init.d/nfs-user-server;
f:/etc/init.d/nfs-kernel-server;

[CIS - Debian Linux - 4.9 - Disable standard boot services - NIS Enabled {CIS: 4.9 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/nis;

[CIS - Debian Linux - 4.13 - Disable standard boot services - Web server Enabled {CIS: 4.13 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/apache;
f:/etc/init.d/apache2;

[CIS - Debian Linux - 4.15 - Disable standard boot services - DNS server Enabled {CIS: 4.15 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/bind;

[CIS - Debian Linux - 4.16 - Disable standard boot services - MySQL server Enabled {CIS: 4.16 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/mysql;

[CIS - Debian Linux - 4.16 - Disable standard boot services - PostgreSQL server Enabled {CIS: 4.16 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/postgresql;

[CIS - Debian Linux - 4.17 - Disable standard boot services - Webmin Enabled {CIS: 4.17 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/webmin;

[CIS - Debian Linux - 4.18 - Disable standard boot services - Squid Enabled {CIS: 4.18 Debian Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/init.d/squid;


# Section 5 - Kernel tuning
[CIS - Debian Linux - 5.1 - Network parameters - Source routing accepted {CIS: 5.1 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

[CIS - Debian Linux - 5.1 - Network parameters - ICMP broadcasts accepted {CIS: 5.1 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

[CIS - Debian Linux - 5.2 - Network parameters - IP Forwarding enabled {CIS: 5.2 Debian Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;


# Section 7 - Permissions
[CIS - Debian Linux - 7.1 - Partition /var without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/var && !r:nodev;

[CIS - Debian Linux - 7.1 - Partition /tmp without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/tmp && !r:nodev;

[CIS - Debian Linux - 7.1 - Partition /opt without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/opt && !r:nodev;

[CIS - Debian Linux - 7.1 - Partition /home without 'nodev' set {CIS: 7.1 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/home && !r:nodev ;

[CIS - Debian Linux - 7.2 - Removable partition /media without 'nodev' set {CIS: 7.2 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

[CIS - Debian Linux - 7.2 - Removable partition /media without 'nosuid' set {CIS: 7.2 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

[CIS - Debian Linux - 7.3 - User-mounted removable partition /media {CIS: 7.3 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && r:user;


# Section 8 - Access and authentication
[CIS - Debian Linux - 8.8 - LILO Password not set {CIS: 8.8 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/lilo.conf -> !r:^# && !r:restricted;
f:/etc/lilo.conf -> !r:^# && !r:password=;

[CIS - Debian Linux - 8.8 - GRUB Password not set {CIS: 8.8 Debian Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/boot/grub/menu.lst -> !r:^# && !r:password;

[CIS - Debian Linux - 9.2 - Account with empty password present {CIS: 9.2 Debian Linux} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - Debian Linux - 13.11 - Non-root account with uid 0 {CIS: 13.11 Debian Linux} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;
!7614 cis_mysql5-6_community_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2017
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry , use "->" to look for a specific entry and another
# "->" to look for the value.
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for MYSQL 
# Based on Center for Internet Security Benchmark for MYSQL v1.1.0 
#
$home_dirs=/usr2/home/*,/home/*,/home,/*/home/*,/*/home,/;
$enviroment_files=/*/home/*/\.bashrc,/*/home/*/\.profile,/*/home/*/\.bash_profile,/home/*/\.bashrc,/home/*/\.profile,/home/*/\.bash_profile;
$mysql-cnfs=/etc/mysql/my.cnf,/etc/mysql/mariadb.cnf,/etc/mysql/conf.d/*.cnf,/etc/mysql/mariadb.conf.d/*.cnf,~/.my.cnf;
#
#
#1.3 Disable MySQL Command History
[CIS - MySQL Configuration - 1.3: Disable MySQL Command History] [any] [https://workbench.cisecurity.org/files/1310/download]
d:$home_dirs -> ^.mysql_history$;
#
#
#1.5 Disable Interactive Login
[CIS - MySQL Configuration - 1.5: Disable Interactive Login] [any] [https://workbench.cisecurity.org/files/1310/download]
f:/etc/passwd -> r:^mysql && !r:\.*/bin/false$|/sbin/nologin$;
#
#
#1.6 Verify That 'MYSQL_PWD' Is Not In Use
[CIS - MySQL Configuration - 1.6: 'MYSQL_PWD' Is in Use] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$enviroment_files -> r:\.*MYSQL_PWD\.*;
#
#
#4.3 Ensure 'allow-suspicious-udfs' Is Set to 'FALSE' 
[CIS - MySQL Configuration - 4.3: 'allow-suspicious-udfs' Is Set in my.cnf'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:allow-suspicious-udfs\.+true;
f:$mysql-cnfs -> r:allow-suspicious-udfs\s*$;
#
#
#4.4 Ensure 'local_infile' Is Disabled
[CIS - MySQL Configuration - 4.4: local_infile is not forbidden in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:local-infile\s*=\s*1;
f:$mysql-cnfs -> r:local-infile\s*$;
#
#
#4.5 Ensure 'mysqld' Is Not Started with '--skip-grant-tables'
[CIS - MySQL Configuration - 4.5: skip-grant-tables is set in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:skip-grant-tables\s*=\s*true;
f:$mysql-cnfs -> !r:skip-grant-tables\s*=\s*false;
f:$mysql-cnfs -> r:skip-grant-tables\s*$;
#
#
#4.6 Ensure '--skip-symbolic-links' Is Enabled
[CIS - MySQL Configuration - 4.6: skip_symbolic_links is not enabled in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:skip_symbolic_links\s*=\s*no;
f:$mysql-cnfs -> !r:skip_symbolic_links\s*=\s*yes;
f:$mysql-cnfs -> r:skip_symbolic_links\s*$;
#
#
#4.8 Ensure 'secure_file_priv' is not empty
[CIS - MySQL Configuration - 4.8: Ensure 'secure_file_priv' is not empty] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> r:^# && r:secure_file_priv=\s*\S+\s*;
f:$mysql-cnfs -> !r:secure_file_priv=\s*\S+\s*;
f:$mysql-cnfs -> r:secure_file_priv\s*$;
#
#
#4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES'
[CIS - MySQL Configuration - 4.9: strict_all_tables is not set at sql_mode section of my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:strict_all_tables\s*$;
#
#
#6.1 Ensure 'log_error' is not empty
[CIS - MySQL Configuration - 6.1: log-error is not set in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> r:^# && r:log_error\s*=\s*\S+\s*;
f:$mysql-cnfs -> !r:log_error\s*=\s*\S+\s*;
f:$mysql-cnfs -> r:log_error\s*$;
#
#
#6.2 Ensure Log Files are not Stored on a non-system partition
[CIS - MySQL Configuration - 6.2: log files are maybe stored on systempartition] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:log_bin= && !r:\s*/\S*\s*;
f:$mysql-cnfs -> !r:^# && r:log_bin= && !r:\s*/var/\S*\s*;
f:$mysql-cnfs -> !r:^# && r:log_bin= && !r:\s*/usr/\S*\s*;
f:$mysql-cnfs -> r:log_bin\s*$;
#
#
#6.3 Ensure 'log_warning' is set to 2 at least
[CIS - MySQL Configuration - 6.3: log warnings is set low] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:log_warnings\s*=\s*0;
f:$mysql-cnfs -> !r:^# && r:log_warnings\s*=\s*1;
f:$mysql-cnfs -> !r:log_warnings\s*=\s*\d+;
f:$mysql-cnfs -> r:log_warnings\s*$;
#
#
#6.5 Ensure 'log_raw' is set to 'off'
[CIS - MySQL Configuration - 6.5: log_raw is not set to off] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:log-raw\s*=\s*on;
f:$mysql-cnfs -> r:log-raw\s*$;
#
#
#7.1 Ensure 'old_password' is not set to '1' or 'On'
[CIS - MySQL Configuration - 7.1:Ensure 'old_passwords' is not set to '1' or 'on'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:old_passwords\s*=\s*1;
f:$mysql-cnfs -> !r:^# && r:old_passwords\s*=\s*on;
f:$mysql-cnfs -> !r:old_passwords\s*=\s*2;
f:$mysql-cnfs -> r:old_passwords\s*$;
#
#
#7.2 Ensure 'secure_auth' is set to 'ON'
[CIS - MySQL Configuration - 7.2: Ensure 'secure_auth' is set to 'ON'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:secure_auth\s*=\s*off;
f:$mysql-cnfs -> !r:secure_auth\s*=\s*on;
f:$mysql-cnfs -> r:secure_auth\s*$;
#
#
#7.3 Ensure Passwords Are Not Stored in the Global Configuration
[CIS - MySQL Configuration - 7.3: Passwords are stored in global configuration] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:^\s*password\.*;
#
#
#7.4 Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'
[CIS - MySQL Configuration - 7.4: Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:no_auto_create_user\s*$;
f:$mysql-cnfs -> r:^# && r:\s*no_auto_create_user\s*$;
#
#
#7.6 Ensure Password Policy is in Place
[CIS - MySQL Configuration - 7.6: Ensure Password Policy is in Place ] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:plugin-load\s*=\s*validate_password.so\s*$;
f:$mysql-cnfs -> !r:validate-password\s*=\s*force_plus_permanent\s*$;
f:$mysql-cnfs -> !r:validate_password_length\s*=\s*14\s$;
f:$mysql-cnfs -> !r:validate_password_mixed_case_count\s*=\s*1\s*$;
f:$mysql-cnfs -> !r:validate_password_number_count\s*=\s*1\s*$;
f:$mysql-cnfs -> !r:validate_password_special_char_count\s*=\s*1;
f:$mysql-cnfs -> !r:validate_password_policy\s*=\s*medium\s*;
#
#
#9.2 Ensure 'master_info_repository' is set to 'Table'
[CIS - MySQL Configuration - 9.2: Ensure 'master_info_repositrory' is set to 'Table'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:master_info_repository\s*=\s*file;
f:$mysql-cnfs -> !r:master_info_repository\s*=\s*table;
f:$mysql-cnfs -> r:master_info_repository\s*$;
!10302 cis_mysql5-6_enterprise_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2017
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry , use "->" to look for a specific entry and another
# "->" to look for the value.
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for MYSQL 
# Based on Center for Internet Security Benchmark for MYSQL v1.1.0 
#
$home_dirs=/usr2/home/*,/home/*,/home,/*/home/*,/*/home,/;
$enviroment_files=/*/home/*/\.bashrc,/*/home/*/\.profile,/*/home/*/\.bash_profile,/home/*/\.bashrc,/home/*/\.profile,/home/*/\.bash_profile;
$mysql-cnfs=/etc/mysql/my.cnf,/etc/mysql/mariadb.cnf,/etc/mysql/conf.d/*.cnf,/etc/mysql/mariadb.conf.d/*.cnf,~/.my.cnf;
#
#
#1.3 Disable MySQL Command History
[CIS - MySQL Configuration - 1.3: Disable MySQL Command History] [any] [https://workbench.cisecurity.org/files/1310/download]
d:$home_dirs -> ^.mysql_history$;
#
#
#1.5 Disable Interactive Login
[CIS - MySQL Configuration - 1.5: Disable Interactive Login] [any] [https://workbench.cisecurity.org/files/1310/download]
f:/etc/passwd -> r:^mysql && !r:\.*/bin/false$|/sbin/nologin$;
#
#
#1.6 Verify That 'MYSQL_PWD' Is Not In Use
[CIS - MySQL Configuration - 1.6: 'MYSQL_PWD' Is in Use] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$enviroment_files -> r:\.*MYSQL_PWD\.*;
#
#
#4.3 Ensure 'allow-suspicious-udfs' Is Set to 'FALSE' 
[CIS - MySQL Configuration - 4.3: 'allow-suspicious-udfs' Is Set in my.cnf'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:allow-suspicious-udfs\.+true;
f:$mysql-cnfs -> r:allow-suspicious-udfs\s*$;
#
#
#4.4 Ensure 'local_infile' Is Disabled
[CIS - MySQL Configuration - 4.4: local_infile is not forbidden in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:local-infile\s*=\s*1;
f:$mysql-cnfs -> r:local-infile\s*$;
#
#
#4.5 Ensure 'mysqld' Is Not Started with '--skip-grant-tables'
[CIS - MySQL Configuration - 4.5: skip-grant-tables is set in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:skip-grant-tables\s*=\s*true;
f:$mysql-cnfs -> !r:skip-grant-tables\s*=\s*false;
f:$mysql-cnfs -> r:skip-grant-tables\s*$;
#
#
#4.6 Ensure '--skip-symbolic-links' Is Enabled
[CIS - MySQL Configuration - 4.6: skip_symbolic_links is not enabled in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:skip_symbolic_links\s*=\s*no;
f:$mysql-cnfs -> !r:skip_symbolic_links\s*=\s*yes;
f:$mysql-cnfs -> r:skip_symbolic_links\s*$;
#
#
#4.8 Ensure 'secure_file_priv' is not empty
[CIS - MySQL Configuration - 4.8: Ensure 'secure_file_priv' is not empty] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> r:^# && r:secure_file_priv=\s*\S+\s*;
f:$mysql-cnfs -> !r:secure_file_priv=\s*\S+\s*;
f:$mysql-cnfs -> r:secure_file_priv\s*$;
#
#
#4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES'
[CIS - MySQL Configuration - 4.9: strict_all_tables is not set at sql_mode section of my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:strict_all_tables\s*$;
#
#
#6.1 Ensure 'log_error' is not empty
[CIS - MySQL Configuration - 6.1: log-error is not set in my.cnf] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> r:^# && r:log_error\s*=\s*\S+\s*;
f:$mysql-cnfs -> !r:log_error\s*=\s*\S+\s*;
f:$mysql-cnfs -> r:log_error\s*$;
#
#
#6.2 Ensure Log Files are not Stored on a non-system partition
[CIS - MySQL Configuration - 6.2: log files are maybe stored on systempartition] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:log_bin= && !r:\s*/\S*\s*;
f:$mysql-cnfs -> !r:^# && r:log_bin= && !r:\s*/var/\S*\s*;
f:$mysql-cnfs -> !r:^# && r:log_bin= && !r:\s*/usr/\S*\s*;
f:$mysql-cnfs -> r:log_bin\s*$;
#
#
#6.3 Ensure 'log_warning' is set to 2 at least
[CIS - MySQL Configuration - 6.3: log warnings is set low] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:log_warnings\s*=\s*0;
f:$mysql-cnfs -> !r:^# && r:log_warnings\s*=\s*1;
f:$mysql-cnfs -> !r:log_warnings\s*=\s*\d+;
f:$mysql-cnfs -> r:log_warnings\s*$;
#
#
#6.4 Ensure 'log_raw' is set to 'off'
[CIS - MySQL Configuration - 6.4: log_raw is not set to off] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:log-raw\s*=\s*on;
f:$mysql-cnfs -> r:log-raw\s*$;
#
#
#6.5 Ensure audit_log_connection_policy is not set to 'none'
[CIS - MySQL Configuration - 6.5: audit_log_connection_policy is set to 'none' change it to all or erros] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r^# && r::audit_log_connection_policy\s*=\s*none;
f:$mysql-cnfs -> r:audit_log_connection_policy\s*$;
#
#
#6.6 Ensure audit_log_exclude_account is set to Null
[CIS - MySQL Configuration - 6.6:audit_log_exclude_accounts is not set to Null] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:audit_log_exclude_accounts\s*=\s* && !r:null\s*$;
f:$mysql-cnfs -> r:audit_log_exclude_accounts\s*$;
#
#
#6.7 Ensure audit_log_include_accounts is set to Null
[CIS - MySQL Configuration - 6.7:audit_log_include_accounts is not set to Null] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:audit_log_include_accounts\s*=\s* && !r:null\s*$;
f:$mysql-cnfs -> r:audit_log_include_accounts\s*$;
#
#
#6.9 Ensure audit_log_policy is not set to all 
[CIS - MySQL Configuration - 6.9: audit_log_policy is not set to all] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:audit_log_policy\s*=\s*queries;
f:$mysql-cnfs -> !r:^# && r:audit_log_policy\s*=\s*none;
f:$mysql-cnfs -> !r:^# && r:audit_log_policy\s*=\s*logins;
f:$mysql-cnfs -> r:audit_log_policy\s*$;
#
#
#6.10 Ensure audit_log_statement_policy is set to all
[CIS - MySQL Configuration - 6.10: Ensure audit_log_statement_policy is set to all] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:audit_log_statement_policy\.+errors;
f:$mysql-cnfs -> !r:^# && r:audit_log_statement_policy\.+none;
f:$mysql-cnfs -> r:audit_log_statement_policy\s*$;
#
#
#6.11 Ensure audit_log_strategy is set to synchronous or semisynchronous
[CIS - MySQL Configuration - 6.11: Ensure audit_log_strategy is set to all] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:audit_log_strategy\.+asynchronous;
f:$mysql-cnfs -> !r:^# && r:audit_log_strategy\.+performance;
f:$mysql-cnfs -> !r:audit_log_strategy\s*=\s* && r:semisynchronous|synchronous;
f:$mysql-cnfs -> r:audit_log_strategy\s*$;
#
#
#6.12 Make sure the audit plugin can't be unloaded
[CIS - MySQL Configuration - 6.12: Audit plugin can be unloaded] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:^audit_log\s*=\s*on\s*;
f:$mysql-cnfs -> !r:^# && r:^audit_log\s*=\s*off\s*;
f:$mysql-cnfs -> !r:^# && r:^audit_log\s*=\s*force\s*;
f:$mysql-cnfs -> !r:^audit_log\s*=\s*force_plus_permanent\s*;
f:$mysql-cnfs -> r:^audit_log\s$;
#
#
#7.1 Ensure 'old_password' is not set to '1' or 'On'
[CIS - MySQL Configuration - 7.1:Ensure 'old_passwords' is not set to '1' or 'on'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:old_passwords\s*=\s*1;
f:$mysql-cnfs -> !r:^# && r:old_passwords\s*=\s*on;
f:$mysql-cnfs -> !r:old_passwords\s*=\s*2;
f:$mysql-cnfs -> r:old_passwords\s*$;
#
#
#7.2 Ensure 'secure_auth' is set to 'ON'
[CIS - MySQL Configuration - 7.2: Ensure 'secure_auth' is set to 'ON'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:secure_auth\s*=\s*off;
f:$mysql-cnfs -> !r:secure_auth\s*=\s*on;
f:$mysql-cnfs -> r:secure_auth\s*$;
#
#
#7.3 Ensure Passwords Are Not Stored in the Global Configuration
[CIS - MySQL Configuration - 7.3: Passwords are stored in global configuration] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:^\s*password\.*;
#
#
#7.4 Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'
[CIS - MySQL Configuration - 7.4: Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:no_auto_create_user\s*$;
f:$mysql-cnfs -> r:^# && r:\s*no_auto_create_user\s*$;
#
#
#7.6 Ensure Password Policy is in Place
[CIS - MySQL Configuration - 7.6: Ensure Password Policy is in Place ] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:plugin-load\s*=\s*validate_password.so\s*$;
f:$mysql-cnfs -> !r:validate-password\s*=\s*force_plus_permanent\s*$;
f:$mysql-cnfs -> !r:validate_password_length\s*=\s*14\s$;
f:$mysql-cnfs -> !r:validate_password_mixed_case_count\s*=\s*1\s*$;
f:$mysql-cnfs -> !r:validate_password_number_count\s*=\s*1\s*$;
f:$mysql-cnfs -> !r:validate_password_special_char_count\s*=\s*1;
f:$mysql-cnfs -> !r:validate_password_policy\s*=\s*medium\s*;
#
#
#9.2 Ensure 'master_info_repository' is set to 'Table'
[CIS - MySQL Configuration - 9.2: Ensure 'master_info_repositrory' is set to 'Table'] [any] [https://workbench.cisecurity.org/files/1310/download]
f:$mysql-cnfs -> !r:^# && r:master_info_repository\s*=\s*file;
f:$mysql-cnfs -> !r:master_info_repository\s*=\s*table;
f:$mysql-cnfs -> r:master_info_repository\s*$;
!35786 cis_rhel5_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2014
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).


# CIS Checks for Red Hat / CentOS 5
# Based on CIS Benchmark for Red Hat Enterprise Linux 5 v2.1.0

# TODO: URL is invalid currently

# RC scripts location
$rc_dirs=/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d;


[CIS - Testing against the CIS Red Hat Enterprise Linux 5 Benchmark v2.1.0] [any required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/redhat-release -> r:^Red Hat Enterprise Linux \S+ release 5;
f:/etc/redhat-release -> r:^CentOS && r:release 5;
f:/etc/redhat-release -> r:^Cloud && r:release 5;
f:/etc/redhat-release -> r:^Oracle && r:release 5;
f:/etc/redhat-release -> r:^Better && r:release 5;


# 1.1.1 /tmp: partition
[CIS - RHEL5 - - Build considerations - Robust partition scheme - /tmp is not on its own partition {CIS: 1.1.1 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:/tmp;

# 1.1.2 /tmp: nodev
[CIS - RHEL5 - 1.1.2 - Partition /tmp without 'nodev' set {CIS: 1.1.2 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 1.1.3 /tmp: nosuid
[CIS - RHEL5 - 1.1.3 - Partition /tmp without 'nosuid' set {CIS: 1.1.3 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nosuid;

# 1.1.4 /tmp: noexec
[CIS - RHEL5 - 1.1.4 - Partition /tmp without 'noexec' set {CIS: 1.1.4 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 1.1.5 Build considerations - Partition scheme.
[CIS - RHEL5 - - Build considerations - Robust partition scheme - /var is not on its own partition {CIS: 1.1.5 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r^# && !r:/var;

# 1.1.6 bind mount /var/tmp to /tmp
[CIS - RHEL5 - - Build considerations - Robust partition scheme - /var/tmp is bound to /tmp {CIS: 1.1.6 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> r:^# && !r:/var/tmp && !r:bind;

# 1.1.7 /var/log: partition
[CIS - RHEL5 - - Build considerations - Robust partition scheme - /var/log is not on its own partition {CIS: 1.1.7 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log;

# 1.1.8 /var/log/audit: partition
[CIS - RHEL5 - - Build considerations - Robust partition scheme - /var/log/audit is not on its own partition {CIS: 1.1.8 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log/audit;

# 1.1.9 /home: partition
[CIS - RHEL5 - - Build considerations - Robust partition scheme - /home is not on its own partition {CIS: 1.1.9 Debian RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> ^# && !r:/home;

# 1.1.10 /home: nodev
[CIS - RHEL5 - 1.1.10 -  Partition /home without 'nodev' set {CIS: 1.1.10 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/home && !r:nodev;

# 1.1.11 nodev on removable media partitions (not scored)
[CIS - RHEL5 - 1.1.11 - Removable partition /media without 'nodev' set {CIS: 1.1.11 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

# 1.1.12 noexec on removable media partitions (not scored)
[CIS - RHEL5 - 1.1.12 - Removable partition /media without 'noexec' set {CIS: 1.1.12 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:noexec;

# 1.1.13 nosuid on removable media partitions (not scored)
[CIS - RHEL5 - 1.1.13 - Removable partition /media without 'nosuid' set {CIS: 1.1.13 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

# 1.1.14 /dev/shm: nodev
[CIS - RHEL5 - 1.1.11 - /dev/shm without 'nodev' set {CIS: 1.1.14 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nodev;

# 1.1.15 /dev/shm: nosuid
[CIS - RHEL5 - 1.1.11 - /dev/shm without 'nosuid' set {CIS: 1.1.15 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nosuid;

# 1.1.16 /dev/shm: noexec
[CIS - RHEL5 - 1.1.11 - /dev/shm without 'noexec' set {CIS: 1.1.16 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;

# 1.1.17 sticky bit on world writable directories (Scored)
# TODO

# 1.1.18 disable cramfs (not scored)

# 1.1.19 disable freevxfs (not scored)

# 1.1.20 disable jffs2 (not scored)

# 1.1.21 disable hfs (not scored)

# 1.1.22 disable hfsplus (not scored)

# 1.1.23 disable squashfs (not scored)

# 1.1.24 disable udf (not scored)


##########################################
# 1.2 Software Updates
##########################################

# 1.2.1 Configure rhn updates (not scored)

# 1.2.2 verify  RPM gpg keys  (Scored)
# TODO

# 1.2.3 verify gpgcheck enabled (Scored)
# TODO

# 1.2.4 Disable rhnsd (not scored)

# 1.2.5 Disable yum-updatesd (Scored)
[CIS - RHEL5 - 1.2.5 - yum-updatesd not Disabled {CIS: 1.2.5 RHEL5} {PCI_DSS: 6.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;
p:yum-updatesd;

# 1.2.6 Obtain updates with yum (not scored)

# 1.2.7 Verify package integrity (not scored)


###############################################
# 1.3 Advanced Intrusion Detection Environment
###############################################
#
# Skipped, this control is obsoleted by OSSEC
#


###############################################
# 1.4 Configure SELinux
###############################################

# 1.4.1 enable selinux in /etc/grub.conf
[CIS - RHEL5 - 1.4.1 - SELinux Disabled in /etc/grub.conf {CIS: 1.4.1 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/grub.conf -> !r:selinux=0;

# 1.4.2 Set selinux state
[CIS - RHEL5 - 1.4.2 - SELinux not set to enforcing {CIS: 1.4.2 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/selinux/config -> r:SELINUX=enforcing;

# 1.4.3 Set seliux policy
[CIS - RHEL5 - 1.4.3 - SELinux policy not set to targeted {CIS: 1.4.3 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/selinux/config -> r:SELINUXTYPE=targeted;

# 1.4.4 Remove SETroubleshoot
[CIS - RHEL5 - 1.4.4 - SELinux setroubleshoot enabled {CIS: 1.4.4 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dsetroubleshoot$;

# 1.4.5 Disable MCS Translation service mcstrans
[CIS - RHEL5 - 1.4.5 - SELinux mctrans enabled {CIS: 1.4.5 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dmctrans$;

# 1.4.6 Check for unconfined daemons
# TODO


###############################################
# 1.5  Secure Boot Settings
###############################################

# 1.5.1 Set User/Group Owner on /etc/grub.conf
# TODO (no mode tests)

# 1.5.2 Set Permissions on /etc/grub.conf (Scored)
# TODO (no mode tests)

# 1.5.3 Set Boot Loader Password (Scored)
[CIS - RHEL5 - 1.5.3 - GRUB Password not set {CIS: 1.5.3 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/boot/grub/menu.lst -> !r:^# && !r:password;

# 1.5.4 Require Authentication for Single-User Mode (Scored)
[CIS - RHEL5 - 1.5.4 - Authentication for single user mode not enabled {CIS: 1.5.4 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/inittab -> !r:^# && r:S:wait;

# 1.5.5 Disable Interactive Boot (Scored)
[CIS - RHEL5 - 1.5.5 - Interactive Boot not disabled {CIS: 1.5.5 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/sysconfig/init -> !r:^# && r:PROMPT=no;



###############################################
# 1.6  Additional Process Hardening
###############################################

# 1.6.1 Restrict Core Dumps (Scored)
[CIS - RHEL5 - 1.6.1 - Interactive Boot not disabled {CIS: 1.6.1 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/security/limits.conf -> !r:^# && !r:hard\.+core\.+0;

# 1.6.2 Configure ExecShield (Scored)
[CIS - RHEL5 - 1.6.2 - ExecShield not enabled  {CIS: 1.6.2 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/kernel/exec-shield -> 0;

# 1.6.3 Enable Randomized Virtual Memory Region Placement (Scored)
[CIS - RHEL5 - 1.6.3 - Randomized Virtual Memory Region Placement not enabled  {CIS: 1.6.3 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/kernel/randomize_va_space -> 0;

# 1.6.4 Enable XD/NX Support on 32-bit x86 Systems (Scored)
# TODO

# 1.6.5 Disable Prelink (Scored)
[CIS - RHEL5 - 1.6.5 - Prelink not disabled {CIS: 1.6.5 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/sysconfig/prelink -> !r:PRELINKING=no;


###############################################
# 1.7  Use the Latest OS Release
###############################################


###############################################
# 2 OS Services
###############################################

###############################################
# 2.1 Remove Legacy Services
###############################################

# 2.1.1 Remove telnet-server (Scored)
# TODO: detect it is installed at all
[CIS - RHEL5 - 2.1.1 - Telnet enabled on xinetd {CIS: 2.1.1 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/telnet -> !r:^# && r:disable && r:no;


# 2.1.2 Remove telnet Clients (Scored)
# TODO

# 2.1.3 Remove rsh-server (Scored)
[CIS - RHEL5 - 2.1.3 - rsh/rlogin/rcp enabled on xinetd {CIS: 2.1.3 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/rlogin -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/rsh -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/shell -> !r:^# && r:disable && r:no;

# 2.1.4 Remove rsh (Scored)
# TODO

# 2.1.5 Remove NIS Client (Scored)
[CIS - RHEL5 - 2.1.5 - Disable standard boot services - NIS (client) Enabled {CIS: 2.1.5 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dypbind$;

# 2.1.6 Remove NIS Server (Scored)
[CIS - RHEL5 - 2.1.5 - Disable standard boot services - NIS (server) Enabled {CIS: 2.1.6 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dypserv$;

# 2.1.7 Remove tftp (Scored)
# TODO

# 2.1.8 Remove tftp-server (Scored)
[CIS - RHEL5 - 2.1.8 - tftpd enabled on xinetd {CIS: 2.1.8 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/tftpd -> !r:^# && r:disable && r:no;

# 2.1.9 Remove talk (Scored)
# TODO

# 2.1.10 Remove talk-server (Scored)
[CIS - RHEL5 - 2.1.10 - talk enabled on xinetd {CIS: 2.1.10 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/talk -> !r:^# && r:disable && r:no;

# 2.1.11 Remove xinetd (Scored)
# TODO

# 2.1.12 Disable chargen-dgram (Scored)
# TODO

# 2.1.13 Disable chargen-stream (Scored)
# TODO

# 2.1.14 Disable daytime-dgram (Scored)
# TODO

# 2.1.15 Disable daytime-stream (Scored)
# TODO

# 2.1.16 Disable echo-dgram (Scored)
# TODO

# 2.1.17 Disable echo-stream (Scored)
# TODO

# 2.1.18 Disable tcpmux-server (Scored)
# TODO


###############################################
# 3 Special Purpose Services
###############################################

###############################################
# 3.1 Disable Avahi Server
###############################################

# 3.1.1 Disable Avahi Server (Scored)
[CIS - RHEL5 - 3.1.1 - Avahi daemon not disabled {CIS: 3.1.1 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
p:avahi-daemon;

# 3.1.2 Service Only via Required Protocol (Not Scored)
# TODO

# 3.1.3 Check Responses TTL Field (Scored)
# TODO

# 3.1.4 Prevent Other Programs from Using Avahi’s Port (Not Scored)
# TODO

# 3.1.5 Disable Publishing (Not Scored)

# 3.1.6 Restrict Published Information (if publishing is required) (Not scored)

# 3.2 Set Daemon umask (Scored)
[CIS - RHEL5 - 3.2 - Set daemon umask - Default umask is higher than 027 {CIS: 3.2 RHEL5}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/init.d/functions -> !r:^# && r:^umask && <:umask 027;

# 3.3 Remove X Windows (Scored)
[CIS - RHEL5 - 3.3 - X11 not disabled {CIS: 3.3 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/inittab -> !r:^# && r:id:5;

# 3.4 Disable Print Server - CUPS (Not Scored)

# 3.5 Remove DHCP Server (Not Scored)
# TODO

# 3.6 Configure Network Time Protocol (NTP) (Scored)
#[CIS - RHEL5 - 3.6 - NTPD not disabled {CIS: 3.6 RHEL5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
# TODO.

# 3.7 Remove LDAP (Not Scored)

# 3.8 Disable NFS and RPC (Not Scored)
[CIS - RHEL5 - 3.8 - Disable standard boot services - NFS Enabled {CIS: 3.8 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dnfs$;
d:$rc_dirs -> ^S\d\dnfslock$;

# 3.9 Remove DNS Server (Not Scored)
# TODO

# 3.10 Remove FTP Server (Not Scored)
[CIS - RHEL5 - 3.10 - VSFTP enabled on xinetd {CIS: 3.10 RHEL5} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/vsftpd -> !r:^# && r:disable && r:no;

# 3.11 Remove HTTP Server (Not Scored)
[CIS - RHEL5 - 3.11 - Disable standard boot services - Apache web server Enabled {CIS: 3.11 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dhttpd$;

# 3.12 Remove Dovecot (IMAP and POP3 services) (Not Scored)
[CIS - RHEL5 - 3.12 - imap enabled on xinetd {CIS: 3.12 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/cyrus-imapd -> !r:^# && r:disable && r:no;

[CIS - RHEL5 - 3.12 - pop3 enabled on xinetd {CIS: 3.12 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/xinetd.d/dovecot -> !r:^# && r:disable && r:no;

# 3.13 Remove Samba (Not Scored)
[CIS - RHEL5 - 3.13 - Disable standard boot services - Samba Enabled {CIS: 3.13 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dsamba$;
d:$rc_dirs -> ^S\d\dsmb$;

# 3.14 Remove HTTP Proxy Server (Not Scored)
[CIS - RHEL5 - 3.14 - Disable standard boot services - Squid Enabled {CIS: 3.14 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dsquid$;

# 3.15 Remove SNMP Server (Not Scored)
[CIS - RHEL5 - 3.15 - Disable standard boot services - SNMPD process Enabled {CIS: 3.15 RHEL5} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dsnmpd$;

# 3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)
# TODO


###############################################
# 4 Network Configuration and Firewalls
###############################################

###############################################
# 4.1 Modify Network Parameters (Host Only)
###############################################

# 4.1.1 Disable IP Forwarding (Scored)
[CIS - RHEL5 - 4.1.1 - Network parameters - IP Forwarding enabled {CIS: 4.1.1 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;

# 4.1.2 Disable Send Packet Redirects (Scored)
[CIS - RHEL5 - 4.1.2 - Network parameters - IP send redirects enabled {CIS: 4.1.2 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/send_redirects -> 0;
f:/proc/sys/net/ipv4/conf/default/send_redirects -> 0;


###############################################
# 4.2 Modify Network Parameters (Host and Router)
###############################################

# 4.2.1 Disable Source Routed Packet Acceptance (Scored)
[CIS - RHEL5 - 4.2.1 - Network parameters - Source routing accepted {CIS: 4.2.1 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

# 4.2.2 Disable ICMP Redirect Acceptance (Scored)
[CIS - RHEL5 - 4.2.2 - Network parameters - ICMP redirects accepted {CIS: 4.2.2 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/accept_redirects -> 1;

# 4.2.3 Disable Secure ICMP Redirect Acceptance (Scored)
[CIS - RHEL5 - 4.2.3 - Network parameters - ICMP secure redirects accepted {CIS: 4.2.3 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/secure_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/secure_redirects -> 1;

# 4.2.4 Log Suspicious Packets (Scored)
[CIS - RHEL5 - 4.2.4 - Network parameters - martians not logged {CIS: 4.2.4 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/log_martians -> 0;

# 4.2.5 Enable Ignore Broadcast Requests (Scored)
[CIS - RHEL5 - 4.2.5 - Network parameters - ICMP broadcasts accepted {CIS: 4.2.5 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

# 4.2.6 Enable Bad Error Message Protection (Scored)
[CIS - RHEL5 - 4.2.6 - Network parameters - Bad error message protection not enabled {CIS: 4.2.6 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses -> 0;

# 4.2.7 Enable RFC-recommended Source Route Validation (Scored)
[CIS - RHEL5 - 4.2.7 - Network parameters - RFC Source route validation not enabled  {CIS: 4.2.7 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/rp_filter -> 0;
f:/proc/sys/net/ipv4/conf/default/rp_filter -> 0;

# 4.2.8 Enable TCP SYN Cookies (Scored)
[CIS - RHEL5 - 4.2.8 - Network parameters - SYN Cookies not enabled  {CIS: 4.2.8 RHEL5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/proc/sys/net/ipv4/tcp_syncookies -> 0;


###############################################
# 4.3 Wireless Networking
###############################################

# 4.3.1 Deactivate Wireless Interfaces (Not Scored)


###############################################
# 4.4 Disable ipv6
###############################################

###############################################
# 4.4.1 Configure IPv6
###############################################

# 4.4.1.1 Disable IPv6 Router Advertisements (Not Scored)

# 4.4.1.2 Disable IPv6 Redirect Acceptance (Not Scored)

# 4.4.2 Disable IPv6 (Not Scored)


###############################################
# 4.5 Install TCP Wrappers
###############################################

# 4.5.1 Install TCP Wrappers (Not Scored)

# 4.5.2 Create /etc/hosts.allow (Not Scored)

# 4.5.3 Verify Permissions on /etc/hosts.allow (Scored)
# TODO

# 4.5.4 Create /etc/hosts.deny (Not Scored)

# 4.5.5 Verify Permissions on /etc/hosts.deny (Scored)
# TODO


###############################################
# 4.6 Uncommon Network Protocols
###############################################

# 4.6.1 Disable DCCP (Not Scored)

# 4.6.2 Disable SCTP (Not Scored)

# 4.6.3 Disable RDS (Not Scored)

# 4.6.4 Disable TIPC (Not Scored)

# 4.7 Enable IPtables (Scored)
# TODO

# 4.8 Enable IP6tables (Not Scored)


###############################################
# 5 Logging and Auditing
###############################################

###############################################
# 5.1 Configure Syslog
###############################################

# 5.1.1 Configure /etc/syslog.conf (Not Scored)

# 5.1.2 Create and Set Permissions on syslog Log Files (Scored)

# 5.1.3 Configure syslog to Send Logs to a Remote Log Host (Scored)

# 5.1.4 Accept Remote syslog Messages Only on Designated Log Hosts (Not Scored)


###############################################
# 5.2 Configure rsyslog
###############################################

# 5.2.1 Install the rsyslog package (Not Scored)

# 5.2.2 Activate the rsyslog Service (Not Scored)

# 5.2.3 Configure /etc/rsyslog.conf (Not Scored)

# 5.2.4 Create and Set Permissions on rsyslog Log Files (Not Scored)

# 5.2.5 Configure rsyslog to Send Logs to a Remote Log Host (Not Scored)

# 5.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)


###############################################
# 5.3 Configure System Accounting (auditd)
###############################################

###############################################
# 5.3.1 Configure Data Retention
###############################################

# 5.3.1.1 Configure Audit Log Storage Size (Not Scored)

# 5.3.1.2 Disable System on Audit Log Full (Not Scored)

# 5.3.1.3 Keep All Auditing Information (Scored)

# 5.3.2 Enable auditd Service (Scored)

# 5.3.3 Configure Audit Log Storage Size (Not Scored)

# 5.3.4 Disable System on Audit Log Full (Not Scored)

# 5.3.5 Keep All Auditing Information (Scored)

# 5.3.6 Enable Auditing for Processes That Start Prior to auditd (Scored)

# 5.3.7 Record Events That Modify Date and Time Information (Scored)

# 5.3.8 Record Events That Modify User/Group Information (Scored)

# 5.3.9 Record Events That Modify the System’s Network Environment (Scored)

# 5.3.10 Record Events That Modify the System’s Mandatory Access Controls (Scored)

# 5.3.11 Collect Login and Logout Events (Scored)

# 5.3.12 Collect Session Initiation Information (Scored)

# 5.3.13 Collect Discretionary Access Control Permission Modification Events (Scored)

# 5.3.14 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)

# 5.3.15 Collect Use of Privileged Commands (Scored)

# 5.3.16 Collect Successful File System Mounts (Scored)

# 5.3.17 Collect File Deletion Events by User (Scored)

# 5.3.18 Collect Changes to System Administration Scope (sudoers) (Scored)

# 5.3.19 Collect System Administrator Actions (sudolog) (Scored)

# 5.3.20 Collect Kernel Module Loading and Unloading (Scored)

# 5.3.21 Make the Audit Configuration Immutable (Scored)

# 5.4 Configure logrotate (Not Scored)


###############################################
# 6 System Access, Authentication and Authorization
###############################################

###############################################
# 6.1 Configure cron and anacron
###############################################

# 6.1.1 Enable anacron Daemon (Scored)

# 6.1.2 Enable cron Daemon (Scored)

# 6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)

# 6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)

# 6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)

# 6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)

# 6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)

# 6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)

# 6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)

# 6.1.10 Restrict at Daemon (Scored)

# 6.1.11 Restrict at/cron to Authorized Users (Scored)

###############################################
# 6.1 Configure SSH
###############################################

# 6.2.1 Set SSH Protocol to 2 (Scored)
[CIS - RHEL5 - 6.2.1 - SSH Configuration - Protocol version 1 enabled {CIS: 6.2.1 RHEL5} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

# 6.2.2 Set LogLevel to INFO (Scored)

# 6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)

# 6.2.4 Disable SSH X11 Forwarding (Scored)

# 6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)

# 6.2.6 Set SSH IgnoreRhosts to Yes (Scored)
[CIS - RHEL5 - 6.2.6 - SSH Configuration - IgnoreRHosts disabled {CIS: 6.2.6 RHEL5} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

# 6.2.7 Set SSH HostbasedAuthentication to No (Scored)
[CIS - RHEL5 - 6.2.7 - SSH Configuration - Host based authentication enabled {CIS: 6.2.7 RHEL5} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

# 6.2.8 Disable SSH Root Login (Scored)
[CIS - RHEL5 - 6.2.8 - SSH Configuration - Root login allowed {CIS: 6.2.8 RHEL5} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;

# 6.2.9 Set SSH PermitEmptyPasswords to No (Scored)
[CIS - RHEL5 - 6.2.9 - SSH Configuration - Empty passwords permitted {CIS: 6.2.9 RHEL5} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;

# 6.2.10 Do Not Allow Users to Set Environment Options (Scored)

# 6.2.11 Use Only Approved Ciphers in Counter Mode (Scored)

# 6.2.12 Set Idle Timeout Interval for User Login (Not Scored)

# 6.2.13 Limit Access via SSH (Scored)

# 6.2.14 Set SSH Banner (Scored)

# 6.2.15 Enable SSH UsePrivilegeSeparation (Scored)


###############################################
# 6.3 Configure PAM
###############################################

# 6.3.1 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)

# 6.3.2 Set Lockout for Failed Password Attempts (Not Scored)

# 6.3.3 Use pam_deny.so to Deny Services (Not Scored)

# 6.3.4 Upgrade Password Hashing Algorithm to SHA-512 (Scored)

# 6.3.5 Limit Password Reuse (Scored)

# 6.3.6 Remove the pam_ccreds Package (Scored)

# 6.4 Restrict root Login to System Console (Not Scored)

# 6.5 Restrict Access to the su Command (Scored)


###############################################
# 7 User Accounts and Environment
###############################################

###############################################
# 7.1 Set Shadow Password Suite Parameters (/etc/login.defs)
###############################################

# 7.1.1 Set Password Expiration Days (Scored)

# 7.1.2 Set Password Change Minimum Number of Days (Scored)

# 7.1.3 Set Password Expiring Warning Days (Scored)

# 7.2 Disable System Accounts (Scored)

# 7.3 Set Default Group for root Account (Scored)

# 7.4 Set Default umask for Users (Scored)

# 7.5 Lock Inactive User Accounts (Scored)


###############################################
# 8 Warning Banners
###############################################

###############################################
# 8.1 Warning Banners for Standard Login Services
###############################################

# 8.1.1 Set Warning Banner for Standard Login Services (Scored)

# 8.1.2 Remove OS Information from Login Warning Banners (Scored)

# 8.2 Set GNOME Warning Banner (Not Scored)


###############################################
# 9 System Maintenance
###############################################

###############################################
# 9.1 Verify System File Permissions
###############################################

# 9.1.1 Verify System File Permissions (Not Scored)

# 9.1.2 Verify Permissions on /etc/passwd (Scored)

# 9.1.3 Verify Permissions on /etc/shadow (Scored)

# 9.1.4 Verify Permissions on /etc/gshadow (Scored)

# 9.1.5 Verify Permissions on /etc/group (Scored)

# 9.1.6 Verify User/Group Ownership on /etc/passwd (Scored)

# 9.1.7 Verify User/Group Ownership on /etc/shadow (Scored)

# 9.1.8 Verify User/Group Ownership on /etc/gshadow (Scored)

# 9.1.9 Verify User/Group Ownership on /etc/group (Scored)

# 9.1.10 Find World Writable Files (Not Scored)

# 9.1.11 Find Un-owned Files and Directories (Scored)

# 9.1.12 Find Un-grouped Files and Directories (Scored)

# 9.1.13 Find SUID System Executables (Not Scored)

# 9.1.14 Find SGID System Executables (Not Scored)


###############################################
# 9.2 Review User and Group Settings
###############################################

# 9.2.1 Ensure Password Fields are Not Empty (Scored)

# 9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)

# 9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)

# 9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)

# 9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
[CIS - RHEL5 - 9.2.5 - Non-root account with uid 0 {CIS: 9.2.5 RHEL5} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;

# 9.2.6 Ensure root PATH Integrity (Scored)

# 9.2.7 Check Permissions on User Home Directories (Scored)

# 9.2.8 Check User Dot File Permissions (Scored)

# 9.2.9 Check Permissions on User .netrc Files (Scored)

# 9.2.10 Check for Presence of User .rhosts Files (Scored)

# 9.2.11 Check Groups in /etc/passwd (Scored)

# 9.2.12 Check That Users Are Assigned Home Directories (Scored)

# 9.2.13 Check That Defined Home Directories Exist (Scored)

# 9.2.14 Check User Home Directory Ownership (Scored)

# 9.2.15 Check for Duplicate UIDs (Scored)

# 9.2.16 Check for Duplicate GIDs (Scored)

# 9.2.17 Check That Reserved UIDs Are Assigned to System Accounts

# 9.2.18 Check for Duplicate User Names (Scored)

# 9.2.19 Check for Duplicate Group Names (Scored)

# 9.2.20 Check for Presence of User .netrc Files (Scored)

# 9.2.21 Check for Presence of User .forward Files (Scored)

# Other/Legacy Tests
[CIS - RHEL5 - X.X.X - Account with empty password present  {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - RHEL5 - X.X.X - User-mounted removable partition allowed on the console] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
f:/etc/security/console.perms -> r:^<console>  \d+ <cdrom>;
f:/etc/security/console.perms -> r:^<console>  \d+ <floppy>;

[CIS - RHEL5 - X.X.X - Disable standard boot services - Kudzu hardware detection Enabled] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dkudzu$;

[CIS - RHEL5 - X.X.X - Disable standard boot services - PostgreSQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dpostgresql$;

[CIS - RHEL5 - X.X.X - Disable standard boot services - MySQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dmysqld$;

[CIS - RHEL5 - X.X.X - Disable standard boot services - DNS server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dnamed$;

[CIS - RHEL5 - X.X.X - Disable standard boot services - NetFS Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf]
d:$rc_dirs -> ^S\d\dnetfs$;
!33875 cis_rhel6_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2014
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).


# CIS Checks for Red Hat / CentOS 6
# Based on CIS Benchmark for Red Hat Enterprise Linux 6 v1.3.0

# RC scripts location
$rc_dirs=/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d;


[CIS - Testing against the CIS Red Hat Enterprise Linux 5 Benchmark v2.1.0] [any required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/redhat-release -> r:^Red Hat Enterprise Linux \S+ release 6;
f:/etc/redhat-release -> r:^CentOS && r:release 6;
f:/etc/redhat-release -> r:^Cloud && r:release 6;
f:/etc/redhat-release -> r:^Oracle && r:release 6;
f:/etc/redhat-release -> r:^Better && r:release 6;

# 1.1.1 /tmp: partition
[CIS - RHEL6 - Build considerations - Robust partition scheme - /tmp is not on its own partition] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:/tmp;

# 1.1.2 /tmp: nodev
[CIS - RHEL6 - 1.1.2 - Partition /tmp without 'nodev' set {CIS: 1.1.2 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 1.1.3 /tmp: nosuid
[CIS - RHEL6 - 1.1.3 - Partition /tmp without 'nosuid' set {CIS: 1.1.3 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nosuid;

# 1.1.4 /tmp: noexec
[CIS - RHEL6 - 1.1.4 - Partition /tmp without 'noexec' set {CIS: 1.1.4 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 1.1.5 Build considerations - Partition scheme.
[CIS - RHEL6 - Build considerations - Robust partition scheme - /var is not on its own partition {CIS: 1.1.5 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r^# && !r:/var;

# 1.1.6 bind mount /var/tmp to /tmp
[CIS - RHEL6 - Build considerations - Robust partition scheme - /var/tmp is bound to /tmp {CIS: 1.1.6 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> r:^# && !r:/var/tmp && !r:bind;

# 1.1.7 /var/log: partition
[CIS - RHEL6 - Build considerations - Robust partition scheme - /var/log is not on its own partition {CIS: 1.1.7 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log;

# 1.1.8 /var/log/audit: partition
[CIS - RHEL6 - Build considerations - Robust partition scheme - /var/log/audit is not on its own partition {CIS: 1.1.8 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log/audit;

# 1.1.9 /home: partition
[CIS - RHEL6 - Build considerations - Robust partition scheme - /home is not on its own partition {CIS: 1.1.9 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> ^# && !r:/home;

# 1.1.10 /home: nodev
[CIS - RHEL6 - 1.1.10 -  Partition /home without 'nodev' set {CIS: 1.1.10 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/home && !r:nodev;

# 1.1.11 nodev on removable media partitions (not scored)
[CIS - RHEL6 - 1.1.11 - Removable partition /media without 'nodev' set {CIS: 1.1.11 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

# 1.1.12 noexec on removable media partitions (not scored)
[CIS - RHEL6 - 1.1.12 - Removable partition /media without 'noexec' set {CIS: 1.1.12 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:noexec;

# 1.1.13 nosuid on removable media partitions (not scored)
[CIS - RHEL6 - 1.1.13 - Removable partition /media without 'nosuid' set {CIS: 1.1.13 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

# 1.1.14 /dev/shm: nodev
[CIS - RHEL6 - 1.1.14 - /dev/shm without 'nodev' set {CIS: 1.1.14 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nodev;

# 1.1.15 /dev/shm: nosuid
[CIS - RHEL6 - 1.1.15 - /dev/shm without 'nosuid' set {CIS: 1.1.15 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nosuid;

# 1.1.16 /dev/shm: noexec
[CIS - RHEL6 - 1.1.16 - /dev/shm without 'noexec' set {CIS: 1.1.16 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;

# 1.1.17 sticky bit on world writable directories (Scored)
# TODO

# 1.1.18 disable cramfs (not scored)

# 1.1.19 disable freevxfs (not scored)

# 1.1.20 disable jffs2 (not scored)

# 1.1.21 disable hfs (not scored)

# 1.1.22 disable hfsplus (not scored)

# 1.1.23 disable squashfs (not scored)

# 1.1.24 disable udf (not scored)


##########################################
# 1.2 Software Updates
##########################################

# 1.2.1 Configure rhn updates (not scored)

# 1.2.2 verify  RPM gpg keys  (Scored)
# TODO

# 1.2.3 verify gpgcheck enabled (Scored)
# TODO

# 1.2.4 Disable rhnsd (not scored)

# 1.2.5 Obtain Software Package Updates with yum (Not Scored)

# 1.2.6 Obtain updates with yum (not scored)


###############################################
# 1.3 Advanced Intrusion Detection Environment
###############################################
#
# Skipped, this control is obsoleted by OSSEC
#

###############################################
# 1.4 Configure SELinux
###############################################

# 1.4.1 enable selinux in /etc/grub.conf
[CIS - RHEL6 - 1.4.1 - SELinux Disabled in /etc/grub.conf {CIS: 1.4.1 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/grub.conf -> !r:selinux=0;

# 1.4.2 Set selinux state
[CIS - RHEL6 - 1.4.2 - SELinux not set to enforcing {CIS: 1.4.2 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/selinux/config -> r:SELINUX=enforcing;

# 1.4.3 Set seliux policy
[CIS - RHEL6 - 1.4.3 - SELinux policy not set to targeted {CIS: 1.4.3 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/selinux/config -> r:SELINUXTYPE=targeted;

# 1.4.4 Remove SETroubleshoot
[CIS - RHEL6 - 1.4.4 - SELinux setroubleshoot enabled {CIS: 1.4.4 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dsetroubleshoot$;

# 1.4.5 Disable MCS Translation service mcstrans
[CIS - RHEL6 - 1.4.5 - SELinux mctrans enabled {CIS: 1.4.5 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dmctrans$;

# 1.4.6 Check for unconfined daemons
# TODO


###############################################
# 1.5  Secure Boot Settings
###############################################

# 1.5.1 Set User/Group Owner on /etc/grub.conf
# TODO (no mode tests)

# 1.5.2 Set Permissions on /etc/grub.conf (Scored)
# TODO (no mode tests)

# 1.5.3 Set Boot Loader Password (Scored)
[CIS - RHEL6 - 1.5.3 - GRUB Password not set {CIS: 1.5.3 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/boot/grub/menu.lst -> !r:^# && !r:password;

# 1.5.4 Require Authentication for Single-User Mode (Scored)
[CIS - RHEL6 - 1.5.4 - Authentication for single user mode not enabled {CIS: 1.5.4 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/inittab -> !r:^# && r:S:wait;

# 1.5.5 Disable Interactive Boot (Scored)
[CIS - RHEL6 - 1.5.5 - Interactive Boot not disabled {CIS: 1.5.5 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/sysconfig/init -> !r:^# && r:PROMPT=no;


###############################################
# 1.6  Additional Process Hardening
###############################################

# 1.6.1 Restrict Core Dumps (Scored)
[CIS - RHEL6 - 1.6.1 - Interactive Boot not disabled {CIS: 1.6.1 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/security/limits.conf -> !r:^# && !r:hard\.+core\.+0;

# 1.6.2 Configure ExecShield (Scored)
[CIS - RHEL6 - 1.6.2 - ExecShield not enabled  {CIS: 1.6.2 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/kernel/exec-shield -> 0;

# 1.6.3 Enable Randomized Virtual Memory Region Placement (Scored)
[CIS - RHEL6 - 1.6.3 - Randomized Virtual Memory Region Placement not enabled  {CIS: 1.6.3 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/kernel/randomize_va_space -> 0;


###############################################
# 1.7  Use the Latest OS Release  (Not Scored)
###############################################


###############################################
# 2 OS Services
###############################################

###############################################
# 2.1 Remove Legacy Services
###############################################

# 2.1.1 Remove telnet-server (Scored)
# TODO: detect it is installed at all
[CIS - RHEL6 - 2.1.1 - Telnet enabled on xinetd {CIS: 2.1.1 RHEL6} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/telnet -> !r:^# && r:disable && r:no;


# 2.1.2 Remove telnet Clients (Scored)
# TODO

# 2.1.3 Remove rsh-server (Scored)
[CIS - RHEL6 - 2.1.3 - rsh/rlogin/rcp enabled on xinetd {CIS: 2.1.3 RHEL6} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/rlogin -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/rsh -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/shell -> !r:^# && r:disable && r:no;

# 2.1.4 Remove rsh (Scored)
# TODO

# 2.1.5 Remove NIS Client (Scored)
[CIS - RHEL6 - 2.1.5 - Disable standard boot services - NIS (client) Enabled {CIS: 2.1.5 RHEL6} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dypbind$;

# 2.1.6 Remove NIS Server (Scored)
[CIS - RHEL6 - 2.1.6 - Disable standard boot services - NIS (server) Enabled {CIS: 2.1.6 RHEL6} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dypserv$;

# 2.1.7 Remove tftp (Scored)
# TODO

# 2.1.8 Remove tftp-server (Scored)
[CIS - RHEL6 - 2.1.8 - tftpd enabled on xinetd {CIS: 2.1.8 RHEL6} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/tftpd -> !r:^# && r:disable && r:no;

# 2.1.9 Remove talk (Scored)
# TODO

# 2.1.10 Remove talk-server (Scored)
[CIS - RHEL6 - 2.1.10 - talk enabled on xinetd {CIS: 2.1.10 RHEL6} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/talk -> !r:^# && r:disable && r:no;

# 2.1.11 Remove xinetd (Scored)
# TODO

# 2.1.12 Disable chargen-dgram (Scored)
# TODO

# 2.1.13 Disable chargen-stream (Scored)
# TODO

# 2.1.14 Disable daytime-dgram (Scored)
# TODO

# 2.1.15 Disable daytime-stream (Scored)
# TODO

# 2.1.16 Disable echo-dgram (Scored)
# TODO

# 2.1.17 Disable echo-stream (Scored)
# TODO

# 2.1.18 Disable tcpmux-server (Scored)
# TODO


###############################################
# 3 Special Purpose Services
###############################################

# 3.1 Set Daemon umask (Scored)
[CIS - RHEL6 - 3.1 - Set daemon umask - Default umask is higher than 027 {CIS: 3.1 RHEL6} {PCI_DSS: 2.2.2}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/init.d/functions -> !r:^# && r:^umask && <:umask 027;

# 3.2 Remove X Windows (Scored)
[CIS - RHEL6 - 3.2 - X11 not disabled {CIS: 3.2 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/inittab -> !r:^# && r:id:5;

# 3.3 Disable Avahi Server (Scored)
[CIS - RHEL6 - 3.2 - Avahi daemon not disabled {CIS: 3.3 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
p:avahi-daemon;

# 3.4 Disable Print Server - CUPS (Not Scored)

# 3.5 Remove DHCP Server (Not Scored)
# TODO

# 3.6 Configure Network Time Protocol (NTP) (Scored)
#[CIS - RHEL6 - 3.6 - NTPD not disabled {CIS: 1.1.1 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
# TODO.

# 3.7 Remove LDAP (Not Scored)

# 3.8 Disable NFS and RPC (Not Scored)
[CIS - RHEL6 - 3.8 - Disable standard boot services - NFS Enabled {CIS: 3.8 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dnfs$;
d:$rc_dirs -> ^S\d\dnfslock$;

# 3.9 Remove DNS Server (Not Scored)
# TODO

# 3.10 Remove FTP Server (Not Scored)
[CIS - RHEL6 - 3.10 - VSFTP enabled on xinetd {CIS: 3.10 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/vsftpd -> !r:^# && r:disable && r:no;

# 3.11 Remove HTTP Server (Not Scored)
[CIS - RHEL6 - 3.11 - Disable standard boot services - Apache web server Enabled {CIS: 3.11 RHEL6}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dhttpd$;

# 3.12 Remove Dovecot (IMAP and POP3 services) (Not Scored)
[CIS - RHEL6 - 3.12 - imap enabled on xinetd {CIS: 3.12 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/cyrus-imapd -> !r:^# && r:disable && r:no;

[CIS - RHEL6 - 3.12 - pop3 enabled on xinetd {CIS: 3.12 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/xinetd.d/dovecot -> !r:^# && r:disable && r:no;

# 3.13 Remove Samba (Not Scored)
[CIS - RHEL6 - 3.13 - Disable standard boot services - Samba Enabled {CIS: 3.13 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dsamba$;
d:$rc_dirs -> ^S\d\dsmb$;

# 3.14 Remove HTTP Proxy Server (Not Scored)
[CIS - RHEL6 - 3.14 - Disable standard boot services - Squid Enabled {CIS: 3.14 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dsquid$;

# 3.15 Remove SNMP Server (Not Scored)
[CIS - RHEL6 - 3.15 - Disable standard boot services - SNMPD process Enabled {CIS: 3.15 RHEL6} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dsnmpd$;

# 3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)
# TODO


###############################################
# 4 Network Configuration and Firewalls
###############################################

###############################################
# 4.1 Modify Network Parameters (Host Only)
###############################################

# 4.1.1 Disable IP Forwarding (Scored)
[CIS - RHEL6 - 4.1.1 - Network parameters - IP Forwarding enabled {CIS: 4.1.1 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;

# 4.1.2 Disable Send Packet Redirects (Scored)
[CIS - RHEL6 - 4.1.2 - Network parameters - IP send redirects enabled {CIS: 4.1.2 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/conf/all/send_redirects -> 0;
f:/proc/sys/net/ipv4/conf/default/send_redirects -> 0;


###############################################
# 4.2 Modify Network Parameters (Host and Router)
###############################################

# 4.2.1 Disable Source Routed Packet Acceptance (Scored)
[CIS - RHEL6 - 4.2.1 - Network parameters - Source routing accepted {CIS: 4.2.1 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

# 4.2.2 Disable ICMP Redirect Acceptance (Scored)
#[CIS - RHEL6 - 4.2.2 - Network parameters - ICMP redirects accepted {CIS: 1.1.1 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
#f:/proc/sys/net/ipv4/conf/all/accept_redirects -> 1;
#f:/proc/sys/net/ipv4/conf/default/accept_redirects -> 1;

# 4.2.3 Disable Secure ICMP Redirect Acceptance (Scored)
[CIS - RHEL6 - 4.2.3 - Network parameters - ICMP secure redirects accepted {CIS: 4.2.3 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/conf/all/secure_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/secure_redirects -> 1;

# 4.2.4 Log Suspicious Packets (Scored)
[CIS - RHEL6 - 4.2.4 - Network parameters - martians not logged {CIS: 4.2.4 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/conf/all/log_martians -> 0;

# 4.2.5 Enable Ignore Broadcast Requests (Scored)
[CIS - RHEL6 - 4.2.5 - Network parameters - ICMP broadcasts accepted {CIS: 4.2.5 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

# 4.2.6 Enable Bad Error Message Protection (Scored)
[CIS - RHEL6 - 4.2.6 - Network parameters - Bad error message protection not enabled {CIS: 4.2.6 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses -> 0;

# 4.2.7 Enable RFC-recommended Source Route Validation (Scored)
[CIS - RHEL6 - 4.2.7 - Network parameters - RFC Source route validation not enabled  {CIS: 4.2.7 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/conf/all/rp_filter -> 0;
f:/proc/sys/net/ipv4/conf/default/rp_filter -> 0;

# 4.2.8 Enable TCP SYN Cookies (Scored)
[CIS - RHEL6 - 4.2.8 - Network parameters - SYN Cookies not enabled {CIS: 4.2.8 RHEL6} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/proc/sys/net/ipv4/tcp_syncookies -> 0;


###############################################
# 4.3 Wireless Networking
###############################################

# 4.3.1 Deactivate Wireless Interfaces (Not Scored)


###############################################
# 4.4 Disable ipv6
###############################################

###############################################
# 4.4.1 Configure IPv6
###############################################

# 4.4.1.1 Disable IPv6 Router Advertisements (Not Scored)

# 4.4.1.2 Disable IPv6 Redirect Acceptance (Not Scored)

# 4.4.2 Disable IPv6 (Not Scored)


###############################################
# 4.5 Install TCP Wrappers
###############################################

# 4.5.1 Install TCP Wrappers (Not Scored)

# 4.5.2 Create /etc/hosts.allow (Not Scored)

# 4.5.3 Verify Permissions on /etc/hosts.allow (Scored)
# TODO

# 4.5.4 Create /etc/hosts.deny (Not Scored)

# 4.5.5 Verify Permissions on /etc/hosts.deny (Scored)
# TODO


###############################################
# 4.6 Uncommon Network Protocols
###############################################

# 4.6.1 Disable DCCP (Not Scored)

# 4.6.2 Disable SCTP (Not Scored)

# 4.6.3 Disable RDS (Not Scored)

# 4.6.4 Disable TIPC (Not Scored)

# 4.7 Enable IPtables (Scored)
# TODO

# 4.8 Enable IP6tables (Not Scored)


###############################################
# 5 Logging and Auditing
###############################################

###############################################
# 5.1 Configure Syslog
###############################################

# 5.1.1 Install the rsyslog package (Scored)
# TODO

# 5.1.2 Activate the rsyslog Service (Scored)
# TODO

# 5.1.3 Configure /etc/rsyslog.conf (Not Scored)

# 5.1.4 Create and Set Permissions on rsyslog Log Files (Scored)

# 5.1.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)

# 5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)


###############################################
# 5.2 Configure System Accounting (auditd)
###############################################

###############################################
# 5.2.1 Configure Data Retention
###############################################

# 5.2.1.1 Configure Audit Log Storage Size (Not Scored)

# 5.2.1.2 Disable System on Audit Log Full (Not Scored)

# 5.2.1.3 Keep All Auditing Information (Scored)

# 5.2.2 Enable auditd Service (Scored)

# 5.2.3 Enable Auditing for Processes That Start Prior to auditd (Scored)

# 5.2.4 Record Events That Modify Date and Time Information (Scored)

# 5.2.5 Record Events That Modify User/Group Information (Scored)

# 5.2.6 Record Events That Modify the System’s Network Environment (Scored)

# 5.2.7 Record Events That Modify the System’s Mandatory Access Controls (Scored)

# 5.2.8 Collect Login and Logout Events (Scored)

# 5.2.9 Collect Session Initiation Information (Scored)

# 5.2.10 Collect Discretionary Access Control Permission Modification Events (Scored)

# 5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)

# 5.2.12 Collect Use of Privileged Commands (Scored)

# 5.2.13 Collect Successful File System Mounts (Scored)

# 5.2.14 Collect File Deletion Events by User (Scored)

# 5.2.15 Collect Changes to System Administration Scope (sudoers) (Scored)

# 5.2.16 Collect System Administrator Actions (sudolog) (Scored)

# 5.2.17 Collect Kernel Module Loading and Unloading (Scored)

# 5.2.18 Make the Audit Configuration Immutable (Scored)

# 5.3 Configure logrotate (Not Scored)


###############################################
# 6 System Access, Authentication and Authorization
###############################################

###############################################
# 6.1 Configure cron and anacron
###############################################

# 6.1.1 Enable anacron Daemon (Scored)

# 6.1.2 Enable cron Daemon (Scored)

# 6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)

# 6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)

# 6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)

# 6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)

# 6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)

# 6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)

# 6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)

# 6.1.10 Restrict at Daemon (Scored)

# 6.1.11 Restrict at/cron to Authorized Users (Scored)

###############################################
# 6.1 Configure SSH
###############################################

# 6.2.1 Set SSH Protocol to 2 (Scored)
[CIS - RHEL6 - 6.2.1 - SSH Configuration - Protocol version 1 enabled {CIS: 6.2.1 RHEL6} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

# 6.2.2 Set LogLevel to INFO (Scored)

# 6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)

# 6.2.4 Disable SSH X11 Forwarding (Scored)

# 6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)

# 6.2.6 Set SSH IgnoreRhosts to Yes (Scored)
[CIS - RHEL6 - 6.2.6 - SSH Configuration - IgnoreRHosts disabled {CIS: 6.2.6 RHEL6} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

# 6.2.7 Set SSH HostbasedAuthentication to No (Scored)
[CIS - RHEL6 - 6.2.7 - SSH Configuration - Host based authentication enabled {CIS: 6.2.7 RHEL6} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

# 6.2.8 Disable SSH Root Login (Scored)
[CIS - RHEL6 - 6.2.8 - SSH Configuration - Root login allowed {CIS: 6.2.8 RHEL6} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;

# 6.2.9 Set SSH PermitEmptyPasswords to No (Scored)
[CIS - RHEL6 - 6.2.9 - SSH Configuration - Empty passwords permitted {CIS: 6.2.9 RHEL6} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;

# 6.2.10 Do Not Allow Users to Set Environment Options (Scored)

# 6.2.11 Use Only Approved Ciphers in Counter Mode (Scored)

# 6.2.12 Set Idle Timeout Interval for User Login (Not Scored)

# 6.2.13 Limit Access via SSH (Scored)

# 6.2.14 Set SSH Banner (Scored)


###############################################
# 6.3 Configure PAM
###############################################

# 6.3.1 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)

# 6.3.2 Set Lockout for Failed Password Attempts (Not Scored)

# 6.3.3 Use pam_deny.so to Deny Services (Not Scored)

# 6.3.4 Upgrade Password Hashing Algorithm to SHA-512 (Scored)

# 6.3.5 Limit Password Reuse (Scored)

# 6.4 Restrict root Login to System Console (Not Scored)

# 6.5 Restrict Access to the su Command (Scored)


###############################################
# 7 User Accounts and Environment
###############################################

###############################################
# 7.1 Set Shadow Password Suite Parameters (/etc/login.defs)
###############################################

# 7.1.1 Set Password Expiration Days (Scored)

# 7.1.2 Set Password Change Minimum Number of Days (Scored)

# 7.1.3 Set Password Expiring Warning Days (Scored)

# 7.2 Disable System Accounts (Scored)

# 7.3 Set Default Group for root Account (Scored)

# 7.4 Set Default umask for Users (Scored)

# 7.5 Lock Inactive User Accounts (Scored)


###############################################
# 8 Warning Banners
###############################################

###############################################
# 8.1 Warning Banners for Standard Login Services
###############################################

# 8.1 Set Warning Banner for Standard Login Services (Scored)

# 8.2 Remove OS Information from Login Warning Banners (Scored)

# 8.3 Set GNOME Warning Banner (Not Scored)


###############################################
# 9 System Maintenance
###############################################

###############################################
# 9.1 Verify System File Permissions
###############################################

# 9.1.1 Verify System File Permissions (Not Scored)

# 9.1.2 Verify Permissions on /etc/passwd (Scored)

# 9.1.3 Verify Permissions on /etc/shadow (Scored)

# 9.1.4 Verify Permissions on /etc/gshadow (Scored)

# 9.1.5 Verify Permissions on /etc/group (Scored)

# 9.1.6 Verify User/Group Ownership on /etc/passwd (Scored)

# 9.1.7 Verify User/Group Ownership on /etc/shadow (Scored)

# 9.1.8 Verify User/Group Ownership on /etc/gshadow (Scored)

# 9.1.9 Verify User/Group Ownership on /etc/group (Scored)

# 9.1.10 Find World Writable Files (Not Scored)

# 9.1.11 Find Un-owned Files and Directories (Scored)

# 9.1.12 Find Un-grouped Files and Directories (Scored)

# 9.1.13 Find SUID System Executables (Not Scored)

# 9.1.14 Find SGID System Executables (Not Scored)


###############################################
# 9.2 Review User and Group Settings
###############################################

# 9.2.1 Ensure Password Fields are Not Empty (Scored)

# 9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)

# 9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)

# 9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)

# 9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
[CIS - RHEL6 - 9.2.5 - Non-root account with uid 0 {CIS: 9.2.5 RHEL6} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;

# 9.2.6 Ensure root PATH Integrity (Scored)

# 9.2.7 Check Permissions on User Home Directories (Scored)

# 9.2.8 Check User Dot File Permissions (Scored)

# 9.2.9 Check Permissions on User .netrc Files (Scored)

# 9.2.10 Check for Presence of User .rhosts Files (Scored)

# 9.2.11 Check Groups in /etc/passwd (Scored)

# 9.2.12 Check That Users Are Assigned Valid Home Directories (Scored)

# 9.2.13 Check User Home Directory Ownership (Scored)

# 9.2.14 Check for Duplicate UIDs (Scored)

# 9.2.15 Check for Duplicate GIDs (Scored)

# 9.2.16 Check for Duplicate User Names (Scored)

# 9.2.17 Check for Duplicate Group Names (Scored)

# 9.2.18 Check for Presence of User .netrc Files (Scored)

# 9.2.19 Check for Presence of User .forward Files (Scored)


# Other/Legacy Tests
[CIS - RHEL6 - X.X.X - Account with empty password present {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - RHEL6 - X.X.X - User-mounted removable partition allowed on the console] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
f:/etc/security/console.perms -> r:^<console>  \d+ <cdrom>;
f:/etc/security/console.perms -> r:^<console>  \d+ <floppy>;

[CIS - RHEL6 - X.X.X - Disable standard boot services - Kudzu hardware detection Enabled] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dkudzu$;

[CIS - RHEL6 - X.X.X - Disable standard boot services - PostgreSQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dpostgresql$;

[CIS - RHEL6 - X.X.X - Disable standard boot services - MySQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dmysqld$;

[CIS - RHEL6 - X.X.X - Disable standard boot services - DNS server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dnamed$;

[CIS - RHEL6 - X.X.X - Disable standard boot services - NetFS Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.3.0.pdf]
d:$rc_dirs -> ^S\d\dnetfs$;
!36962 cis_rhel7_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2014
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).


# CIS Checks for Red Hat / CentOS 7
# Based on CIS Benchmark for Red Hat Enterprise Linux 7 v1.1.0

# Vars
$sshd_file=/etc/ssh/sshd_config;

# RC scripts location
$rc_dirs=/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d;


[CIS - Testing against the CIS Red Hat Enterprise Linux 7 Benchmark v1.1.0] [any required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/redhat-release -> r:^Red Hat Enterprise Linux \S+ release 7;
f:/etc/redhat-release -> r:^CentOS && r:release 7;
f:/etc/redhat-release -> r:^Cloud && r:release 7;
f:/etc/redhat-release -> r:^Oracle && r:release 7;
f:/etc/redhat-release -> r:^Better && r:release 7;
f:/etc/redhat-release -> r:^OpenVZ && r:release 7;

# 1.1.1 /tmp: partition
[CIS - RHEL7 - Build considerations - Robust partition scheme - /tmp is not on its own partition] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:/tmp;

# 1.1.2 /tmp: nodev
[CIS - RHEL7 - 1.1.2 - Partition /tmp without 'nodev' set {CIS: 1.1.2 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 1.1.3 /tmp: nosuid
[CIS - RHEL7 - 1.1.3 - Partition /tmp without 'nosuid' set {CIS: 1.1.3 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nosuid;

# 1.1.4 /tmp: noexec
[CIS - RHEL7 - 1.1.4 - Partition /tmp without 'noexec' set {CIS: 1.1.4 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:noexec;

# 1.1.5 Build considerations - Partition scheme.
[CIS - RHEL7 - Build considerations - Robust partition scheme - /var is not on its own partition {CIS: 1.1.5 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r^# && !r:/var;

# 1.1.6 bind mount /var/tmp to /tmp
[CIS - RHEL7 - Build considerations - Robust partition scheme - /var/tmp is bound to /tmp {CIS: 1.1.6 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && !r:/var/tmp;

# 1.1.7 /var/log: partition
[CIS - RHEL7 - Build considerations - Robust partition scheme - /var/log is not on its own partition {CIS: 1.1.7 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && !r:/var/log;

# 1.1.8 /var/log/audit: partition
[CIS - RHEL7 - Build considerations - Robust partition scheme - /var/log/audit is not on its own partition {CIS: 1.1.8 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && !r:/var/log/audit;

# 1.1.9 /home: partition
[CIS - RHEL7 - Build considerations - Robust partition scheme - /home is not on its own partition {CIS: 1.1.9 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && !r:/home;

# 1.1.10 /home: nodev
[CIS - RHEL7 - 1.1.10 -  Partition /home without 'nodev' set {CIS: 1.1.10 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/home && !r:nodev;

# 1.1.11 nodev on removable media partitions (not scored)
[CIS - RHEL7 - 1.1.11 - Removable partition /media without 'nodev' set {CIS: 1.1.11 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

# 1.1.12 noexec on removable media partitions (not scored)
[CIS - RHEL7 - 1.1.12 - Removable partition /media without 'noexec' set {CIS: 1.1.12 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:noexec;

# 1.1.13 nosuid on removable media partitions (not scored)
[CIS - RHEL7 - 1.1.13 - Removable partition /media without 'nosuid' set {CIS: 1.1.13 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

# 1.1.14 /dev/shm: nodev
[CIS - RHEL7 - 1.1.14 - /dev/shm without 'nodev' set {CIS: 1.1.14 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nodev;

# 1.1.15 /dev/shm: nosuid
[CIS - RHEL7 - 1.1.15 - /dev/shm without 'nosuid' set {CIS: 1.1.15 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nosuid;

# 1.1.16 /dev/shm: noexec
[CIS - RHEL7 - 1.1.16 - /dev/shm without 'noexec' set {CIS: 1.1.16 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;

# 1.1.17 sticky bit on world writable directories (Scored)
# TODO

# 1.1.18 disable cramfs (not scored)

# 1.1.19 disable freevxfs (not scored)

# 1.1.20 disable jffs2 (not scored)

# 1.1.21 disable hfs (not scored)

# 1.1.22 disable hfsplus (not scored)

# 1.1.23 disable squashfs (not scored)

# 1.1.24 disable udf (not scored)


##########################################
# 1.2 Software Updates
##########################################

# 1.2.1 Configure rhn updates (not scored)

# 1.2.2 verify  RPM gpg keys  (Scored)
# TODO

# 1.2.3 verify gpgcheck enabled (Scored)
# TODO

# 1.2.4 Disable rhnsd (not scored)

# 1.2.5 Obtain Software Package Updates with yum (Not Scored)

# 1.2.6 Obtain updates with yum (not scored)


###############################################
# 1.3 Advanced Intrusion Detection Environment
###############################################
#
# Skipped, this control is obsoleted by OSSEC
#

###############################################
# 1.4 Configure SELinux
###############################################

# 1.4.1 enable selinux in /etc/grub.conf
[CIS - RHEL7 - 1.4.1 - SELinux Disabled in /etc/grub.conf {CIS: 1.4.1 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/grub.conf -> r:selinux=0;
f:/etc/grub2.cfg -> r:selinux=0;

# 1.4.2 Set selinux state
[CIS - RHEL7 - 1.4.2 - SELinux not set to enforcing {CIS: 1.4.2 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/selinux/config -> !r:SELINUX=enforcing;

# 1.4.3 Set seliux policy
[CIS - RHEL7 - 1.4.3 - SELinux policy not set to targeted {CIS: 1.4.3 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/selinux/config -> !r:SELINUXTYPE=targeted;

# 1.4.4 Remove SETroubleshoot
[CIS - RHEL7 - 1.4.4 - SELinux setroubleshoot enabled {CIS: 1.4.4 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsetroubleshoot$;
f:/usr/share/dbus-1/services/sealert.service -> r:Exec=/usr/bin/sealert;

# 1.4.5 Disable MCS Translation service mcstrans
[CIS - RHEL7 - 1.4.5 - SELinux mctrans enabled {CIS: 1.4.5 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dmctrans$;
f:/usr/lib/systemd/system/mcstransd.service -> r:ExecStart=/usr/sbin/mcstransd;

# 1.4.6 Check for unconfined daemons
# TODO


###############################################
# 1.5  Secure Boot Settings
###############################################

# 1.5.1 Set User/Group Owner on /etc/grub.conf
# TODO (no mode tests)
# stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"

# 1.5.2 Set Permissions on /etc/grub.conf (Scored)
# TODO (no mode tests)
#  stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"

# 1.5.3 Set Boot Loader Password (Scored)
[CIS - RHEL7 - 1.5.3 - GRUB Password not set {CIS: 1.5.3 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/boot/grub2/grub.cfg -> !r:^# && !r:password;



###############################################
# 1.6  Additional Process Hardening
###############################################

# 1.6.1 Restrict Core Dumps (Scored)
[CIS - RHEL7 - 1.6.1 - Interactive Boot not disabled {CIS: 1.6.1 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/security/limits.conf -> !r:^# && !r:hard\.+core\.+0;

# 1.6.1 Enable Randomized Virtual Memory Region Placement (Scored)
# Note this is also labeled 1.6.1 in the CIS benchmark.
[CIS - RHEL7 - 1.6.1 - Randomized Virtual Memory Region Placement not enabled  {CIS: 1.6.3 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/kernel/randomize_va_space -> !r:^2$;


###############################################
# 1.7  Use the Latest OS Release  (Not Scored)
###############################################


###############################################
# 2 OS Services
###############################################

###############################################
# 2.1 Remove Legacy Services
###############################################

# 2.1.1 Remove telnet-server (Scored)
# TODO: detect it is installed at all
[CIS - RHEL7 - 2.1.1 - Telnet enabled on xinetd {CIS: 2.1.1 RHEL7} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/telnet -> !r:^# && r:disable && r:no;
f:/usr/lib/systemd/system/telnet@.service -> r:ExecStart=-/usr/sbin/in.telnetd;


# 2.1.2 Remove telnet Clients (Scored)
# TODO

# 2.1.3 Remove rsh-server (Scored)
[CIS - RHEL7 - 2.1.3 - rsh/rlogin/rcp enabled on xinetd {CIS: 2.1.3 RHEL7} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/rlogin -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/rsh -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/shell -> !r:^# && r:disable && r:no;
# TODO (finish this)
f:/usr/lib/systemd/system/rexec@.service -> r:ExecStart;
f:/usr/lib/systemd/system/rlogin@.service -> r:ExecStart;
f:/usr/lib/systemd/system/rsh@.service -> r:ExecStart;

# 2.1.4 Remove rsh (Scored)
# TODO

# 2.1.5 Remove NIS Client (Scored)
[CIS - RHEL7 - 2.1.5 - Disable standard boot services - NIS (client) Enabled {CIS: 2.1.5 RHEL7} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dypbind$;
f:/usr/lib/systemd/system/ypbind.service -> r:Exec;

# 2.1.6 Remove NIS Server (Scored)
[CIS - RHEL7 - 2.1.6 - Disable standard boot services - NIS (server) Enabled {CIS: 2.1.6 RHEL7} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dypserv$;
f:/usr/lib/systemd/system/ypserv.service -> r:Exec;

# 2.1.7 Remove tftp (Scored)
# TODO

# 2.1.8 Remove tftp-server (Scored)
[CIS - RHEL7 - 2.1.8 - tftpd enabled on xinetd {CIS: 2.1.8 RHEL7} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/tftpd -> !r:^# && r:disable && r:no;
f:/usr/lib/systemd/system/tftp.service -> r:Exec;

# 2.1.9 Remove talk (Scored)
# TODO

# 2.1.10 Remove talk-server (Scored)
[CIS - RHEL7 - 2.1.10 - talk enabled on xinetd {CIS: 2.1.10 RHEL7} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/talk -> !r:^# && r:disable && r:no;
f:/usr/lib/systemd/system/ntalk.service -> r:Exec;

# 2.1.11 Remove xinetd (Scored)
[CIS - RHEL7 - 2.1.11 -  xinetd detected {CIS: 2.1.11 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/usr/lib/systemd/system/xinetd.service -> r:Exec;

# 2.1.12 Disable chargen-dgram (Scored)
[CIS - RHEL7 - 2.1.12 -  chargen-dgram enabled on xinetd {CIS: 2.1.12 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/chargen-dgram -> !r:^# && r:disable && r:no;

# 2.1.13 Disable chargen-stream (Scored)
[CIS - RHEL7 - 2.1.13 -  chargen-stream enabled on xinetd {CIS: 2.1.13 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/chargen-stream -> !r:^# && r:disable && r:no;

# 2.1.14 Disable daytime-dgram (Scored)
[CIS - RHEL7 - 2.1.14 -  daytime-dgram enabled on xinetd {CIS: 2.1.14 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/daytime-dgram -> !r:^# && r:disable && r:no;

# 2.1.15 Disable daytime-stream (Scored)
[CIS - RHEL7 - 2.1.15 -  daytime-stream enabled on xinetd {CIS: 2.1.15 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/daytime-stream -> !r:^# && r:disable && r:no;


# 2.1.16 Disable echo-dgram (Scored)
[CIS - RHEL7 - 2.1.16 -  echo-dgram enabled on xinetd {CIS: 2.1.16 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/echo-dgram -> !r:^# && r:disable && r:no;

# 2.1.17 Disable echo-stream (Scored)
[CIS - RHEL7 - 2.1.17 -  echo-stream enabled on xinetd {CIS: 2.1.17 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/echo-stream -> !r:^# && r:disable && r:no;

# 2.1.18 Disable tcpmux-server (Scored)
[CIS - RHEL7 - 2.1.18 -  tcpmux-server enabled on xinetd {CIS: 2.1.18 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/tcpmux-server -> !r:^# && r:disable && r:no;


###############################################
# 3 Special Purpose Services
###############################################

# 3.1 Set Daemon umask (Scored)
[CIS - RHEL7 - 3.1 - Set daemon umask - Default umask is higher than 027 {CIS: 3.1 RHEL7} {PCI_DSS: 2.2.2}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/sysconfig/init -> !r:^# && r:^umask && <:umask 027;

# 3.2 Remove X Windows (Scored)
[CIS - RHEL7 - 3.2 - X11 not disabled {CIS: 3.2 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
p:gdm-x-session;

# 3.3 Disable Avahi Server (Scored)
[CIS - RHEL7 - 3.2 - Avahi daemon not disabled {CIS: 3.3 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
p:avahi-daemon;

# 3.4 Disable Print Server - CUPS (Not Scored)

# 3.5 Remove DHCP Server (Scored)
[CIS - RHEL7 - 3.5 - DHCPnot disabled {CIS: 3.5 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/usr/lib/systemd/system/dhcpd.service -> r:Exec;

# 3.6 Configure Network Time Protocol (NTP) (Scored)
[CIS - RHEL7 - 3.6 - NTPD not Configured {CIS: 3.6 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/ntp.conf -> r:restrict default kod nomodify notrap nopeer noquery && r:^server;
f:/etc/sysconfig/ntpd -> r:OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid";

# 3.7 Remove LDAP (Not Scored)

# 3.8 Disable NFS and RPC (Not Scored)
[CIS - RHEL7 - 3.8 - Disable standard boot services - NFS Enabled {CIS: 3.8 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dnfs$;
d:$rc_dirs -> ^S\d\dnfslock$;

# 3.9 Remove DNS Server (Not Scored)
# TODO

# 3.10 Remove FTP Server (Not Scored)
[CIS - RHEL7 - 3.10 - VSFTP enabled on xinetd {CIS: 3.10 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/vsftpd -> !r:^# && r:disable && r:no;

# 3.11 Remove HTTP Server (Not Scored)
[CIS - RHEL7 - 3.11 - Disable standard boot services - Apache web server Enabled {CIS: 3.11 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dhttpd$;

# 3.12 Remove Dovecot (IMAP and POP3 services) (Not Scored)
[CIS - RHEL7 - 3.12 - imap enabled on xinetd {CIS: 3.12 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/cyrus-imapd -> !r:^# && r:disable && r:no;

[CIS - RHEL7 - 3.12 - pop3 enabled on xinetd {CIS: 3.12 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/dovecot -> !r:^# && r:disable && r:no;

# 3.13 Remove Samba (Not Scored)
[CIS - RHEL7 - 3.13 - Disable standard boot services - Samba Enabled {CIS: 3.13 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsamba$;
d:$rc_dirs -> ^S\d\dsmb$;

# 3.14 Remove HTTP Proxy Server (Not Scored)
[CIS - RHEL7 - 3.14 - Disable standard boot services - Squid Enabled {CIS: 3.14 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsquid$;

# 3.15 Remove SNMP Server (Not Scored)
[CIS - RHEL7 - 3.15 - Disable standard boot services - SNMPD process Enabled {CIS: 3.15 RHEL7} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsnmpd$;

# 3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)
# TODO


###############################################
# 4 Network Configuration and Firewalls
###############################################

###############################################
# 4.1 Modify Network Parameters (Host Only)
###############################################

# 4.1.1 Disable IP Forwarding (Scored)
[CIS - RHEL7 - 4.1.1 - Network parameters - IP Forwarding enabled {CIS: 4.1.1 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;

# 4.1.2 Disable Send Packet Redirects (Scored)
[CIS - RHEL7 - 4.1.2 - Network parameters - IP send redirects enabled {CIS: 4.1.2 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/send_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/send_redirects -> 1;


###############################################
# 4.2 Modify Network Parameters (Host and Router)
###############################################

# 4.2.1 Disable Source Routed Packet Acceptance (Scored)
[CIS - RHEL7 - 4.2.1 - Network parameters - Source routing accepted {CIS: 4.2.1 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

# 4.2.2 Disable ICMP Redirect Acceptance (Scored)
[CIS - RHEL7 - 4.2.2 - Network parameters - ICMP redirects accepted {CIS: 1.1.1 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/accept_redirects -> 1;

# 4.2.3 Disable Secure ICMP Redirect Acceptance (Scored)
[CIS - RHEL7 - 4.2.3 - Network parameters - ICMP secure redirects accepted {CIS: 4.2.3 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/secure_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/secure_redirects -> 1;

# 4.2.4 Log Suspicious Packets (Scored)
[CIS - RHEL7 - 4.2.4 - Network parameters - martians not logged {CIS: 4.2.4 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/log_martians -> 0;

# 4.2.5 Enable Ignore Broadcast Requests (Scored)
[CIS - RHEL7 - 4.2.5 - Network parameters - ICMP broadcasts accepted {CIS: 4.2.5 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

# 4.2.6 Enable Bad Error Message Protection (Scored)
[CIS - RHEL7 - 4.2.6 - Network parameters - Bad error message protection not enabled {CIS: 4.2.6 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses -> 0;

# 4.2.7 Enable RFC-recommended Source Route Validation (Scored)
[CIS - RHEL7 - 4.2.7 - Network parameters - RFC Source route validation not enabled  {CIS: 4.2.7 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/rp_filter -> 0;
f:/proc/sys/net/ipv4/conf/default/rp_filter -> 0;

# 4.2.8 Enable TCP SYN Cookies (Scored)
[CIS - RHEL7 - 4.2.8 - Network parameters - SYN Cookies not enabled {CIS: 4.2.8 RHEL7} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/tcp_syncookies -> 0;


###############################################
# 4.3 Wireless Networking
###############################################

# 4.3.1 Deactivate Wireless Interfaces (Not Scored)


###############################################
# 4.4 Disable ipv6
###############################################

###############################################
# 4.4.1 Configure IPv6
###############################################

# 4.4.1.1 Disable IPv6 Router Advertisements (Not Scored)

# 4.4.1.2 Disable IPv6 Redirect Acceptance (Not Scored)

# 4.4.2 Disable IPv6 (Not Scored)


###############################################
# 4.5 Install TCP Wrappers
###############################################

# 4.5.1 Install TCP Wrappers (Not Scored)

# 4.5.2 Create /etc/hosts.allow (Not Scored)

# 4.5.3 Verify Permissions on /etc/hosts.allow (Scored)
# TODO

# 4.5.4 Create /etc/hosts.deny (Not Scored)

# 4.5.5 Verify Permissions on /etc/hosts.deny (Scored)
# TODO


###############################################
# 4.6 Uncommon Network Protocols
###############################################

# 4.6.1 Disable DCCP (Not Scored)

# 4.6.2 Disable SCTP (Not Scored)

# 4.6.3 Disable RDS (Not Scored)

# 4.6.4 Disable TIPC (Not Scored)

# 4.7 Enable IPtables (Scored)
#[CIS - RHEL7 - 4.7 - Uncommon Network Protocols - Firewalld not enabled {CIS: 4.7 RHEL7}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
#f:/usr/lib/systemd/system/firewalld.service -> TODO;


###############################################
# 5 Logging and Auditing
###############################################

###############################################
# 5.1 Configure Syslog
###############################################

# 5.1.1 Install the rsyslog package (Scored)
# TODO

# 5.1.2 Activate the rsyslog Service (Scored)
# TODO

# 5.1.3 Configure /etc/rsyslog.conf (Not Scored)

# 5.1.4 Create and Set Permissions on rsyslog Log Files (Scored)

# 5.1.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)

# 5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)


###############################################
# 5.2 Configure System Accounting (auditd)
###############################################

###############################################
# 5.2.1 Configure Data Retention
###############################################

# 5.2.1.1 Configure Audit Log Storage Size (Not Scored)

# 5.2.1.2 Disable System on Audit Log Full (Not Scored)

# 5.2.1.3 Keep All Auditing Information (Scored)

# 5.2.2 Enable auditd Service (Scored)

# 5.2.3 Enable Auditing for Processes That Start Prior to auditd (Scored)

# 5.2.4 Record Events That Modify Date and Time Information (Scored)

# 5.2.5 Record Events That Modify User/Group Information (Scored)

# 5.2.6 Record Events That Modify the System’s Network Environment (Scored)

# 5.2.7 Record Events That Modify the System’s Mandatory Access Controls (Scored)

# 5.2.8 Collect Login and Logout Events (Scored)

# 5.2.9 Collect Session Initiation Information (Scored)

# 5.2.10 Collect Discretionary Access Control Permission Modification Events (Scored)

# 5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)

# 5.2.12 Collect Use of Privileged Commands (Scored)

# 5.2.13 Collect Successful File System Mounts (Scored)

# 5.2.14 Collect File Deletion Events by User (Scored)

# 5.2.15 Collect Changes to System Administration Scope (sudoers) (Scored)

# 5.2.16 Collect System Administrator Actions (sudolog) (Scored)

# 5.2.17 Collect Kernel Module Loading and Unloading (Scored)

# 5.2.18 Make the Audit Configuration Immutable (Scored)

# 5.3 Configure logrotate (Not Scored)


###############################################
# 6 System Access, Authentication and Authorization
###############################################

###############################################
# 6.1 Configure cron and anacron
###############################################

# 6.1.1 Enable anacron Daemon (Scored)

# 6.1.2 Enable cron Daemon (Scored)

# 6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)

# 6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)

# 6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)

# 6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)

# 6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)

# 6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)

# 6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)

# 6.1.10 Restrict at Daemon (Scored)

# 6.1.11 Restrict at/cron to Authorized Users (Scored)

###############################################
# 6.2 Configure SSH
###############################################

# 6.2.1 Set SSH Protocol to 2 (Scored)
[CIS - RHEL7 - 6.2.1 - SSH Configuration - Protocol version 1 enabled {CIS: 6.2.1 RHEL7} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

# 6.2.2 Set LogLevel to INFO (Scored)
[CIS - RHEL7 - 6.2.1 - SSH Configuration - Protocol version 1 enabled {CIS: 6.2.1 RHEL7} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && !r:LogLevel\.+INFO;

# 6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)
# TODO

# 6.2.4 Disable SSH X11 Forwarding (Scored)
# TODO

# 6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)
[CIS - RHEL7 - 6.2.5 - SSH Configuration - Set SSH MaxAuthTries to 4 or Less  {CIS - RHEL7 - 6.2.5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:$sshd_file -> !r:^\s*MaxAuthTries\s+4\s*$;

# 6.2.6 Set SSH IgnoreRhosts to Yes (Scored)
[CIS - RHEL7 - 6.2.6 - SSH Configuration - IgnoreRHosts disabled {CIS: 6.2.6 RHEL7} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

# 6.2.7 Set SSH HostbasedAuthentication to No (Scored)
[CIS - RHEL7 - 6.2.7 - SSH Configuration - Host based authentication enabled {CIS: 6.2.7 RHEL7} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

# 6.2.8 Disable SSH Root Login (Scored)
[CIS - RHEL7 - 6.2.8 - SSH Configuration - Root login allowed {CIS: 6.2.8 RHEL7} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:$sshd_file -> !r:^\s*PermitRootLogin\.+no;

# 6.2.9 Set SSH PermitEmptyPasswords to No (Scored)
[CIS - RHEL7 - 6.2.9 - SSH Configuration - Empty passwords permitted {CIS: 6.2.9 RHEL7} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:$sshd_file -> !r:^\s*PermitEmptyPasswords\.+no;

# 6.2.10 Do Not Allow Users to Set Environment Options (Scored)

# 6.2.11 Use Only Approved Ciphers in Counter Mode (Scored)

# 6.2.12 Set Idle Timeout Interval for User Login (Not Scored)

# 6.2.13 Limit Access via SSH (Scored)

# 6.2.14 Set SSH Banner (Scored)


###############################################
# 6.3 Configure PAM
###############################################

# 6.3.1 Upgrade Password Hashing Algorithm to SHA-512 (Scored)
# authconfig --test | grep hashing | grep sha512

# 6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)

# 6.3.3 Set Lockout for Failed Password Attempts (Not Scored)

# 6.3.4 Limit Password Reuse (Scored)


# 6.4 Restrict root Login to System Console (Not Scored)

# 6.5 Restrict Access to the su Command (Scored)


###############################################
# 7 User Accounts and Environment
###############################################

###############################################
# 7.1 Set Shadow Password Suite Parameters (/etc/login.defs)
###############################################

# 7.1.1 Set Password Expiration Days (Scored)

# 7.1.2 Set Password Change Minimum Number of Days (Scored)

# 7.1.3 Set Password Expiring Warning Days (Scored)

# 7.2 Disable System Accounts (Scored)

# 7.3 Set Default Group for root Account (Scored)

# 7.4 Set Default umask for Users (Scored)

# 7.5 Lock Inactive User Accounts (Scored)


###############################################
# 8 Warning Banners
###############################################

###############################################
# 8.1 Warning Banners for Standard Login Services
###############################################

# 8.1 Set Warning Banner for Standard Login Services (Scored)

# 8.2 Remove OS Information from Login Warning Banners (Scored)

# 8.3 Set GNOME Warning Banner (Not Scored)


###############################################
# 9 System Maintenance
###############################################

###############################################
# 9.1 Verify System File Permissions
###############################################

# 9.1.1 Verify System File Permissions (Not Scored)

# 9.1.2 Verify Permissions on /etc/passwd (Scored)

# 9.1.3 Verify Permissions on /etc/shadow (Scored)

# 9.1.4 Verify Permissions on /etc/gshadow (Scored)

# 9.1.5 Verify Permissions on /etc/group (Scored)

# 9.1.6 Verify User/Group Ownership on /etc/passwd (Scored)

# 9.1.7 Verify User/Group Ownership on /etc/shadow (Scored)

# 9.1.8 Verify User/Group Ownership on /etc/gshadow (Scored)

# 9.1.9 Verify User/Group Ownership on /etc/group (Scored)

# 9.1.10 Find World Writable Files (Not Scored)

# 9.1.11 Find Un-owned Files and Directories (Scored)

# 9.1.12 Find Un-grouped Files and Directories (Scored)

# 9.1.13 Find SUID System Executables (Not Scored)

# 9.1.14 Find SGID System Executables (Not Scored)


###############################################
# 9.2 Review User and Group Settings
###############################################

# 9.2.1 Ensure Password Fields are Not Empty (Scored)

# 9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)

# 9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)

# 9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)

# 9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
[CIS - RHEL7 - 9.2.5 - Non-root account with uid 0 {CIS: 9.2.5 RHEL7} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;

# 9.2.6 Ensure root PATH Integrity (Scored)

# 9.2.7 Check Permissions on User Home Directories (Scored)

# 9.2.8 Check User Dot File Permissions (Scored)

# 9.2.9 Check Permissions on User .netrc Files (Scored)

# 9.2.10 Check for Presence of User .rhosts Files (Scored)

# 9.2.11 Check Groups in /etc/passwd (Scored)

# 9.2.12 Check That Users Are Assigned Valid Home Directories (Scored)

# 9.2.13 Check User Home Directory Ownership (Scored)

# 9.2.14 Check for Duplicate UIDs (Scored)

# 9.2.15 Check for Duplicate GIDs (Scored)

# 9.2.16 Check That Reserved UIDs Are Assigned to System Accounts  (Scored)

# 9.2.17 Check for Duplicate User Names (Scored)

# 9.2.18 Check for Duplicate Group Names (Scored)

# 9.2.19 Check for Presence of User .netrc Files (Scored)

# 9.2.20 Check for Presence of User .forward Files (Scored)


# Other/Legacy Tests
[CIS - RHEL7 - X.X.X - Account with empty password present {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - RHEL7 - X.X.X - User-mounted removable partition allowed on the console] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
f:/etc/security/console.perms -> r:^<console>  \d+ <cdrom>;
f:/etc/security/console.perms -> r:^<console>  \d+ <floppy>;

[CIS - RHEL7 - X.X.X - Disable standard boot services - Kudzu hardware detection Enabled] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dkudzu$;

[CIS - RHEL7 - X.X.X - Disable standard boot services - PostgreSQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dpostgresql$;

[CIS - RHEL7 - X.X.X - Disable standard boot services - MySQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dmysqld$;

[CIS - RHEL7 - X.X.X - Disable standard boot services - DNS server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dnamed$;

[CIS - RHEL7 - X.X.X - Disable standard boot services - NetFS Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dnetfs$;
!17663 cis_rhel_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2014
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).


# CIS Checks for Red Hat (RHEL 2.1, 3.0, 4.0 and Fedora Core 1,2,3,4 and 5).
# Based on CIS Benchmark for Red Hat Enterprise Linux v1.0.5



# RC scripts location
$rc_dirs=/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d;



# Main one. Only valid for Red Hat/Fedora.
[CIS - Testing against the CIS Red Hat Enterprise Linux Benchmark v1.0.5] [any required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/redhat-release -> r:^Red Hat Enterprise Linux \S+ release 4;
f:/etc/redhat-release -> r:^Red Hat Enterprise Linux \S+ release 3;
f:/etc/redhat-release -> r:^Red Hat Enterprise Linux \S+ release 2.1;
f:/etc/fedora-release -> r:^Fedora && r:release 1;
f:/etc/fedora-release -> r:^Fedora && r:release 2;
f:/etc/fedora-release -> r:^Fedora && r:release 3;
f:/etc/fedora-release -> r:^Fedora && r:release 4;
f:/etc/fedora-release -> r:^Fedora && r:release 5;


# Build considerations - Partition scheme.
[CIS - Red Hat Linux - - Build considerations - Robust partition scheme - /var is not on its own partition] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:/var;

[CIS - Red Hat Linux - - Build considerations - Robust partition scheme - /home is not on its own partition] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:/home;


# Section 1.3 - SSH configuration
[CIS - Red Hat Linux - 1.3 - SSH Configuration - Protocol version 1 enabled {CIS: 1.3 Red Hat Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

[CIS - Red Hat Linux - 1.3 - SSH Configuration - IgnoreRHosts disabled {CIS: 1.3 Red Hat Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

[CIS - Red Hat Linux - 1.3 - SSH Configuration - Empty passwords permitted {CIS: 1.3 Red Hat Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;

[CIS - Red Hat Linux - 1.3 - SSH Configuration - Host based authentication enabled {CIS: 1.3 Red Hat Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

[CIS - Red Hat Linux - 1.3 - SSH Configuration - Root login allowed {CIS: 1.3 Red Hat Linux} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;


# Section 1.4 Enable system accounting
#[CIS - Red Hat Linux - 1.4 - System Accounting - Sysstat not installed] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
#f:!/var/log/sa;


# Section 2.5 Install and run Bastille
#[CIS - Red Hat Linux - 1.5 - System harderning - Bastille is not installed] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
#f:!/etc/Bastille;


# Section 2 - Minimize xinetd services
[CIS - Red Hat Linux - 2.3 - Telnet enabled on xinetd {CIS: 2.3 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/telnet -> !r:^# && r:disable && r:no;

[CIS - Red Hat Linux - 2.4 - VSFTP enabled on xinetd {CIS: 2.4 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/vsftpd -> !r:^# && r:disable && r:no;

[CIS - Red Hat Linux - 2.4 - WU-FTP enabled on xinetd {CIS: 2.4 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/wu-ftpd -> !r:^# && r:disable && r:no;

[CIS - Red Hat Linux - 2.5 - rsh/rlogin/rcp enabled on xinetd {CIS: 2.5 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/rlogin -> !r:^# && r:disable && r:no;
f:/etc/xinetd.c/rsh -> !r:^# && r:disable && r:no;
f:/etc/xinetd.c/shell -> !r:^# && r:disable && r:no;

[CIS - Red Hat Linux - 2.6 - tftpd enabled on xinetd {CIS: 2.6 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/tftpd -> !r:^# && r:disable && r:no;

[CIS - Red Hat Linux - 2.7 - imap enabled on xinetd {CIS: 2.7 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/imap -> !r:^# && r:disable && r:no;
f:/etc/xinetd.c/imaps -> !r:^# && r:disable && r:no;

[CIS - Red Hat Linux - 2.8 - pop3 enabled on xinetd {CIS: 2.8 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/xinetd.c/ipop3 -> !r:^# && r:disable && r:no;
f:/etc/xinetd.c/pop3s -> !r:^# && r:disable && r:no;


# Section 3 - Minimize boot services
[CIS - Red Hat Linux - 3.1 - Set daemon umask - Default umask is higher than 027 {CIS: 3.1 Red Hat Linux}] [all] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/init.d/functions -> !r:^# && r:^umask && >:umask 027;

[CIS - Red Hat Linux - 3.4 - GUI login enabled {CIS: 3.4 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/inittab -> !r:^# && r:id:5;

[CIS - Red Hat Linux - 3.7 - Disable standard boot services - Samba Enabled {CIS: 3.7 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dsamba$;
d:$rc_dirs -> ^S\d\dsmb$;

[CIS - Red Hat Linux - 3.8 - Disable standard boot services - NFS Enabled {CIS: 3.8 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dnfs$;
d:$rc_dirs -> ^S\d\dnfslock$;

[CIS - Red Hat Linux - 3.10 - Disable standard boot services - NIS Enabled {CIS: 3.10 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dypbind$;
d:$rc_dirs -> ^S\d\dypserv$;

[CIS - Red Hat Linux - 3.13 - Disable standard boot services - NetFS Enabled {CIS: 3.13 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dnetfs$;

[CIS - Red Hat Linux - 3.15 - Disable standard boot services - Apache web server Enabled {CIS: 3.15 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dapache$;
d:$rc_dirs -> ^S\d\dhttpd$;

[CIS - Red Hat Linux - 3.15 - Disable standard boot services - TUX web server Enabled {CIS: 3.15 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dtux$;

[CIS - Red Hat Linux - 3.16 - Disable standard boot services - SNMPD process Enabled {CIS: 3.16 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dsnmpd$;

[CIS - Red Hat Linux - 3.17 - Disable standard boot services - DNS server Enabled {CIS: 3.17 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dnamed$;

[CIS - Red Hat Linux - 3.18 - Disable standard boot services - MySQL server Enabled {CIS: 3.18 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dmysqld$;

[CIS - Red Hat Linux - 3.18 - Disable standard boot services - PostgreSQL server Enabled {CIS: 3.18 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dpostgresql$;

[CIS - Red Hat Linux - 3.19 - Disable standard boot services - Webmin Enabled {CIS: 3.19 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dwebmin$;

[CIS - Red Hat Linux - 3.20 - Disable standard boot services - Squid Enabled {CIS: 3.20 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dsquid$;

[CIS - Red Hat Linux - 3.21 - Disable standard boot services - Kudzu hardware detection Enabled {CIS: 3.21 Red Hat Linux} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
d:$rc_dirs -> ^S\d\dkudzu$;


# Section 4 - Kernel tuning
[CIS - Red Hat Linux - 4.1 - Network parameters - Source routing accepted {CIS: 4.1 Red Hat Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

[CIS - Red Hat Linux - 4.1 - Network parameters - ICMP broadcasts accepted {CIS: 4.1 Red Hat Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

[CIS - Red Hat Linux - 4.2 - Network parameters - IP Forwarding enabled {CIS: 4.2 Red Hat Linux}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;


# Section 6 - Permissions
[CIS - Red Hat Linux - 6.1 - Partition /var without 'nodev' set {CIS: 6.1 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/var && !r:nodev;

[CIS - Red Hat Linux - 6.1 - Partition /tmp without 'nodev' set {CIS: 6.1 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/tmp && !r:nodev;

[CIS - Red Hat Linux - 6.1 - Partition /opt without 'nodev' set {CIS: 6.1 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/opt && !r:nodev;

[CIS - Red Hat Linux - 6.1 - Partition /home without 'nodev' set {CIS: 6.1 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/home && !r:nodev ;

[CIS - Red Hat Linux - 6.2 - Removable partition /media without 'nodev' set {CIS: 6.2 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

[CIS - Red Hat Linux - 6.2 - Removable partition /media without 'nosuid' set {CIS: 6.2 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

[CIS - Red Hat Linux - 6.3 - User-mounted removable partition allowed on the console {CIS: 6.3 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/security/console.perms -> r:^<console>  \d+ <cdrom>;
f:/etc/security/console.perms -> r:^<console>  \d+ <floppy>;


# Section 7 - Access and authentication
[CIS - Red Hat Linux - 7.8 - LILO Password not set {CIS: 7.8 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/lilo.conf -> !r:^# && !r:restricted;
f:/etc/lilo.conf -> !r:^# && !r:password=;

[CIS - Red Hat Linux - 7.8 - GRUB Password not set {CIS: 7.8 Red Hat Linux} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/boot/grub/menu.lst -> !r:^# && !r:password;

[CIS - Red Hat Linux - 8.2 - Account with empty password present {CIS: 8.2 Red Hat Linux} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - Red Hat Linux - SN.11 - Non-root account with uid 0 {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_RHLinux_Benchmark_v1.0.5.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;


# Tests specific for VMware ESX - Runs on Red Hat Linux -
# Will not be tested anywhere else.
[VMware ESX - Testing against the Security Harderning benchmark VI3 for ESX 3.5] [any required] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
f:/etc/vmware-release -> r:^VMware ESX;


# Virtual Machine Files and Settings - 1
# 1.1
[VMware ESX - VM settings - Copy operation between guest and console enabled] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^isolation.tools.copy.disable;
d:/vmfs/volumes -> .vmx$ -> r:^isolation.tools.copy.disable && r:false;

# 1.2
[VMware ESX - VM settings - Paste operation between guest and console enabled] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^isolation.tools.paste.disable;
d:/vmfs/volumes -> .vmx$ -> r:^isolation.tools.paste.disable && r:false;

# 1.3
[VMware ESX - VM settings - GUI Options enabled] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> r:^isolation.tools.setGUIOptions.enable && r:true;

# 1.4
[VMware ESX - VM settings - Data Flow from the Virtual Machine to the Datastore not limited - Rotate size not 100KB] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^log.rotateSize;
d:/vmfs/volumes -> .vmx$ -> r:^log.rotateSize && !r:"100000";

# 1.5
[VMware ESX - VM settings - Data Flow from the Virtual Machine to the Datastore not limited - Maximum number of logs not 10] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^log.keepOld;
d:/vmfs/volumes -> .vmx$ -> r:^log.keepOld && r:"10";

# 1.6
[VMware ESX - VM settings - Data Flow from the Virtual Machine to the Datastore not limited - Guests allowed to write SetInfo data to config] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^isolation.tools.setinfo.disable;
d:/vmfs/volumes -> .vmx$ -> r:^isolation.tools.setinfo.disable && r:false;

# 1.7
[VMware ESX - VM settings - Nonpersistent Disks being used] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> r:^scsi\d:\d.mode && r:!independent-nonpersistent;

# 1.8
[VMware ESX - VM settings - Floppy drive present] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> r:^floppy\d+.present && r:!false;

[VMware ESX - VM settings - Serial port present] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> r:^serial\d+.present && r:!false;

[VMware ESX - VM settings - Parallel port present] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> r:^parallel\d+.present && r:!false;

# 1.9
[VMware ESX - VM settings - Unauthorized Removal or Connection of Devices allowed] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^Isolation.tools.connectable.disable;
d:/vmfs/volumes -> .vmx$ -> r:^Isolation.tools.connectable.disable && r:false;

# 1.10
[VMware ESX - VM settings - Avoid Denial of Service Caused by Virtual Disk Modification Operations - diskWiper enabled] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^isolation.tools.diskWiper.disable;
d:/vmfs/volumes -> .vmx$ -> r:^isolation.tools.diskWiper.disable && r:false;

[VMware ESX - VM settings - Avoid Denial of Service Caused by Virtual Disk Modification Operations - diskShrink enabled] [any] [http://www.vmware.com/pdf/vi3_security_hardening_wp.pdf]
d:/vmfs/volumes -> .vmx$ -> !r:^isolation.tools.diskShrink.disable;
d:/vmfs/volumes -> .vmx$ -> r:^isolation.tools.diskShrink.disable && r:false;


# Configuring the Service Console in ESX 3.5 - 2
# 2.1
!34381 cis_sles11_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2014
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).


# CIS Checks for SUSE SLES 11
# Based on CIS Benchmark for SUSE Linux Enterprise Server 11 v1.1.0

# RC scripts location
$rc_dirs=/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d;


[CIS - Testing against the CIS SUSE Linux Enterprise Server 11 Benchmark v1.1.0] [any required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 11";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 11 SP1";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 11 SP2";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 11 SP3";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 11 SP4";

# 2.1 /tmp: partition
[CIS - SLES11 - 2.1 - Build considerations - Robust partition scheme - /tmp is not on its own partition {CIS: 2.2 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:/tmp;

# 2.2 /tmp: nodev
[CIS - SLES11 - 2.2 - Partition /tmp without 'nodev' set {CIS: 2.2 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 2.3 /tmp: nosuid
[CIS - SLES11 - 2.3 - Partition /tmp without 'nosuid' set {CIS: 2.3 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nosuid;

# 2.4 /tmp: noexec
[CIS - SLES11 - 2.4 - Partition /tmp without 'noexec' set {CIS: 2.4 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 2.5 Build considerations - Partition scheme.
[CIS - SLES11 - Build considerations - Robust partition scheme - /var is not on its own partition {CIS: 2.5 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r^# && !r:/var;

# 2.6 bind mount /var/tmp to /tmp
[CIS - SLES11 - Build considerations - Robust partition scheme - /var/tmp is bound to /tmp {CIS: 2.6 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> r:^# && !r:/var/tmp && !r:bind;

# 2.7 /var/log: partition
[CIS - SLES11 - Build considerations - Robust partition scheme - /var/log is not on its own partition {CIS: 2.7 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log;

# 2.8 /var/log/audit: partition
[CIS - SLES11 - Build considerations - Robust partition scheme - /var/log/audit is not on its own partition {CIS: 2.8 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log/audit;

# 2.9 /home: partition
[CIS - SLES11 - Build considerations - Robust partition scheme - /home is not on its own partition {CIS: 2.9 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> ^# && !r:/home;

# 2.10 /home: nodev
[CIS - SLES11 - 2.10 -  Partition /home without 'nodev' set {CIS: 2.10 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/home && !r:nodev;

# 2.11 nodev on removable media partitions (not scored)
[CIS - SLES11 - 2.11 - Removable partition /media without 'nodev' set {CIS: 2.11 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

# 2.12 noexec on removable media partitions (not scored)
[CIS - SLES11 - 2.12 - Removable partition /media without 'noexec' set {CIS: 2.12 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:noexec;

# 2.13 nosuid on removable media partitions (not scored)
[CIS - SLES11 - 2.13 - Removable partition /media without 'nosuid' set {CIS: 2.13 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

# 2.14 /dev/shm: nodev
[CIS - SLES11 - 2.14 - /dev/shm without 'nodev' set {CIS: 2.14 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nodev;

# 2.15 /dev/shm: nosuid
[CIS - SLES11 - 2.15 - /dev/shm without 'nosuid' set {CIS: 2.15 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nosuid;

# 2.16 /dev/shm: noexec
[CIS - SLES11 - 2.16 - /dev/shm without 'noexec' set {CIS: 2.16 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;

# 2.17 sticky bit on world writable directories (Scored)
# TODO

# 2.18 disable cramfs (not scored)

# 2.19 disable freevxfs (not scored)

# 2.20 disable jffs2 (not scored)

# 2.21 disable hfs (not scored)

# 2.22 disable hfsplus (not scored)

# 2.23 disable squashfs (not scored)

# 2.24 disable udf (not scored)

# 2.25 disable automounting (Scored)
# TODO

###############################################
# 3  Secure Boot Settings
###############################################

# 3.1 Set User/Group Owner on /etc/grub.conf
# TODO (no mode tests)
# stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"

# 3.2 Set Permissions on /etc/grub.conf (Scored)
# TODO (no mode tests)
#  stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"

# 3.3 Set Boot Loader Password (Scored)
[CIS - SLES11 - 3.3 - GRUB Password not set {CIS: 3.3 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/boot/grub2/grub.cfg -> !r:^# && !r:password;

# 3.4 Require Authentication for Single-User Mode (Scored)

# 3.5 Disable Interactive Boot (Scored)

###############################################
# 4  Additional Process Hardening
###############################################

# 4.1 Restrict Core Dumps (Scored)
[CIS - SLES11 - 4.1 - Interactive Boot not disabled {CIS: 4.1 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/security/limits.conf -> !r:^# && !r:hard\.+core\.+0;

# 4.2 Enable XD/NX Support on 32-bit x86 Systems (Not Scored)
# TODO

# 4.3 Enable Randomized Virtual Memory Region Placement (Scored)
[CIS - SLES11 - 4.3 - Randomized Virtual Memory Region Placement not enabled  {CIS: 4.3 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/kernel/randomize_va_space -> 2;

# 4.4 Disable Prelink (Scored)
# TODO

# 4.5 Activate AppArmor (Scored)
# TODO

###############################################
# 5 OS Services
###############################################

###############################################
# 5.1 Remove Legacy Services
###############################################

# 5.1.1 Remove NIS Server (Scored)
[CIS - SLES11 - 5.1.1 - Disable standard boot services - NIS (server) Enabled {CIS: 5.1.1 SLES11} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dypserv$;

# 5.1.2 Remove NIS Client (Scored)
[CIS - SLES11 - 5.1.2 - Disable standard boot services - NIS (client) Enabled {CIS: 51.2 SLES11} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dypbind$;

# 5.1.3 Remove rsh-server (Scored)
[CIS - SLES11 - 5.1.3 - rsh/rlogin/rcp enabled on xinetd {CIS: 5.1.3 SLES11} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/rlogin -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/rsh -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/shell -> !r:^# && r:disable && r:no;

# 5.1.4 Remove rsh client (Scored)
# TODO

# 5.1.5 Remove talk-server (Scored)
[CIS - SLES11 - 5.1.5 - talk enabled on xinetd {CIS: 5.1.5 SLES11} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/talk -> !r:^# && r:disable && r:no;

# 5.1.6 Remove talk client (Scored)
# TODO

# 5.1.7 Remove telnet-server (Scored)
# TODO: detect it is installed at all
[CIS - SLES11 - 5.1.7 - Telnet enabled on xinetd {CIS: 5.1.7 SLES11} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/telnet -> !r:^# && r:disable && r:no;

# 5.1.8 Remove tftp-server (Scored)
[CIS - SLES11 - 5.1.8 - tftpd enabled on xinetd {CIS: 5.1.8 SLES11} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/tftpd -> !r:^# && r:disable && r:no;

# 5.1.9 Remove xinetd (Scored)
[CIS - SLES11 - 5.1.9 -  xinetd detected {CIS: 5.1.9 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]

# 5.2 Disable chargen-udp (Scored)
[CIS - SLES11 - 5.2 -  chargen-udp enabled on xinetd {CIS: 5.2 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/chargen-udp -> !r:^# && r:disable && r:no;

# 5.3 Disable chargen (Scored)
[CIS - SLES11 - 5.3 -  chargen enabled on xinetd {CIS: 5.3 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/chargen -> !r:^# && r:disable && r:no;

# 5.4 Disable daytime-udp (Scored)
[CIS - SLES11 - 5.4 -  daytime-udp enabled on xinetd {CIS: 5.4 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/daytime-udp -> !r:^# && r:disable && r:no;

# 5.5 Disable daytime (Scored)
[CIS - SLES11 - 5.5 -  daytime enabled on xinetd {CIS: 5.5 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/daytime -> !r:^# && r:disable && r:no;


# 5.6 Disable echo-udp (Scored)
[CIS - SLES11 - 5.6 -  echo-udp enabled on xinetd {CIS: 5.6 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/echo-udp -> !r:^# && r:disable && r:no;

# 5.7 Disable echo (Scored)
[CIS - SLES11 - 5.7 -  echo enabled on xinetd {CIS: 5.7 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/echo -> !r:^# && r:disable && r:no;

# 5.8 Disable discard-udp (Scored)
[CIS - SLES11 - 5.8 -  discard-udp enabled on xinetd {CIS: 5.8 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/discard-udp -> !r:^# && r:disable && r:no;

# 5.9 Disable discard (Scored)
[CIS - SLES11 - 5.9 -  discard enabled on xinetd {CIS: 5.9 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/discard -> !r:^# && r:disable && r:no;

# 5.10 Disable time-udp (Scored)
[CIS - SLES11 - 5.10 -  time-udp enabled on xinetd {CIS: 5.10 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/time-udp -> !r:^# && r:disable && r:no;

# 5.11 Disable time (Scored)
[CIS - SLES11 - 5.11 -  time enabled on xinetd {CIS: 5.11 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/time -> !r:^# && r:disable && r:no;

###############################################
# 6 Special Purpose Services
###############################################

# 6.1 Remove X Windows (Scored)
[CIS - SLES11 - 6.1 - X11 not disabled {CIS: 6.1 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/inittab -> !r:^# && r:id:5;

# 6.2 Disable Avahi Server (Scored)
[CIS - SLES11 - 6.2 - Avahi daemon not disabled {CIS: 6.2 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
p:avahi-daemon;

# 6.3 Disable Print Server - CUPS (Not Scored)
#TODO

# 6.4 Remove DHCP Server (Scored)
#[CIS - SLES11 - 6.4 - DHCPnot disabled {CIS: 6.4 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dhcpd$;
d:$rc_dirs -> ^S\d\dhcpd6$;

# 6.5 Configure Network Time Protocol (NTP) (Scored)
#TODO Chrony
[CIS - SLES11 - 6.5 - NTPD not Configured {CIS: 6.5 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/ntp.conf -> r:restrict default kod nomodify notrap nopeer noquery && r:^server;
f:/etc/sysconfig/ntpd -> r:OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid";

# 6.6 Remove LDAP (Not Scored)
#TODO

# 6.7 Disable NFS and RPC (Not Scored)
[CIS - SLES11 - 6.7 - Disable standard boot services - NFS Enabled {CIS: 6.7 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dnfs$;
d:$rc_dirs -> ^S\d\dnfslock$;

# 6.8 Remove DNS Server (Not Scored)
# TODO

# 6.9 Remove FTP Server (Not Scored)
[CIS - SLES11 - 6.9 - VSFTP enabled on xinetd {CIS: 6.9 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/vsftpd -> !r:^# && r:disable && r:no;

# 6.10 Remove HTTP Server (Not Scored)
[CIS - SLES11 - 6.10 - Disable standard boot services - Apache web server Enabled {CIS: 6.10 SLES11}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dapache2$;

# 6.11 Remove Dovecot (IMAP and POP3 services) (Not Scored)
[CIS - SLES11 - 6.11 - imap enabled on xinetd {CIS: 6.11 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/cyrus-imapd -> !r:^# && r:disable && r:no;

[CIS - SLES11 - 6.11 - pop3 enabled on xinetd {CIS: 6.11 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/xinetd.d/dovecot -> !r:^# && r:disable && r:no;

# 6.12 Remove Samba (Not Scored)
[CIS - SLES11 - 6.12 - Disable standard boot services - Samba Enabled {CIS: 6.12 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsamba$;
d:$rc_dirs -> ^S\d\dsmb$;

# 6.13 Remove HTTP Proxy Server (Not Scored)
[CIS - SLES11 - 6.13 - Disable standard boot services - Squid Enabled {CIS: 6.13 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsquid$;

# 6.14 Remove SNMP Server (Not Scored)
[CIS - SLES11 - 6.14 - Disable standard boot services - SNMPD process Enabled {CIS: 6.14 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dsnmpd$;

# 6.15 Configure Mail Transfer Agent for Local-Only Mode (Scored)
# TODO

# 6.16 Ensure rsync service is not enabled (Scored)
[CIS - SLES11 - 6.16 - Disable standard boot services - rsyncd process Enabled {CIS: 6.16 SLES11} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\drsyncd$;

# 6.17 Ensure Biosdevname is not enabled (Scored)
# TODO

###############################################
# 7 Network Configuration and Firewalls
###############################################

###############################################
# 7.1 Modify Network Parameters (Host Only)
###############################################

# 7.1.1 Disable IP Forwarding (Scored)
[CIS - SLES11 - 7.1.1 - Network parameters - IP Forwarding enabled {CIS: 7.1.1 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;

# 7.1.2 Disable Send Packet Redirects (Scored)
[CIS - SLES11 - 7.1.2 - Network parameters - IP send redirects enabled {CIS: 7.1.2 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/send_redirects -> 0;
f:/proc/sys/net/ipv4/conf/default/send_redirects -> 0;

###############################################
# 7.2 Modify Network Parameters (Host and Router)
###############################################

# 7.2.1 Disable Source Routed Packet Acceptance (Scored)
[CIS - SLES11 - 7.2.1 - Network parameters - Source routing accepted {CIS: 7.2.1 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

# 7.2.2 Disable ICMP Redirect Acceptance (Scored)
[CIS - SLES11 - 7.2.2 - Network parameters - ICMP redirects accepted {CIS: 7.2.2 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/accept_redirects -> 1;

# 7.2.3 Disable Secure ICMP Redirect Acceptance (Scored)
[CIS - SLES11 - 7.2.3 - Network parameters - ICMP secure redirects accepted {CIS: 7.2.3 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/secure_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/secure_redirects -> 1;

# 7.2.4 Log Suspicious Packets (Scored)
[CIS - SLES11 - 7.2.4 - Network parameters - martians not logged {CIS: 7.2.4 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/log_martians -> 0;

# 7.2.5 Enable Ignore Broadcast Requests (Scored)
[CIS - SLES11 - 7.2.5 - Network parameters - ICMP broadcasts accepted {CIS: 7.2.5 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

# 7.2.6 Enable Bad Error Message Protection (Scored)
[CIS - SLES11 - 7.2.6 - Network parameters - Bad error message protection not enabled {CIS: 7.2.6 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses -> 0;

# 7.2.7 Enable RFC-recommended Source Route Validation (Scored)
[CIS - SLES11 - 7.2.7 - Network parameters - RFC Source route validation not enabled  {CIS: 7.2.7 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/conf/all/rp_filter -> 0;
f:/proc/sys/net/ipv4/conf/default/rp_filter -> 0;

# 7.2.8 Enable TCP SYN Cookies (Scored)
[CIS - SLES11 - 7.2.8 - Network parameters - SYN Cookies not enabled {CIS: 7.2.8 SLES11} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/proc/sys/net/ipv4/tcp_syncookies -> 0;

###############################################
# 7.3 Configure IPv6
###############################################

# 7.3.1 Disable IPv6 Router Advertisements (Not Scored)

# 7.3.2 Disable IPv6 Redirect Acceptance (Not Scored)

# 7.3.3 Disable IPv6 (Not Scored)

###############################################
# 7.4 Install TCP Wrappers
###############################################

# 7.4.1 Install TCP Wrappers (Not Scored)

# 7.4.2 Create /etc/hosts.allow (Not Scored)

# 7.4.3 Verify Permissions on /etc/hosts.allow (Scored)
# TODO

# 7.4.4 Create /etc/hosts.deny (Not Scored)

# 7.5.5 Verify Permissions on /etc/hosts.deny (Scored)
# TODO

###############################################
# 7.5 Uncommon Network Protocols
###############################################

# 7.5.1 Disable DCCP (Not Scored)

# 7.5.2 Disable SCTP (Not Scored)

# 7.5.3 Disable RDS (Not Scored)

# 7.5.4 Disable TIPC (Not Scored)

# 7.6 Deactivate Wireless Interfaces (Not Scored)

# 7.7 Enable SuSEfirewall2 (Scored)

# 7.8 Limit access to trusted networks (Not Scored)

###############################################
# 8 Logging and Auditing
###############################################

###############################################
# 8.1 Configure System Accounting (auditd)
###############################################

###############################################
# 8.1.1 Configure Data Retention
###############################################

# 8.1.1.1 Configure Audit Log Storage Size (Not Scored)

# 8.1.1.2 Disable System on Audit Log Full (Not Scored)

# 8.1.1.3 Keep All Auditing Information (Scored)

# 8.1.2 Enable auditd Service (Scored)

# 8.1.3 Enable Auditing for Processes That Start Prior to auditd (Scored)

# 8.1.4 Record Events That Modify Date and Time Information (Scored)

# 8.1.5 Record Events That Modify User/Group Information (Scored)

# 8.1.6 Record Events That Modify the System’s Network Environment (Scored)

# 8.1.7 Record Events That Modify the System’s Mandatory Access Controls (Scored)

# 8.1.8 Collect Login and Logout Events (Scored)

# 8.1.9 Collect Session Initiation Information (Scored)

# 8.1.10 Collect Discretionary Access Control Permission Modification Events (Scored)

# 8.1.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)

# 8.1.12 Collect Use of Privileged Commands (Scored)

# 8.1.13 Collect Successful File System Mounts (Scored)

# 8.1.14 Collect File Deletion Events by User (Scored)

# 8.1.15 Collect Changes to System Administration Scope (sudoers) (Scored)

# 8.1.16 Collect System Administrator Actions (sudolog) (Scored)

# 8.1.17 Collect Kernel Module Loading and Unloading (Scored)

# 8.1.18 Make the Audit Configuration Immutable (Scored)

###############################################
# 8.2 Configure rsyslog
###############################################

# 8.2.1 Install the rsyslog package (Scored)
# TODO

# 8.2.2 Activate the rsyslog Service (Scored)
# TODO

# 8.2.3 Configure /etc/rsyslog.conf (Not Scored)

# 8.2.4 Create and Set Permissions on rsyslog Log Files (Scored)

# 8.2.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)

# 8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)

###############################################
# 8.3 Advanced Intrusion Detection Environment (AIDE)
###############################################

# 8.3.1 Install AIDE (Scored)

# 8.3.2 Implement Periodic Execution of File Integrity (Scored)

# 8.4 Configure logrotate (Not Scored)

###############################################
# 9 System Access, Authentication and Authorization
###############################################

###############################################
# 9.1 Configure cron and anacron
###############################################

# 9.1.1 Enable cron Daemon (Scored)

# 9.1.2 Set User/Group Owner and Permission on /etc/crontab (Scored)

# 9.1.3 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)

# 9.1.4 Set User/Group Owner and Permission on /etc/cron.daily (Scored)

# 9.1.5 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)

# 9.1.6 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)

# 9.1.7 Set User/Group Owner and Permission on /etc/cron.d (Scored)

# 9.1.8 Restrict at/cron to Authorized Users (Scored)

###############################################
# 9.2 Configure SSH
###############################################

# 9.2.1 Set SSH Protocol to 2 (Scored)
[CIS - SLES11 - 9.2.1 - SSH Configuration - Protocol version 1 enabled {CIS: 9.2.1 SLES11} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

# 9.2.2 Set LogLevel to INFO (Scored)
[CIS - SLES11 - 9.2.1 - SSH Configuration - Loglevel not INFO {CIS: 9.2.1 SLES11} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && !r:LogLevel\.+INFO;

# 9.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)
# TODO

# 9.2.4 Disable SSH X11 Forwarding (Scored)
# TODO

# 9.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)
[ CIS - SLES11 - 9.2.5 - SSH Configuration - Set SSH MaxAuthTries to 4 or Less  {CIS - SLES11 - 9.2.5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:$sshd_file -> !r:^\s*MaxAuthTries\s+4\s*$;

# 9.2.6 Set SSH IgnoreRhosts to Yes (Scored)
[CIS - SLES11 - 9.2.6 - SSH Configuration - IgnoreRHosts disabled {CIS: 9.2.6 SLES11} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

# 9.2.7 Set SSH HostbasedAuthentication to No (Scored)
[CIS - SLES11 - 9.2.7 - SSH Configuration - Host based authentication enabled {CIS: 9.2.7 SLES11} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

# 9.2.8 Disable SSH Root Login (Scored)
[CIS - SLES11 - 9.2.8 - SSH Configuration - Root login allowed {CIS: 9.2.8 SLES11} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:$sshd_file -> !r:^\s*PermitRootLogin\.+no;

# 9.2.9 Set SSH PermitEmptyPasswords to No (Scored)
[CIS - SLES11 - 9.2.9 - SSH Configuration - Empty passwords permitted {CIS: 9.2.9 SLES11} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:$sshd_file -> !r:^\s*PermitEmptyPasswords\.+no;

# 9.2.10 Do Not Allow Users to Set Environment Options (Scored)

# 9.2.11 Use Only Approved Ciphers in Counter Mode (Scored)

# 9.2.12 Set Idle Timeout Interval for User Login (Not Scored)

# 9.2.13 Limit Access via SSH (Scored)

# 9.2.14 Set SSH Banner (Scored)

###############################################
# 9.3 Configure PAM
###############################################

# 9.3.1 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)

# 9.3.2 Set Lockout for Failed Password Attempts (Not Scored)

# 9.3.3 Limit Password Reuse (Scored)

# 9.4 Restrict root Login to System Console (Not Scored)

# 9.5 Restrict Access to the su Command (Scored)

###############################################
# 10 User Accounts and Environment
###############################################

###############################################
# 10.1 Set Shadow Password Suite Parameters (/etc/login.defs)
###############################################

# 10.1.1 Set Password Expiration Days (Scored)

# 10.1.2 Set Password Change Minimum Number of Days (Scored)

# 10.1.3 Set Password Expiring Warning Days (Scored)

# 10.2 Disable System Accounts (Scored)

# 10.3 Set Default Group for root Account (Scored)

# 10.4 Set Default umask for Users (Scored)

# 10.5 Lock Inactive User Accounts (Scored)


###############################################
# 11 Warning Banners
###############################################

# 11.1 Set Warning Banner for Standard Login Services (Scored)

# 11.2 Remove OS Information from Login Warning Banners (Scored)

# 11.3 Set Graphical Warning Banner (Not Scored)

###############################################
# 12 Verify System File Permissions
###############################################

# 12.1 Verify System File Permissions (Not Scored)

# 12.2 Verify Permissions on /etc/passwd (Scored)

# 12.3 Verify Permissions on /etc/shadow (Scored)

# 12.4 Verify Permissions on /etc/group (Scored)

# 12.5 Verify User/Group Ownership on /etc/passwd (Scored)

# 12.6 Verify User/Group Ownership on /etc/shadow (Scored)

# 12.7 Verify User/Group Ownership on /etc/group (Scored)

# 12.8 Find World Writable Files (Not Scored)

# 12.9 Find Un-owned Files and Directories (Scored)

# 12.10 Find Un-grouped Files and Directories (Scored)

# 12.11 Find SUID System Executables (Not Scored)

# 12.12 Find SGID System Executables (Not Scored)

###############################################
# 13 Review User and Group Settings
###############################################

# 13.1 Ensure Password Fields are Not Empty (Scored)

# 13.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)

# 13.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)

# 13.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)

# 13.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
[CIS - SLES11 - 13.5 - Non-root account with uid 0 {CIS: 13.5 SLES11} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;

# 13.6 Ensure root PATH Integrity (Scored)

# 13.7 Check Permissions on User Home Directories (Scored)

# 13.8 Check User Dot File Permissions (Scored)

# 13.9 Check Permissions on User .netrc Files (Scored)

# 13.10 Check for Presence of User .rhosts Files (Scored)

# 13.11 Check Groups in /etc/passwd (Scored)

# 13.12 Check That Users Are Assigned Valid Home Directories (Scored)

# 13.13 Check User Home Directory Ownership (Scored)

# 13.14 Check for Duplicate UIDs (Scored)

# 13.15 Check for Duplicate GIDs (Scored)

# 13.16 Check for Duplicate User Names (Scored)

# 13.17 Check for Duplicate Group Names (Scored)

# 13.18 Check for Presence of User .netrc Files (Scored)

# 13.19 Check for Presence of User .forward Files (Scored)

# 13.20 Ensure shadow group is empty (Scored)


# Other/Legacy Tests
[CIS - SLES11 - X.X.X - Account with empty password present {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - SLES11 - X.X.X - User-mounted removable partition allowed on the console] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
f:/etc/security/console.perms -> r:^<console>  \d+ <cdrom>;
f:/etc/security/console.perms -> r:^<console>  \d+ <floppy>;

[CIS - SLES11 - X.X.X - Disable standard boot services - Kudzu hardware detection Enabled] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dkudzu$;

[CIS - SLES11 - X.X.X - Disable standard boot services - PostgreSQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dpostgresql$;

[CIS - SLES11 - X.X.X - Disable standard boot services - MySQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dmysqld$;

[CIS - SLES11 - X.X.X - Disable standard boot services - DNS server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dnamed$;

[CIS - SLES11 - X.X.X - Disable standard boot services - NetFS Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.1.0.pdf]
d:$rc_dirs -> ^S\d\dnetfs$;
!35086 cis_sles12_linux_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2014
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).


# CIS Checks for SUSE SLES 12
# Based on CIS Benchmark for SUSE Linux Enterprise Server 12 v1.0.0

# RC scripts location
$rc_dirs=/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d;


[CIS - Testing against the CIS SUSE Linux Enterprise Server 12 Benchmark v1.0.0] [any required] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 12";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 12 SP1";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 12 SP2";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 12 SP3";
f:/etc/os-release -> r:^PRETTY_NAME="SUSE Linux Enterprise Server 12 SP4";

# 2.1 /tmp: partition
[CIS - SLES12 - 2.1 - Build considerations - Robust partition scheme - /tmp is not on its own partition {CIS: 2.2 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:/tmp;

# 2.2 /tmp: nodev
[CIS - SLES12 - 2.2 - Partition /tmp without 'nodev' set {CIS: 2.2 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 2.3 /tmp: nosuid
[CIS - SLES12 - 2.3 - Partition /tmp without 'nosuid' set {CIS: 2.3 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nosuid;

# 2.4 /tmp: noexec
[CIS - SLES12 - 2.4 - Partition /tmp without 'noexec' set {CIS: 2.4 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/tmp && !r:nodev;

# 2.5 Build considerations - Partition scheme.
[CIS - SLES12 - Build considerations - Robust partition scheme - /var is not on its own partition {CIS: 2.5 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r^# && !r:/var;

# 2.6 bind mount /var/tmp to /tmp
[CIS - SLES12 - Build considerations - Robust partition scheme - /var/tmp is bound to /tmp {CIS: 2.6 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> r:^# && !r:/var/tmp && !r:bind;

# 2.7 /var/log: partition
[CIS - SLES12 - Build considerations - Robust partition scheme - /var/log is not on its own partition {CIS: 2.7 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log;

# 2.8 /var/log/audit: partition
[CIS - SLES12 - Build considerations - Robust partition scheme - /var/log/audit is not on its own partition {CIS: 2.8 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> ^# && !r:/var/log/audit;

# 2.9 /home: partition
[CIS - SLES12 - Build considerations - Robust partition scheme - /home is not on its own partition {CIS: 2.9 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> ^# && !r:/home;

# 2.10 /home: nodev
[CIS - SLES12 - 2.10 -  Partition /home without 'nodev' set {CIS: 2.10 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/home && !r:nodev;

# 2.11 nodev on removable media partitions (not scored)
[CIS - SLES12 - 2.11 - Removable partition /media without 'nodev' set {CIS: 2.11 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nodev;

# 2.12 noexec on removable media partitions (not scored)
[CIS - SLES12 - 2.12 - Removable partition /media without 'noexec' set {CIS: 2.12 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:noexec;

# 2.13 nosuid on removable media partitions (not scored)
[CIS - SLES12 - 2.13 - Removable partition /media without 'nosuid' set {CIS: 2.13 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;

# 2.14 /dev/shm: nodev
[CIS - SLES12 - 2.14 - /dev/shm without 'nodev' set {CIS: 2.14 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nodev;

# 2.15 /dev/shm: nosuid
[CIS - SLES12 - 2.15 - /dev/shm without 'nosuid' set {CIS: 2.15 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nosuid;

# 2.16 /dev/shm: noexec
[CIS - SLES12 - 2.16 - /dev/shm without 'noexec' set {CIS: 2.16 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;

# 2.17 sticky bit on world writable directories (Scored)
# TODO

# 2.18 disable cramfs (not scored)

# 2.19 disable freevxfs (not scored)

# 2.20 disable jffs2 (not scored)

# 2.21 disable hfs (not scored)

# 2.22 disable hfsplus (not scored)

# 2.23 disable squashfs (not scored)

# 2.24 disable udf (not scored)

# 2.25 disable automounting (Scored)
# TODO

###############################################
# 3  Secure Boot Settings
###############################################

# 3.1 Set User/Group Owner on /etc/grub.conf
# TODO (no mode tests)
# stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"

# 3.2 Set Permissions on /etc/grub.conf (Scored)
# TODO (no mode tests)
#  stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"

# 3.3 Set Boot Loader Password (Scored)
[CIS - SLES12 - 3.3 - GRUB Password not set {CIS: 3.3 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/boot/grub2/grub.cfg -> !r:^# && !r:password;

###############################################
# 4  Additional Process Hardening
###############################################

# 4.1 Restrict Core Dumps (Scored)
[CIS - SLES12 - 4.1 - Interactive Boot not disabled {CIS: 4.1 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/security/limits.conf -> !r:^# && !r:hard\.+core\.+0;

# 4.2 Enable XD/NX Support on 32-bit x86 Systems (Not Scored)
# TODO

# 4.3 Enable Randomized Virtual Memory Region Placement (Scored)
[CIS - SLES12 - 4.3 - Randomized Virtual Memory Region Placement not enabled  {CIS: 4.3 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/kernel/randomize_va_space -> 2;

# 4.4 Disable Prelink (Scored)
# TODO

# 4.5 Activate AppArmor (Scored)
# TODO

###############################################
# 5 OS Services
###############################################

###############################################
# 5.1 Remove Legacy Services
###############################################

# 5.1.1 Remove NIS Server (Scored)
[CIS - SLES12 - 5.1.1 - Disable standard boot services - NIS (server) Enabled {CIS: 5.1.1 SLES12} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dypserv$;
f:/usr/lib/systemd/system/ypserv.service -> r:Exec;

# 5.1.2 Remove NIS Client (Scored)
[CIS - SLES12 - 5.1.2 - Disable standard boot services - NIS (client) Enabled {CIS: 51.2 SLES12} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dypbind$;
f:/usr/lib/systemd/system/ypbind.service -> r:Exec;

# 5.1.3 Remove rsh-server (Scored)
[CIS - SLES12 - 5.1.3 - rsh/rlogin/rcp enabled on xinetd {CIS: 5.1.3 SLES12} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/rlogin -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/rsh -> !r:^# && r:disable && r:no;
f:/etc/xinetd.d/shell -> !r:^# && r:disable && r:no;
# TODO (finish this)
f:/usr/lib/systemd/system/rexec@.service -> r:ExecStart;
f:/usr/lib/systemd/system/rlogin@.service -> r:ExecStart;
f:/usr/lib/systemd/system/rsh@.service -> r:ExecStart;

# 5.1.4 Remove rsh client (Scored)
# TODO

# 5.1.5 Remove talk-server (Scored)
[CIS - SLES12 - 5.1.5 - talk enabled on xinetd {CIS: 5.1.5 SLES12} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/talk -> !r:^# && r:disable && r:no;
f:/usr/lib/systemd/system/ntalk.service -> r:Exec;

# 5.1.6 Remove talk client (Scored)
# TODO

# 5.1.7 Remove telnet-server (Scored)
# TODO: detect it is installed at all
[CIS - SLES12 - 5.1.7 - Telnet enabled on xinetd {CIS: 5.1.7 SLES12} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/telnet -> !r:^# && r:disable && r:no;
f:/usr/lib/systemd/system/telnet@.service -> r:ExecStart=-/usr/sbin/in.telnetd;

# 5.1.8 Remove tftp-server (Scored)
[CIS - SLES12 - 5.1.8 - tftpd enabled on xinetd {CIS: 5.1.8 SLES12} {PCI_DSS: 2.2.3}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/tftpd -> !r:^# && r:disable && r:no;
f:/usr/lib/systemd/system/tftp.service -> r:Exec;

# 5.1.9 Remove xinetd (Scored)
[CIS - SLES12 - 5.1.9 -  xinetd detected {CIS: 5.1.9 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/usr/lib/systemd/system/xinetd.service -> r:Exec;

# 5.2 Disable chargen-udp (Scored)
[CIS - SLES12 - 5.2 -  chargen-udp enabled on xinetd {CIS: 5.2 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/chargen-udp -> !r:^# && r:disable && r:no;

# 5.3 Disable chargen (Scored)
[CIS - SLES12 - 5.3 -  chargen enabled on xinetd {CIS: 5.3 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/chargen -> !r:^# && r:disable && r:no;

# 5.4 Disable daytime-udp (Scored)
[CIS - SLES12 - 5.4 -  daytime-udp enabled on xinetd {CIS: 5.4 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/daytime-udp -> !r:^# && r:disable && r:no;

# 5.5 Disable daytime (Scored)
[CIS - SLES12 - 5.5 -  daytime enabled on xinetd {CIS: 5.5 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/daytime -> !r:^# && r:disable && r:no;


# 5.6 Disable echo-udp (Scored)
[CIS - SLES12 - 5.6 -  echo-udp enabled on xinetd {CIS: 5.6 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/echo-udp -> !r:^# && r:disable && r:no;

# 5.7 Disable echo (Scored)
[CIS - SLES12 - 5.7 -  echo enabled on xinetd {CIS: 5.7 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/echo -> !r:^# && r:disable && r:no;

# 5.8 Disable discard-udp (Scored)
[CIS - SLES12 - 5.8 -  discard-udp enabled on xinetd {CIS: 5.8 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/discard-udp -> !r:^# && r:disable && r:no;

# 5.9 Disable discard (Scored)
[CIS - SLES12 - 5.9 -  discard enabled on xinetd {CIS: 5.9 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/discard -> !r:^# && r:disable && r:no;

# 5.10 Disable time-udp (Scored)
[CIS - SLES12 - 5.10 -  time-udp enabled on xinetd {CIS: 5.10 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/time-udp -> !r:^# && r:disable && r:no;

# 5.11 Disable time (Scored)
[CIS - SLES12 - 5.11 -  time enabled on xinetd {CIS: 5.11 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/time -> !r:^# && r:disable && r:no;

###############################################
# 6 Special Purpose Services
###############################################

# 6.1 Remove X Windows (Scored)
[CIS - SLES12 - 6.1 - X11 not disabled {CIS: 6.1 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/usr/lib/systemd/system/default.target -> r:Graphical;
p:gdm-x-session;

# 6.2 Disable Avahi Server (Scored)
[CIS - SLES12 - 6.2 - Avahi daemon not disabled {CIS: 6.2 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
p:avahi-daemon;

# 6.3 Disable Print Server - CUPS (Not Scored)
#TODO

# 6.4 Remove DHCP Server (Scored)
[CIS - SLES12 - 6.4 - DHCPnot disabled {CIS: 6.4 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/usr/lib/systemd/system/dhcpd.service -> r:Exec;

# 6.5 Configure Network Time Protocol (NTP) (Scored)
#TODO Chrony
[CIS - SLES12 - 6.5 - NTPD not Configured {CIS: 6.5 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ntp.conf -> r:restrict default kod nomodify notrap nopeer noquery && r:^server;
f:/etc/sysconfig/ntpd -> r:OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid";

# 6.6 Remove LDAP (Not Scored)
#TODO

# 6.7 Disable NFS and RPC (Not Scored)
[CIS - SLES12 - 6.7 - Disable standard boot services - NFS Enabled {CIS: 6.7 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dnfs$;
d:$rc_dirs -> ^S\d\dnfslock$;

# 6.8 Remove DNS Server (Not Scored)
# TODO

# 6.9 Remove FTP Server (Not Scored)
[CIS - SLES12 - 6.9 - VSFTP enabled on xinetd {CIS: 6.9 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/vsftpd -> !r:^# && r:disable && r:no;

# 6.10 Remove HTTP Server (Not Scored)
[CIS - SLES12 - 6.10 - Disable standard boot services - Apache web server Enabled {CIS: 6.10 SLES12}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dapache2$;

# 6.11 Remove Dovecot (IMAP and POP3 services) (Not Scored)
[CIS - SLES12 - 6.11 - imap enabled on xinetd {CIS: 6.11 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/cyrus-imapd -> !r:^# && r:disable && r:no;

[CIS - SLES12 - 6.11 - pop3 enabled on xinetd {CIS: 6.11 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/xinetd.d/dovecot -> !r:^# && r:disable && r:no;

# 6.12 Remove Samba (Not Scored)
[CIS - SLES12 - 6.12 - Disable standard boot services - Samba Enabled {CIS: 6.12 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dsamba$;
d:$rc_dirs -> ^S\d\dsmb$;

# 6.13 Remove HTTP Proxy Server (Not Scored)
[CIS - SLES12 - 6.13 - Disable standard boot services - Squid Enabled {CIS: 6.13 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dsquid$;

# 6.14 Remove SNMP Server (Not Scored)
[CIS - SLES12 - 6.14 - Disable standard boot services - SNMPD process Enabled {CIS: 6.14 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dsnmpd$;

# 6.15 Configure Mail Transfer Agent for Local-Only Mode (Scored)
# TODO

# 6.16 Ensure rsync service is not enabled (Scored)
[CIS - SLES12 - 6.16 - Disable standard boot services - rsyncd process Enabled {CIS: 6.16 SLES12} {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\drsyncd$;

# 6.17 Ensure Biosdevname is not enabled (Scored)
# TODO

###############################################
# 7 Network Configuration and Firewalls
###############################################

###############################################
# 7.1 Modify Network Parameters (Host Only)
###############################################

# 7.1.1 Disable IP Forwarding (Scored)
[CIS - SLES12 - 7.1.1 - Network parameters - IP Forwarding enabled {CIS: 7.1.1 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/ip_forward -> 1;
f:/proc/sys/net/ipv6/ip_forward -> 1;

# 7.1.2 Disable Send Packet Redirects (Scored)
[CIS - SLES12 - 7.1.2 - Network parameters - IP send redirects enabled {CIS: 7.1.2 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/conf/all/send_redirects -> 0;
f:/proc/sys/net/ipv4/conf/default/send_redirects -> 0;

###############################################
# 7.2 Modify Network Parameters (Host and Router)
###############################################

# 7.2.1 Disable Source Routed Packet Acceptance (Scored)
[CIS - SLES12 - 7.2.1 - Network parameters - Source routing accepted {CIS: 7.2.1 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;

# 7.2.2 Disable ICMP Redirect Acceptance (Scored)
[CIS - SLES12 - 7.2.2 - Network parameters - ICMP redirects accepted {CIS: 7.2.2 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/conf/all/accept_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/accept_redirects -> 1;

# 7.2.3 Disable Secure ICMP Redirect Acceptance (Scored)
[CIS - SLES12 - 7.2.3 - Network parameters - ICMP secure redirects accepted {CIS: 7.2.3 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/conf/all/secure_redirects -> 1;
f:/proc/sys/net/ipv4/conf/default/secure_redirects -> 1;

# 7.2.4 Log Suspicious Packets (Scored)
[CIS - SLES12 - 7.2.4 - Network parameters - martians not logged {CIS: 7.2.4 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/conf/all/log_martians -> 0;

# 7.2.5 Enable Ignore Broadcast Requests (Scored)
[CIS - SLES12 - 7.2.5 - Network parameters - ICMP broadcasts accepted {CIS: 7.2.5 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;

# 7.2.6 Enable Bad Error Message Protection (Scored)
[CIS - SLES12 - 7.2.6 - Network parameters - Bad error message protection not enabled {CIS: 7.2.6 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses -> 0;

# 7.2.7 Enable RFC-recommended Source Route Validation (Scored)
[CIS - SLES12 - 7.2.7 - Network parameters - RFC Source route validation not enabled  {CIS: 7.2.7 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/conf/all/rp_filter -> 0;
f:/proc/sys/net/ipv4/conf/default/rp_filter -> 0;

# 7.2.8 Enable TCP SYN Cookies (Scored)
[CIS - SLES12 - 7.2.8 - Network parameters - SYN Cookies not enabled {CIS: 7.2.8 SLES12} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/proc/sys/net/ipv4/tcp_syncookies -> 0;

###############################################
# 7.3 Configure IPv6
###############################################

# 7.3.1 Disable IPv6 Router Advertisements (Not Scored)

# 7.3.2 Disable IPv6 Redirect Acceptance (Not Scored)

# 7.3.3 Disable IPv6 (Not Scored)

###############################################
# 7.4 Install TCP Wrappers
###############################################

# 7.4.1 Install TCP Wrappers (Not Scored)

# 7.4.2 Create /etc/hosts.allow (Not Scored)

# 7.4.3 Verify Permissions on /etc/hosts.allow (Scored)
# TODO

# 7.4.4 Create /etc/hosts.deny (Not Scored)

# 7.5.5 Verify Permissions on /etc/hosts.deny (Scored)
# TODO

###############################################
# 7.5 Uncommon Network Protocols
###############################################

# 7.5.1 Disable DCCP (Not Scored)

# 7.5.2 Disable SCTP (Not Scored)

# 7.5.3 Disable RDS (Not Scored)

# 7.5.4 Disable TIPC (Not Scored)

# 7.6 Deactivate Wireless Interfaces (Not Scored)

# 7.7 Enable SuSEfirewall2 (Scored)

# 7.8 Limit access to trusted networks (Not Scored)

###############################################
# 8 Logging and Auditing
###############################################

###############################################
# 8.1 Configure System Accounting (auditd)
###############################################

###############################################
# 8.1.1 Configure Data Retention
###############################################

# 8.1.1.1 Configure Audit Log Storage Size (Not Scored)

# 8.1.1.2 Disable System on Audit Log Full (Not Scored)

# 8.1.1.3 Keep All Auditing Information (Scored)

# 8.1.2 Enable auditd Service (Scored)

# 8.1.3 Enable Auditing for Processes That Start Prior to auditd (Scored)

# 8.1.4 Record Events That Modify Date and Time Information (Scored)

# 8.1.5 Record Events That Modify User/Group Information (Scored)

# 8.1.6 Record Events That Modify the System’s Network Environment (Scored)

# 8.1.7 Record Events That Modify the System’s Mandatory Access Controls (Scored)

# 8.1.8 Collect Login and Logout Events (Scored)

# 8.1.9 Collect Session Initiation Information (Scored)

# 8.1.10 Collect Discretionary Access Control Permission Modification Events (Scored)

# 8.1.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)

# 8.1.12 Collect Use of Privileged Commands (Scored)

# 8.1.13 Collect Successful File System Mounts (Scored)

# 8.1.14 Collect File Deletion Events by User (Scored)

# 8.1.15 Collect Changes to System Administration Scope (sudoers) (Scored)

# 8.1.16 Collect System Administrator Actions (sudolog) (Scored)

# 8.1.17 Collect Kernel Module Loading and Unloading (Scored)

# 8.1.18 Make the Audit Configuration Immutable (Scored)

###############################################
# 8.2 Configure rsyslog
###############################################

# 8.2.1 Install the rsyslog package (Scored)
# TODO

# 8.2.2 Activate the rsyslog Service (Scored)
# TODO

# 8.2.3 Configure /etc/rsyslog.conf (Not Scored)

# 8.2.4 Create and Set Permissions on rsyslog Log Files (Scored)

# 8.2.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)

# 8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)

###############################################
# 8.3 Advanced Intrusion Detection Environment (AIDE)
###############################################

# 8.3.1 Install AIDE (Scored)

# 8.3.2 Implement Periodic Execution of File Integrity (Scored)

# 8.4 Configure logrotate (Not Scored)

###############################################
# 9 System Access, Authentication and Authorization
###############################################

###############################################
# 9.1 Configure cron and anacron
###############################################

# 9.1.1 Enable cron Daemon (Scored)

# 9.1.2 Set User/Group Owner and Permission on /etc/crontab (Scored)

# 9.1.3 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)

# 9.1.4 Set User/Group Owner and Permission on /etc/cron.daily (Scored)

# 9.1.5 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)

# 9.1.6 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)

# 9.1.7 Set User/Group Owner and Permission on /etc/cron.d (Scored)

# 9.1.8 Restrict at/cron to Authorized Users (Scored)

###############################################
# 9.2 Configure SSH
###############################################

# 9.2.1 Set SSH Protocol to 2 (Scored)
[CIS - SLES12 - 9.2.1 - SSH Configuration - Protocol version 1 enabled {CIS: 9.2.1 SLES12} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+1;

# 9.2.2 Set LogLevel to INFO (Scored)
[CIS - SLES12 - 9.2.1 - SSH Configuration - Loglevel not INFO {CIS: 9.2.1 SLES12} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && !r:LogLevel\.+INFO;

# 9.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)
# TODO

# 9.2.4 Disable SSH X11 Forwarding (Scored)
# TODO

# 9.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)
[ CIS - SLES12 - 9.2.5 - SSH Configuration - Set SSH MaxAuthTries to 4 or Less  {CIS - SLES12 - 9.2.5} {PCI_DSS: 2.2.4}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:MaxAuthTries && !r:3\s*$;
f:/etc/ssh/sshd_config -> r:^#\s*MaxAuthTries;
f:/etc/ssh/sshd_config -> !r:MaxAuthTries;

# 9.2.6 Set SSH IgnoreRhosts to Yes (Scored)
[CIS - SLES12 - 9.2.6 - SSH Configuration - IgnoreRHosts disabled {CIS: 9.2.6 SLES12} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;

# 9.2.7 Set SSH HostbasedAuthentication to No (Scored)
[CIS - SLES12 - 9.2.7 - SSH Configuration - Host based authentication enabled {CIS: 9.2.7 SLES12} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;

# 9.2.8 Disable SSH Root Login (Scored)
[CIS - SLES12 - 9.2.8 - SSH Configuration - Root login allowed {CIS: 9.2.8 SLES12} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;
f:/etc/ssh/sshd_config -> r:^#\s*PermitRootLogin;

# 9.2.9 Set SSH PermitEmptyPasswords to No (Scored)
[CIS - SLES12 - 9.2.9 - SSH Configuration - Empty passwords permitted {CIS: 9.2.9 SLES12} {PCI_DSS: 4.1}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;
f:/etc/ssh/sshd_config -> r:^#\s*PermitEmptyPasswords;

# 9.2.10 Do Not Allow Users to Set Environment Options (Scored)

# 9.2.11 Use Only Approved Ciphers in Counter Mode (Scored)

# 9.2.12 Set Idle Timeout Interval for User Login (Not Scored)

# 9.2.13 Limit Access via SSH (Scored)

# 9.2.14 Set SSH Banner (Scored)

###############################################
# 9.3 Configure PAM
###############################################

# 9.3.1 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)

# 9.3.2 Set Lockout for Failed Password Attempts (Not Scored)

# 9.3.3 Limit Password Reuse (Scored)

# 9.4 Restrict root Login to System Console (Not Scored)

# 9.5 Restrict Access to the su Command (Scored)

###############################################
# 10 User Accounts and Environment
###############################################

###############################################
# 10.1 Set Shadow Password Suite Parameters (/etc/login.defs)
###############################################

# 10.1.1 Set Password Expiration Days (Scored)

# 10.1.2 Set Password Change Minimum Number of Days (Scored)

# 10.1.3 Set Password Expiring Warning Days (Scored)

# 10.2 Disable System Accounts (Scored)

# 10.3 Set Default Group for root Account (Scored)

# 10.4 Set Default umask for Users (Scored)

# 10.5 Lock Inactive User Accounts (Scored)


###############################################
# 11 Warning Banners
###############################################

# 11.1 Set Warning Banner for Standard Login Services (Scored)

# 11.2 Remove OS Information from Login Warning Banners (Scored)

# 11.3 Set Graphical Warning Banner (Not Scored)

###############################################
# 12 Verify System File Permissions
###############################################

# 12.1 Verify System File Permissions (Not Scored)

# 12.2 Verify Permissions on /etc/passwd (Scored)

# 12.3 Verify Permissions on /etc/shadow (Scored)

# 12.4 Verify Permissions on /etc/group (Scored)

# 12.5 Verify User/Group Ownership on /etc/passwd (Scored)

# 12.6 Verify User/Group Ownership on /etc/shadow (Scored)

# 12.7 Verify User/Group Ownership on /etc/group (Scored)

# 12.8 Find World Writable Files (Not Scored)

# 12.9 Find Un-owned Files and Directories (Scored)

# 12.10 Find Un-grouped Files and Directories (Scored)

# 12.11 Find SUID System Executables (Not Scored)

# 12.12 Find SGID System Executables (Not Scored)

###############################################
# 13 Review User and Group Settings
###############################################

# 13.1 Ensure Password Fields are Not Empty (Scored)

# 13.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)

# 13.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)

# 13.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)

# 13.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
[CIS - SLES12 - 13.5 - Non-root account with uid 0 {CIS: 13.5 SLES12} {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;

# 13.6 Ensure root PATH Integrity (Scored)

# 13.7 Check Permissions on User Home Directories (Scored)

# 13.8 Check User Dot File Permissions (Scored)

# 13.9 Check Permissions on User .netrc Files (Scored)

# 13.10 Check for Presence of User .rhosts Files (Scored)

# 13.11 Check Groups in /etc/passwd (Scored)

# 13.12 Check That Users Are Assigned Valid Home Directories (Scored)

# 13.13 Check User Home Directory Ownership (Scored)

# 13.14 Check for Duplicate UIDs (Scored)

# 13.15 Check for Duplicate GIDs (Scored)

# 13.16 Check for Duplicate User Names (Scored)

# 13.17 Check for Duplicate Group Names (Scored)

# 13.18 Check for Presence of User .netrc Files (Scored)

# 13.19 Check for Presence of User .forward Files (Scored)

# 13.20 Ensure shadow group is empty (Scored)


# Other/Legacy Tests
[CIS - SLES12 - X.X.X - Account with empty password present {PCI_DSS: 10.2.5}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/shadow -> r:^\w+::;

[CIS - SLES12 - X.X.X - User-mounted removable partition allowed on the console] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
f:/etc/security/console.perms -> r:^<console>  \d+ <cdrom>;
f:/etc/security/console.perms -> r:^<console>  \d+ <floppy>;

[CIS - SLES12 - X.X.X - Disable standard boot services - Kudzu hardware detection Enabled] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dkudzu$;

[CIS - SLES12 - X.X.X - Disable standard boot services - PostgreSQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dpostgresql$;

[CIS - SLES12 - X.X.X - Disable standard boot services - MySQL server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dmysqld$;

[CIS - SLES12 - X.X.X - Disable standard boot services - DNS server Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dnamed$;

[CIS - SLES12 - X.X.X - Disable standard boot services - NetFS Enabled {PCI_DSS: 2.2.2}] [any] [https://benchmarks.cisecurity.org/tools2/linux/CIS_SUSE_Linux_Enterprise_Server_12_Benchmark_v1.0.0.pdf]
d:$rc_dirs -> ^S\d\dnetfs$;
!94882 cis_win2012r2_domainL1_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2018 OSSEC Project
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Windows Server 2012 R2 Domain Controller L1
# Based on Center for Internet Security Benchmark v2.2.1 for Microsoft Windows Server 2012 R2 (https://workbench.cisecurity.org/benchmarks/288)
#
#
#
#1.1.2 Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
[CIS - Microsoft Windows Server 2012 R2 - Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 0;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 3D;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 3E;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 3F;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:4\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:5\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:6\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:7\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:8\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:9\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:A\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:B\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:C\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:D\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:E\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:F\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:\w\w\w+;
#
#
#2.3.1.2 Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.1.2: Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> NoConnectedUser -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> NoConnectedUser -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !NoConnectedUser;
#
#
#2.3.1.4 Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.1.4: Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LimitBlankPasswordUse -> 0;
#
#
#2.3.2.1 Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.2.1: Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> SCENoApplyLegacyAuditPolicy -> !1;
#
#
#2.3.2.2 Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.2.2: Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> CrashOnAuditFail -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> CrashOnAuditFail -> 2;
#
#
#2.3.4.1 Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators' 
[CIS - Microsoft Windows Server 2012 R2 - 2.3.4.1: Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> AllocateDASD -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> AllocateDASD -> 2;
#
#
#2.3.4.2 Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.4.2: Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers -> AddPrinterDrivers -> !1;
#
#
#2.3.5.1 Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)
[CIS - Microsoft Windows Server 2012 R2 - 2.3.5.1: Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl -> !0;

#
#
#2.3.5.2 Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.5.2: Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters -> LDAPServerIntegrity -> !2;
#
#
#2.3.5.3 Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.5.3: Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> RefusePasswordChange -> 1;
#
#
#2.3.6.1 Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.1: Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> RequireSignOrSeal -> 0;
#
#
#2.3.6.2 Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.2: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> SealSecureChannel -> 0;
#
#
#2.3.6.3 Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.3: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> SignSecureChannel -> 0;
#
#
#2.3.6.4 Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.4: Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> DisablePasswordChange -> 1;
#
#
#2.3.6.6 Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.6: Ensure 'Domain member: Require strong session key' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> RequireStrongKey -> 0;
#
#
#2.3.7.1 Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.1: Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> DontDisplayLastUserName -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !DontDisplayLastUserName;
#
#
#2.3.7.2 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.2: Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> DisableCAD -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !DisableCAD;
#
#
#2.3.7.3 Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.3: Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 385;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 386;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 387;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 388;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 389;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:38\D;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:39\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:3\D\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:4\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:5\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:6\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:7\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:8\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:9\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:\D\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:\w\w\w\w+;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !InactivityTimeoutSecs;
#
#
#2.3.7.7 Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.7: Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 2;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 3;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 4;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 0F;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:1\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:2\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:3\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:4\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:5\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:6\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:7\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:8\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:9\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:\D\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:\w\w\w+;
#
#
#2.3.7.9 Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.9: Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> ScRemoveOption -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> !ScRemoveOption;
#
#
#2.3.8.1 Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.8.1: Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> RequireSecuritySignature -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> !RequireSecuritySignature;
#
#
#2.3.8.2 Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.8.2: Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> EnableSecuritySignature -> !1;
#
#
#2.3.8.3 Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.8.3: Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> EnablePlainTextPassword -> !0;
#
#
#2.3.9.1 Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.1: Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> 0;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:1\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:2\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:3\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:4\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:5\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:6\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:7\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:8\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:9\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:\D\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:\w\w\w+;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !AutoDisconnect;
#
#
#2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.2: Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> RequireSecuritySignature -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !RequireSecuritySignature;
#
#
#2.3.9.3 Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.3: Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> EnableSecuritySignature -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !EnableSecuritySignature;
#
#
#2.3.9.4 Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.4: Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> EnableForcedLogOff -> !1;
#
#
#2.3.10.5 Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.5: Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> EveryoneIncludesAnonymous -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> EveryoneIncludesAnonymous -> 2;
#
#
#2.3.10.6 Configure 'Network access: Named Pipes that can be accessed anonymously'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.6: Configure 'Network access: Named Pipes that can be accessed anonymously'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> NullSessionPipes -> !r:lsarpc|netlogon|samr;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !NullSessionPipes;
#
#
#2.3.10.7 Configure 'Network access: Remotely accessible registry paths'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.7: Configure 'Network access: Remotely accessible registry paths'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths -> Machine -> !r:System\\CurrentControlSet\\Control\\ProductOptions|System\\CurrentControlSet\\Control\\Server Applications|Software\\Microsoft\\Windows NT\\CurrentVersion;
#
#
#2.3.10.8 Configure 'Network access: Remotely accessible registry paths and sub-paths'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.8: Configure 'Network access: Remotely accessible registry paths and sub-paths'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths -> Machine -> !r:Software\\Microsoft\\Windows NT\\CurrentVersion\\Print|Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows|System\\CurrentControlSet\\Control\\Print\\Printers|System\\CurrentControlSet\\Services\\Eventlog|Software\\Microsoft\\OLAP Server|System\\CurrentControlSet\\Control\\ContentIndex|System\\CurrentControlSet\\Control\\Terminal Server|System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig|System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration|Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib|System\\CurrentControlSet\\Services\\SysmonLog|System\\CurrentControlSet\\Services\\CertSvc|System\\CurrentControlSet\\Services\\WINS;
#
#
#2.3.10.9 Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.9: Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> RestrictNullSessAccess -> !1;
#
#
#2.3.10.10 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.10: Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> NullSessionShares -> r:\.+;
#
#
#2.3.10.11 Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.11: Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> ForceGuest -> 1;
#
#
#2.3.11.1 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.1: Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> UseMachineId -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> !UseMachineId;
#
#
#2.3.11.2 Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.2: Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> allownullsessionfallback -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> !allownullsessionfallback;
#
#
#2.3.11.3 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.3: Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u -> AllowOnlineID -> !0;
#
#
#2.3.11.4 Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.4: Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters -> SupportedEncryptionTypes -> !2147483644;
#
#
#2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.5: Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> NoLMHash -> 0;
#
#
#2.3.11.6 Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.6: Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -> EnableForcedLogOff -> !1;
#
#
#2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.7: Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 0;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 2;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 3;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 4;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> !LmCompatibilityLevel;
#
#
#2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP -> LDAPClientIntegrity -> !1;
#
#
#2.3.11.9 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.9: Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption''] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinClientSec -> !537395200;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> !NTLMMinClientSec;
#
#
#2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.10: Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinServerSec -> !537395200;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> !NTLMMinServerSec;
#
#
#2.3.13.1 Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.13.1: Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ShutdownWithoutLogon -> 1;
#
#
#2.3.15.1 Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.15.1: Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel -> ObCaseInsensitive -> !1;
#
#
#2.3.15.2 Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.15.2: Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager -> ProtectionMode -> !1;
#
#
#2.3.17.1 Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.1: Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> FilterAdministratorToken -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !FilterAdministratorToken;
#
#
#2.3.17.2 Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.2: Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableUIADesktopToggle -> 1;
#
#
#2.3.17.3 Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.3: Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorAdmin -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorAdmin -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !ConsentPromptBehaviorAdmin;
#
#
#2.3.17.4 Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.4: Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorUser -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !ConsentPromptBehaviorUser;
#
#
#2.3.17.5 Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.5: Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableInstallerDetection -> 0;
r:HKEY_LOCAL_MACHINE\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !EnableInstallerDetection;
#
#
#2.3.17.6 Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.6: Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableSecureUIAPaths -> 0;
#
#
#2.3.17.7 Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.7: Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableLUA -> 0;
#
#
#2.3.17.8 Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.8: Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> PromptOnSecureDesktop -> 0;
#
#
#2.3.17.9 Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.9: Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableVirtualization -> 0;
#
#
#9.1.1 Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.1: Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> EnableFirewall -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> EnableFirewall -> 0;
#
#
#9.1.2 Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.2: Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> DefaultInboundAction -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> DefaultInboundAction -> 0;
#
#
#9.1.3 Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.3: Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> DefaultOutboundAction -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> DefaultOutboundAction -> 1;
#
#
#9.1.4 Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.4: Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> !DisableNotifications;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> !DisableNotifications;
#
#
#9.1.5 Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.5: Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> AllowLocalPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> AllowLocalPolicyMerge -> 0;
#
#
#9.1.6 Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.6: Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> AllowLocalIPsecPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> AllowLocalIPsecPolicyMerge -> 0;
#
#
#9.1.7 Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.7: Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
#
#
#9.1.8 Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16384 KB or greater'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.8: Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16384 KB or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:3\w\w\w;
#
#
#9.1.9 Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.9: Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogDroppedPackets -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogDroppedPackets -> 0;
#
#
#9.1.10 Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.10: Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogSuccessfulConnections -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogSuccessfulConnections -> 0;
#
#
#9.2.1 Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.1: Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> EnableFirewall -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> EnableFirewall -> 0;
#
#
#9.2.2 Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.2: Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> DefaultInboundAction -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> DefaultInboundAction -> 0;
#
#
#9.2.3 Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.3: Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> DefaultOutboundAction -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> DefaultOutboundAction -> 1;
#
#
#9.2.4 Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.4: Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> DisableNotifications -> 0;
#
#
#9.2.5 Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.5: Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> AllowLocalPolicyMerge -> 0; 
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> AllowLocalPolicyMerge -> 0;
#
#
#9.2.6 Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.6: Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> AllowLocalIPsecPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> AllowLocalIPsecPolicyMerge -> 0;
#
#
#9.2.7 Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.7: Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
#
#
#9.2.8 Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16384 KB or greater'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.8: Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16384 KB or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:\w; 
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:3\w\w\w;
#
#
#9.2.9 Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.9: Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogDroppedPackets -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogDroppedPackets -> 0;
#
#
#9.2.10 Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.10: Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogSuccessfulConnections -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogSuccessfulConnections -> 0;
#
#
#9.3.1 Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.1: Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> EnableFirewall -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> EnableFirewall -> 0;
#
#
#9.3.2 Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.2: Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> DefaultInboundAction -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> DefaultInboundAction -> 0;
#
#
#9.3.3 Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.3: Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> DefaultOutboundAction -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> DefaultOutboundAction -> 1;
#
#
#9.3.4 Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.4: Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> DisableNotifications -> 0;
#
#
#9.3.5 Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.5: Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> AllowLocalPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> AllowLocalPolicyMerge -> 0;
#
#
#9.3.6 Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.6: Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> AllowLocalIPsecPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> AllowLocalIPsecPolicyMerge -> 0;
#
#
#9.3.7 Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.7: Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog; 
#
#
#9.3.8 Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16384 KB or greater'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.8: Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16384 KB or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:3\w\w\w;
#
#
#9.3.9 Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.9: Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogDroppedPackets -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogDroppedPackets -> 0;
#
#
#9.3.10 Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.10: Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogSuccessfulConnections -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogSuccessfulConnections -> 0;
#
#
#18.1.1.1 Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.1.1.1: Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> NoLockScreenCamera -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> !NoLockScreenCamera;
#
#
#18.1.1.2 Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.1.1.2: Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> NoLockScreenSlideshow -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> !NoLockScreenSlideshow;
#
#
#18.3.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.1: Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> AutoAdminLogon -> !0;
#
#
#18.3.2 Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.2: Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -> DisableIPSourceRouting -> !2;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -> !DisableIPSourceRouting;
#
#
#18.3.3 Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.3: Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> DisableIPSourceRouting -> !2;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !DisableIPSourceRouting;
#
#
#18.3.4 Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.4: Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> EnableICMPRedirect -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !EnableICMPRedirect;
#
#
#18.3.6 Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.6: Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters -> NoNameReleaseOnDemand -> !1;
#
#
#18.3.8 Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.8: Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager -> SafeDllSearchMode -> 0;
#
#
#18.3.9 Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.9: Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 6;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 7;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 8;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 9;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> r:\w\w+;
#
#
#18.3.12 Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.12: Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5B;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5C;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5D;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5E;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5F;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:6\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:7\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:8\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:9\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:\D\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:\w\w\w+;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> !WarningLevel;
#
#
#18.4.11.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.11.2: Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> NC_AllowNetBridge_NLA -> 1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> !NC_AllowNetBridge_NLA;
#
#
#18.4.11.3 Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.11.3: Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> NC_StdDomainUserSetLocation -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> !NC_StdDomainUserSetLocation;
#
#
#18.4.21.1 Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.21.1: Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -> fMinimizeConnections -> !1;
#
#
#18.6.2 Ensure 'WDigest Authentication' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.6.2: Ensure 'WDigest Authentication' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -> UseLogonCredential -> !0;
#
#
#18.8.3.1 Ensure 'Include command line in process creation events' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.3.1: Ensure 'Include command line in process creation events' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -> ProcessCreationIncludeCmdLine_Enabled -> !0;
#
#
#18.8.12.1 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.12.1: Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch -> DriverLoadPolicy -> !3;
#
#
#18.8.19.2 Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.19.2: Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> NoBackgroundPolicy -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> !NoBackgroundPolicy;
#
#
#18.8.19.3 Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.19.3: Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> NoGPOListChanges -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> !NoGPOListChanges;
#
#
#18.8.19.4 Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.19.4: Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> DisableBkGndGroupPolicy -> !0;
#
#
#18.8.25.1 Ensure 'Do not display network selection UI' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.1: Ensure 'Do not display network selection UI' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> DontDisplayNetworkSelectionUI -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !DontDisplayNetworkSelectionUI;
#
#
#18.8.25.2 Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.2: Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> DontEnumerateConnectedUsers -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !DontEnumerateConnectedUsers;
#
#
#18.8.25.3 Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.3: Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> EnumerateLocalUsers -> !0;
#
#
#18.8.25.4 Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.4: Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> DisableLockScreenAppNotifications -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !DisableLockScreenAppNotifications;
#
#
#18.8.25.5 Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.5: Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> AllowDomainPINLogon -> !0;
#
#
#18.8.31.1 Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.31.1: Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fAllowUnsolicited -> !0;
#
#
#18.8.31.2 Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.31.2: Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fAllowToGetHelp -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fAllowToGetHelp;
#
#
#18.9.6.1 Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.6.1: Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> MSAOptional -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> !MSAOptional;
#
#
#18.9.8.1 Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.8.1: Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoAutoplayfornonVolume -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoAutoplayfornonVolume;
#
#
#18.9.8.2 Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.8.2: Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoAutorun -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoAutorun;
#
#
#18.9.8.3 Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.8.3: Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer-> NoDriveTypeAutoRun -> !ff;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer-> !NoDriveTypeAutoRun;
#
#
#18.9.15.1 Ensure 'Do not display the password reveal button' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.15.1: Ensure 'Do not display the password reveal button' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI -> DisablePasswordReveal -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI -> !DisablePasswordReveal;
#
#
#18.9.15.2 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.15.2: Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI -> EnumerateAdministrators -> !0;
#
#
#18.9.26.1.1 Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.1.1: Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> Retention -> !0;
#
#
#18.9.26.1.2 Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.1.2: Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:0\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:4\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:5\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:6\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:7\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> !MaxSize;
#
#
#18.9.26.2.1 Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.2.1: Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> Retention -> !0;
#
#
#18.9.26.2.2 Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.2.2: Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:0\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:1\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:2\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> !MaxSize;
#
#
#18.9.26.3.1 Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.3.1: Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> Retention -> !0;
#
#
#18.9.26.3.2 Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.3.2: Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:0\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:4\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:5\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:6\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:7\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> !MaxSize;
#
#
#18.9.26.4.1 Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.4.1: Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> Retention -> !0;
#
#
#18.9.26.4.2 Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.4.2: Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:0\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:4\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:5\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:6\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:7\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> !MaxSize;
#
#
#18.9.30.2 Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.2: Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> EnableSmartScreen -> !2;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !EnableSmartScreen;
#
#
#18.9.30.3 Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.3: Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoDataExecutionPrevention -> !0;
#
#
#18.9.30.4 Ensure 'Turn off heap termination on corruption' is set to 'Disabled'[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.4: Ensure 'Turn off heap termination on corruption' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoHeapTerminationOnCorruption -> !0;
#
#
#18.9.30.5 Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.5: Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> PreXPSP2ShellProtocolBehavior -> !0;
#
#
#18.9.47.1 Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.47.1: Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive -> DisableFileSyncNGSC -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive -> !DisableFileSyncNGSC;
#
#
#18.9.47.2 Ensure 'Prevent the usage of OneDrive for file storage on Windows 8.1' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.47.2: Ensure 'Prevent the usage of OneDrive for file storage on Windows 8.1' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Skydrive -> DisableFileSync -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Skydrive -> !DisableFileSync;
#
#
#18.9.52.2.2 Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.2.2: Ensure 'Do not allow passwords to be saved' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> DisablePasswordSaving -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !DisablePasswordSaving;
#
#
#18.9.52.3.3.2 Ensure 'Do not allow drive redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.2: Ensure 'Do not allow drive redirection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisableCdm -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisableCdm;
#
#
#18.9.52.3.9.1 Ensure 'Always prompt for password upon connection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.9.1: Ensure 'Always prompt for password upon connection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fPromptForPassword -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fPromptForPassword;
#
#
#18.9.52.3.9.2 Ensure 'Require secure RPC communication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.9.2: Ensure 'Require secure RPC communication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fEncryptRPCTraffic -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fEncryptRPCTraffic;
#
#
#18.9.52.3.9.3 Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.9.3: Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MinEncryptionLevel -> !3;
#
#
#18.9.52.3.11.1 Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.11.1: Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> DeleteTempDirsOnExit -> !1;
#
#
#18.9.52.3.11.2 Ensure 'Do not use temporary folders per session' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.11.2: Ensure 'Do not use temporary folders per session' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> PerSessionTempDir -> !1;
#
#
#18.9.53.1 Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.53.1: Ensure 'Prevent downloading of enclosures' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds -> DisableEnclosureDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds -> !DisableEnclosureDownload;
#
#
#18.9.54.2 Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.54.2: Ensure 'Allow indexing of encrypted files' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search -> AllowIndexingEncryptedStoresOrItems -> !0;
#
#
#18.9.61.1 Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.61.1: Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> AutoDownload -> !4;
#
#
#18.9.61.2 Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.61.2: Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> DisableOSUpgrade -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> !DisableOSUpgrade;
#
#
#18.9.70.2.1 Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.70.2.1: Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent -> DefaultConsent -> !1;
#
#
#18.9.70.3 Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.70.3: Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> AutoApproveOSDumps -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !AutoApproveOSDumps;
#
#
#18.9.74.1 Ensure 'Allow user control over installs' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.74.1: Ensure 'Allow user control over installs' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer -> EnableUserControl -> !0;
#
#
#18.9.74.2 Ensure 'Always install with elevated privileges' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.74.2: Ensure 'Always install with elevated privileges' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer -> AlwaysInstallElevated -> !0;
#
#
#18.9.75.1 Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.75.1: Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> DisableAutomaticRestartSignOn -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> !DisableAutomaticRestartSignOn;
#
#
#18.9.84.1 Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'[CIS - Microsoft Windows Server 2012 R2 - 18.9.84.1: Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -> EnableScriptBlockLogging -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -> !EnableScriptBlockLogging;
#
#
#18.9.84.2 Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.84.2: Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -> EnableTranscripting -> !0;
#
#
#18.9.86.1.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.1.1: Ensure 'Allow Basic authentication' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> AllowBasic -> !0;
#
#
#18.9.86.1.2 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.1.2: Ensure 'Allow unencrypted traffic' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> AllowUnencryptedTraffic -> !0;
#
#
#18.9.86.1.3 Ensure 'Disallow Digest authentication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.1.3: Ensure 'Disallow Digest authentication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> AllowDigest -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> !AllowDigest;
#
#
#18.9.86.2.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.1: Ensure 'Allow Basic authentication' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> AllowBasic -> !0;
#
#
#18.9.86.2.3 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.3: Ensure 'Allow unencrypted traffic' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> AllowUnencryptedTraffic -> !0;
#
#
#18.9.86.2.4 Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.4: Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> DisableRunAs -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> !DisableRunAs;
#
#
#18.9.90.2 Ensure 'Configure Automatic Updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.90.2: Ensure 'Configure Automatic Updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> NoAutoUpdate -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> !NoAutoUpdate;
#
#
#18.9.90.3 Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.90.3: Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> ScheduledInstallDay -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> !ScheduledInstallDay;
#
#
#18.9.90.4 Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.90.4: Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> NoAutoRebootWithLoggedOnUsers -> !0;
#
!28011 cis_win2012r2_domainL2_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2018 OSSEC Project
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Windows Server 2012 R2 Domain Controller L2
# Based on Center for Internet Security Benchmark v2.2.1 for Microsoft Windows Server 2012 R2 (https://workbench.cisecurity.org/benchmarks/288)
#
#
#2.3.10.4 Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.4: Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> DisableDomainCreds -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> !DisableDomainCreds;
#
#
#18.3.5 Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.5: Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> KeepAliveTime -> !493e0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !KeepAliveTime;
#
#
#18.3.7 Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.7: Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> PerformRouterDiscovery  -> !0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !PerformRouterDiscovery;
#
#
#18.3.10 Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.10: Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> TcpMaxDataRetransmissions -> !3;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> !TcpMaxDataRetransmissions;
#
#
#18.3.11 Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.11: Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> TcpMaxDataRetransmissions -> !3;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !TcpMaxDataRetransmissions;
#
#
#18.4.9.1 Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.9.1: Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowLLTDIOOnDomain -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowLLTDIOOnPublicNet -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> EnableLLTDIO -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> ProhibitLLTDIOOnPrivateNet -> !0;
#
#
#18.4.9.2 Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.9.2: Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowRspndrOnDomain -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowRspndrOnPublicNet -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> EnableRspndr -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> ProhibitRspndrOnPrivateNet -> !0;
#
#
#18.4.10.2 Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.10.2: Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet -> !Disabled;
#
#
#18.4.19.2.1 Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
[CIS - Microsoft Windows Server 2012 R2 - 18.4.19.2.1: Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> DisabledComponents -> !ff;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> !DisabledComponents;
#
#
#18.4.20.1 Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.20.1: Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> EnableRegistrars -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !EnableRegistrars;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableUPnPRegistrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableUPnPRegistrar;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableInBand802DOT11Registrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableInBand802DOT11Registrar;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableFlashConfigRegistrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableFlashConfigRegistrar;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableWPDRegistrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableWPDRegistrar;
#
#
#18.4.20.2 Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.20.2: Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI -> DisableWcnUi -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI -> !DisableWcnUi;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
#18.8.24.1 Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.24.1: Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International -> BlockUserInputMethodsForSignIn -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International -> !BlockUserInputMethodsForSignIn;
#
#
#18.8.29.5.1 Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.29.5.1: Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> DCSettingIndex -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> !DCSettingIndex;
#
#
#18.8.29.5.2 Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.29.5.2: Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> ACSettingIndex -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> !ACSettingIndex;
#
#
#18.8.39.5.1 Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.39.5.1: Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy -> DisableQueryRemoteServer -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy -> !DisableQueryRemoteServer;
#
#
#18.8.39.11.1 Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.39.11.1: Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d} -> ScenarioExecutionEnabled -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d} -> !ScenarioExecutionEnabled;
#
#
#18.8.41.1 Ensure 'Turn off the advertising ID' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.41.1: Ensure 'Turn off the advertising ID' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -> DisabledByGroupPolicy -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -> !DisabledByGroupPolicy;
#
#
#18.8.44.1.1 Ensure 'Enable Windows NTP Client' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.44.1.1: Ensure 'Enable Windows NTP Client' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient -> Enabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient -> !Enabled;
#
#
#18.9.37.1 Ensure 'Turn off location' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.37.1: Ensure 'Turn off location' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors -> DisableLocation -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors -> !DisableLocation;
#
#
#18.9.52.3.2.1 Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.2.1: Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fSingleSessionPerUser -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fSingleSessionPerUser;
#
#
#18.9.52.3.3.1 Ensure 'Do not allow COM port redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.1: Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisableCcm -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisableCcm;
#
#
#18.9.52.3.3.3 Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.3: Ensure 'Do not allow LPT port redirection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisableLPT -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisableLPT;
#
#
#18.9.52.3.3.4 Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.4: Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisablePNPRedir -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisablePNPRedir;
#
#
#18.9.52.3.10.1 Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.10.1: Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba2;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba3;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba4;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba5;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba6;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba7;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba8;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba9;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba\D;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbb\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbc\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbd\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbe\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbf\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbc\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbd\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbe\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbf\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dc\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dd\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:de\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:df\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:e\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:f\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:\w\w\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !MaxIdleTime;
#
#
#18.9.52.3.10.2 Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.10.2: Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxDisconnectionTime -> !EA60;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !MaxDisconnectionTime;
#
#
#18.9.54.3 Ensure 'Set what information is shared in Search' is set to 'Enabled: Anonymous info'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.54.3: Ensure 'Set what information is shared in Search' is set to 'Enabled: Anonymous info'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search -> ConnectedSearchPrivacy -> !3;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search -> !ConnectedSearchPrivacy;
#
#
#18.9.59.1 Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.59.1: Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform -> NoGenTicket -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform -> !NoGenTicket;
#
#
#18.9.61.3 Ensure 'Turn off the Store application' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.61.3: Ensure 'Turn off the Store application' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> RemoveWindowsStore -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> !RemoveWindowsStore;
#
#
#18.9.69.3.1 Ensure 'Join Microsoft MAPS' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.69.3.1: Ensure 'Join Microsoft MAPS' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet -> SpynetReporting -> !0;
#
#
#18.9.74.3 Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.74.3: Ensure 'Join Microsoft MAPS' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer -> SafeForScripting -> !0;
#
#
#18.9.86.2.2 Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.2: Ensure 'Allow remote server management through WinRM' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> AllowAutoConfig -> !0;
#
#
#18.9.87.1 Ensure 'Allow Remote Shell Access' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.87.1: Ensure 'Allow Remote Shell Access' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS -> AllowRemoteShellAccess -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS -> !AllowRemoteShellAccess;
#
!100535 cis_win2012r2_memberL1_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2018 OSSEC Project
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Windows Server 2012 R2 Domain Controller L2
# Based on Center for Internet Security Benchmark v2.2.1 for Microsoft Windows Server 2012 R2 (https://workbench.cisecurity.org/benchmarks/288)
#
#
#1.1.2 Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
[CIS - Microsoft Windows Server 2012 R2 - Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 0;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 3D;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 3E;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> 3F;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:4\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:5\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:6\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:7\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:8\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:9\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:A\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:B\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:C\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:D\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:E\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:F\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> MaximumPasswordAge -> r:\w\w\w+;
#
#
#2.3.1.2 Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.1.2: Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> NoConnectedUser -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> NoConnectedUser -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !NoConnectedUser;
#
#
#2.3.1.4 Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.1.4: Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LimitBlankPasswordUse -> 0;
#
#
#2.3.2.1 Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.2.1: Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> SCENoApplyLegacyAuditPolicy -> !1;
#
#
#2.3.2.2 Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.2.2: Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> CrashOnAuditFail -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> CrashOnAuditFail -> 2;
#
#
#2.3.4.1 Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.4.1: Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> AllocateDASD -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> AllocateDASD -> 2;
#
#
#2.3.4.2 Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.4.2: Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers -> AddPrinterDrivers -> !1;
#
#
#2.3.6.1 Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.1: Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> RequireSignOrSeal -> 0;
#
#
#2.3.6.2 Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.2: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> SealSecureChannel -> 0;
#
#
#2.3.6.3 Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.3: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> SignSecureChannel -> 0;
#
#
#2.3.6.4 Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.4: Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> DisablePasswordChange -> 1;
#
#
#2.3.6.6 Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.6.6: Ensure 'Domain member: Require strong session key' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters -> RequireStrongKey -> 0;
#
#
#2.3.7.1 Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.1: Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> DontDisplayLastUserName -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !DontDisplayLastUserName;
#
#
#2.3.7.2 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.2: Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> DisableCAD -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !DisableCAD;
#
#
#2.3.7.3 Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.3: Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 385;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 386;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 387;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 388;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> 389;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:38\D;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:39\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:3\D\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:4\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:5\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:6\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:7\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:8\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:9\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:\D\w\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> InactivityTimeoutSecs -> r:\w\w\w\w+;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !InactivityTimeoutSecs;
#
#
#2.3.7.7 Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.7: Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 2;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 3;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 4;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> 0F;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:1\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:2\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:3\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:4\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:5\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:6\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:7\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:8\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:9\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:\D\w;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> PasswordExpiryWarning -> r:\w\w\w+;
#
#
#2.3.7.8 Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.8: Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ForceUnlockLogon -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> !ForceUnlockLogon;
#
#
#2.3.7.9 Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
[CIS - Microsoft Windows Server 2012 R2 - 2.3.7.9: Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> ScRemoveOption -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon -> !ScRemoveOption;
#
#
#2.3.8.1 Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.8.1: Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> RequireSecuritySignature -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> !RequireSecuritySignature;
#
#
#2.3.8.2 Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.8.2: Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> EnableSecuritySignature -> !1;
#
#
#2.3.8.3 Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.8.3: Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -> EnablePlainTextPassword -> !0;
#
#
#2.3.9.1 Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.1: Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> 0;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:1\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:2\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:3\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:4\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:5\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:6\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:7\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:8\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:9\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:\D\w;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> AutoDisconnect -> r:\w\w\w+;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !AutoDisconnect;
#
#
#2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.2: Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> RequireSecuritySignature -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !RequireSecuritySignature;
#
#
#2.3.9.3 Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.3: Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> EnableSecuritySignature -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !EnableSecuritySignature;
#
#
#2.3.9.4 Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.4: Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> EnableForcedLogOff -> !1;
#
#
#2.3.9.5 Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
[CIS - Microsoft Windows Server 2012 R2 - 2.3.9.5: Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -> SMBServerNameHardeningLevel -> !0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -> !SMBServerNameHardeningLevel;
#
#
#2.3.10.2 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.2: Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa -> RestrictAnonymousSAM -> 0;
#
#
#2.3.10.3 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.3: Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa -> RestrictAnonymous -> !1;
#
#
#2.3.10.5 Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.5: Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> EveryoneIncludesAnonymous -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> EveryoneIncludesAnonymous -> 2;
#
#
#2.3.10.6 Configure 'Network access: Named Pipes that can be accessed anonymously'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.6: Configure 'Network access: Named Pipes that can be accessed anonymously'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> NullSessionPipes -> !r:lsarpc|netlogon|samr;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> !NullSessionPipes;
#
#
#2.3.10.7 Configure 'Network access: Remotely accessible registry paths'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.7: Configure 'Network access: Remotely accessible registry paths'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths -> Machine -> !r:System\\CurrentControlSet\\Control\\ProductOptions|System\\CurrentControlSet\\Control\\Server Applications|Software\\Microsoft\\Windows NT\\CurrentVersion;
#
#
#2.3.10.8 Configure 'Network access: Remotely accessible registry paths and sub-paths'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.8: Configure 'Network access: Remotely accessible registry paths and sub-paths'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths -> Machine -> !r:Software\\Microsoft\\Windows NT\\CurrentVersion\\Print|Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows|System\\CurrentControlSet\\Control\\Print\\Printers|System\\CurrentControlSet\\Services\\Eventlog|Software\\Microsoft\\OLAP Server|System\\CurrentControlSet\\Control\\ContentIndex|System\\CurrentControlSet\\Control\\Terminal Server|System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig|System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration|Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib|System\\CurrentControlSet\\Services\\SysmonLog|System\\CurrentControlSet\\Services\\CertSvc|System\\CurrentControlSet\\Services\\WINS;
#
#
#2.3.10.9 Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.9: Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> RestrictNullSessAccess -> !1;
#
#
#2.3.10.10 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.10: Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -> NullSessionShares -> r:\.+;
#
#
#2.3.10.11 Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.11: Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> ForceGuest -> 1;
#
#
#2.3.11.1 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.1: Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> UseMachineId -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> !UseMachineId;
#
#
#2.3.11.2 Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.2: Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> allownullsessionfallback -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> !allownullsessionfallback;
#
#
#2.3.11.3 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.3: Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u -> AllowOnlineID -> !0;
#
#
#2.3.11.4 Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.4: Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters -> SupportedEncryptionTypes -> !2147483644;
#
#
#2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.5: Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> NoLMHash -> 0;
#
#
#2.3.11.6 Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.6: Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -> EnableForcedLogOff -> !1;
#
#
#2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.7: Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 0;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 2;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 3;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> LmCompatibilityLevel -> 4;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> !LmCompatibilityLevel;
#
#
#2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP -> LDAPClientIntegrity -> !1;
#
#
#2.3.11.9 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.9: Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption''] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinClientSec -> !537395200;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> !NTLMMinClientSec;
#
#
#2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.11.10: Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinServerSec -> !537395200;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> !NTLMMinServerSec;
#
#
#2.3.13.1 Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.13.1: Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ShutdownWithoutLogon -> 1;
#
#
#2.3.15.1 Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.15.1: Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel -> ObCaseInsensitive -> !1;
#
#
#2.3.15.2 Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.15.2: Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager -> ProtectionMode -> !1;
#
#
#2.3.17.1 Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.1: Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> FilterAdministratorToken -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !FilterAdministratorToken;
#
#
#2.3.17.2 Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.2: Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableUIADesktopToggle -> 1;
#
#
#2.3.17.3 Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.3: Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorAdmin -> 0;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorAdmin -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !ConsentPromptBehaviorAdmin;
#
#
#2.3.17.4 Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.4: Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> ConsentPromptBehaviorUser -> 1;
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !ConsentPromptBehaviorUser;
#
#
#2.3.17.5 Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.5: Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableInstallerDetection -> 0;
r:HKEY_LOCAL_MACHINE\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> !EnableInstallerDetection;
#
#
#2.3.17.6 Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.6: Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableSecureUIAPaths -> 0;
#
#
#2.3.17.7 Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.7: Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableLUA -> 0;
#
#
#2.3.17.8 Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.8: Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> PromptOnSecureDesktop -> 0;
#
#
#2.3.17.9 Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.17.9: Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -> EnableVirtualization -> 0;
#
#
#9.1.1 Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.1: Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> EnableFirewall -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> EnableFirewall -> 0;
#
#
#9.1.2 Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.2: Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> DefaultInboundAction -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> DefaultInboundAction -> 0;
#
#
#9.1.3 Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.3: Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> DefaultOutboundAction -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> DefaultOutboundAction -> 1;
#
#
#9.1.4 Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.4: Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> !DisableNotifications;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> !DisableNotifications;
#
#
#9.1.5 Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.5: Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> AllowLocalPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> AllowLocalPolicyMerge -> 0;
#
#
#9.1.6 Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.6: Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -> AllowLocalIPsecPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -> AllowLocalIPsecPolicyMerge -> 0;
#
#
#9.1.7 Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.7: Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
#
#
#9.1.8 Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16384 KB or greater'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.8: Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16384 KB or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogFileSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogFileSize -> r:3\w\w\w;
#
#
#9.1.9 Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.9: Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogDroppedPackets -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogDroppedPackets -> 0;
#
#
#9.1.10 Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.1.10: Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -> LogSuccessfulConnections -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging -> LogSuccessfulConnections -> 0;
#
#
#9.2.1 Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.1: Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> EnableFirewall -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> EnableFirewall -> 0;
#
#
#9.2.2 Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.2: Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> DefaultInboundAction -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> DefaultInboundAction -> 0;
#
#
#9.2.3 Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.3: Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> DefaultOutboundAction -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> DefaultOutboundAction -> 1;
#
#
#9.2.4 Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.4: Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> DisableNotifications -> 0;
#
#
#9.2.5 Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.5: Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> AllowLocalPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> AllowLocalPolicyMerge -> 0;
#
#
#9.2.6 Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.6: Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile -> AllowLocalIPsecPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile -> AllowLocalIPsecPolicyMerge -> 0;
#
#
#9.2.7 Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.7: Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
#
#
#9.2.8 Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16384 KB or greater'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.8: Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16384 KB or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogFileSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogFileSize -> r:3\w\w\w;
#
#
#9.2.9 Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.9: Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogDroppedPackets -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogDroppedPackets -> 0;
#
#
#9.2.10 Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.2.10: Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -> LogSuccessfulConnections -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging -> LogSuccessfulConnections -> 0;
#
#
#9.3.1 Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.1: Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> EnableFirewall -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> EnableFirewall -> 0;
#
#
#9.3.2 Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.2: Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> DefaultInboundAction -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> DefaultInboundAction -> 0;
#
#
#9.3.3 Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.3: Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> DefaultOutboundAction -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> DefaultOutboundAction -> 1;
#
#
#9.3.4 Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.4: Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> DisableNotifications -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> DisableNotifications -> 0;
#
#
#9.3.5 Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.5: Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> AllowLocalPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> AllowLocalPolicyMerge -> 0;
#
#
#9.3.6 Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.6: Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile -> AllowLocalIPsecPolicyMerge -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile -> AllowLocalIPsecPolicyMerge -> 0;
#
#
#9.3.7 Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.7: Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\*.log'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFilePath -> r:\psystemroot\p\\system32\logfiles\firewall\\w+\plog;
#
#
#9.3.8 Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16384 KB or greater'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.8: Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16384 KB or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogFileSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogFileSize -> r:3\w\w\w;
#
#
#9.3.9 Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.9: Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogDroppedPackets -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogDroppedPackets -> 0;
#
#
#9.3.10 Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
[CIS - Microsoft Windows Server 2012 R2 - 9.3.10: Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -> LogSuccessfulConnections -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging -> LogSuccessfulConnections -> 0;
#
#
#18.1.1.1 Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.1.1.1: Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> NoLockScreenCamera -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> !NoLockScreenCamera;
#
#
#18.1.1.2 Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.1.1.2: Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> NoLockScreenSlideshow -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization -> !NoLockScreenSlideshow;
#
#
#18.2.1 Ensure LAPS AdmPwd GPO Extension / CSE is installed
[CIS - Microsoft Windows Server 2012 R2 - 18.2.1: Ensure LAPS AdmPwd GPO Extension / CSE is installed] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA} -> !DllName;
#
#
#18.2.2 Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.2.2: Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PwdExpirationProtectionEnabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> !PwdExpirationProtectionEnabled;
#
#
#18.2.3 Ensure 'Enable Local Admin Password Management' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.2.3: Ensure 'Enable Local Admin Password Management' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> AdmPwdEnabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> !AdmPwdEnabled;
#
#
#18.2.4 Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'
[CIS - Microsoft Windows Server 2012 R2 - 18.2.4: Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordComplexity -> !4;
#
#
#18.2.5 Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'
[CIS - Microsoft Windows Server 2012 R2 - 18.2.5: Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordLength -> r:\d;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordLength -> r:a;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordLength -> r:b;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordLength -> r:c;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordLength -> r:d;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordLength -> r:e;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> !PasswordLength;
#
#
#18.2.6 Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'
[CIS - Microsoft Windows Server 2012 R2 - 18.2.6: Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> 1F;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:2\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:3\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:4\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:5\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:6\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:7\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:8\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:9\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:\D\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd -> PasswordAgeDays -> r:\w\w\w+;
#
#
#18.3.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.1: Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> AutoAdminLogon -> !0;
#
#
#18.3.2 Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.2: Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -> DisableIPSourceRouting -> !2;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -> !DisableIPSourceRouting;
#
#
#18.3.3 Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.3: Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> DisableIPSourceRouting -> !2;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !DisableIPSourceRouting;
#
#
#18.3.4 Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.4: Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> EnableICMPRedirect -> 1;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !EnableICMPRedirect;
#
#
#18.3.6 Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.6: Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters -> NoNameReleaseOnDemand -> !1;
#
#
#18.3.8 Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.8: Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager -> SafeDllSearchMode -> 0;
#
#
#18.3.9 Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.9: Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 6;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 7;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 8;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> 9;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> ScreenSaverGracePeriod -> r:\w\w+;
#
#
#18.3.12 Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.12: Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5B;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5C;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5D;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5E;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> 5F;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:6\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:7\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:8\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:9\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:\D\w;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> WarningLevel -> r:\w\w\w+;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security -> !WarningLevel;
#
#
#18.4.11.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.11.2: Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> NC_AllowNetBridge_NLA -> 1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> !NC_AllowNetBridge_NLA;
#
#
#18.4.11.3 Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.11.3: Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> NC_StdDomainUserSetLocation -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections -> !NC_StdDomainUserSetLocation;
#
#
#18.4.21.1 Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.21.1: Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -> fMinimizeConnections -> !1;
#
#
#18.6.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.6.1: Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> LocalAccountTokenFilterPolicy -> !0;
#
#
#18.6.2 Ensure 'WDigest Authentication' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.6.2: Ensure 'WDigest Authentication' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -> UseLogonCredential -> !0;
#
#
#18.8.3.1 Ensure 'Include command line in process creation events' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.3.1: Ensure 'Include command line in process creation events' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -> ProcessCreationIncludeCmdLine_Enabled -> !0;
#
#
#18.8.12.1 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.12.1: Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch -> DriverLoadPolicy -> !3;
#
#
#18.8.19.2 Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.19.2: Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> NoBackgroundPolicy -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> !NoBackgroundPolicy;
#
#
#18.8.19.3 Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.19.3: Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> NoGPOListChanges -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} -> !NoGPOListChanges;
#
#
#18.8.19.4 Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.19.4: Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> DisableBkGndGroupPolicy -> !0;
#
#
#18.8.25.1 Ensure 'Do not display network selection UI' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.1: Ensure 'Do not display network selection UI' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> DontDisplayNetworkSelectionUI -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !DontDisplayNetworkSelectionUI;
#
#
#18.8.25.2 Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.2: Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> DontEnumerateConnectedUsers -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !DontEnumerateConnectedUsers;
#
#
#18.8.25.3 Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.3: Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> EnumerateLocalUsers -> !0;
#
#
#18.8.25.4 Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.4: Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> DisableLockScreenAppNotifications -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !DisableLockScreenAppNotifications;
#
#
#18.8.25.5 Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.25.5: Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> AllowDomainPINLogon -> !0;
#
#
#18.8.31.1 Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.31.1: Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fAllowUnsolicited -> !0;
#
#
#18.8.31.2 Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.31.2: Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fAllowToGetHelp -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fAllowToGetHelp;
#
#
#18.8.32.1 Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.32.1: Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc -> EnableAuthEpResolution -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc -> !EnableAuthEpResolution;
#
#
#18.9.6.1 Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.6.1: Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> MSAOptional -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> !MSAOptional;
#
#
#18.9.8.1 Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.8.1: Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoAutoplayfornonVolume -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoAutoplayfornonVolume;
#
#
#18.9.8.2 Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.8.2: Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoAutorun -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoAutorun;
#
#
#18.9.8.3 Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.8.3: Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer-> NoDriveTypeAutoRun -> !ff;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer-> !NoDriveTypeAutoRun;
#
#
#18.9.15.1 Ensure 'Do not display the password reveal button' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.15.1: Ensure 'Do not display the password reveal button' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI -> DisablePasswordReveal -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI -> !DisablePasswordReveal;
#
#
#18.9.15.2 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.15.2: Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI -> EnumerateAdministrators -> !0;
#
#
#18.9.26.1.1 Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.1.1: Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> Retention -> !0;
#
#
#18.9.26.1.2 Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.1.2: Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:0\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:4\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:5\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:6\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> MaxSize -> r:7\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -> !MaxSize;
#
#
#18.9.26.2.1 Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.2.1: Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> Retention -> !0;
#
#
#18.9.26.2.2 Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.2.2: Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:0\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:1\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> MaxSize -> r:2\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -> !MaxSize;
#
#
#18.9.26.3.1 Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.3.1: Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> Retention -> !0;
#
#
#18.9.26.3.2 Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.3.2: Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:0\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:4\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:5\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:6\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> MaxSize -> r:7\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -> !MaxSize;
#
#
#18.9.26.4.1 Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.4.1: Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> Retention -> !0;
#
#
#18.9.26.4.2 Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.26.4.2: Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:0\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:1\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:2\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:3\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:4\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:5\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:6\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> MaxSize -> r:7\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -> !MaxSize;
#
#
#18.9.30.2 Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.2: Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> EnableSmartScreen -> !2;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System -> !EnableSmartScreen;
#
#
#18.9.30.3 Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.3: Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoDataExecutionPrevention -> !0;
#
#
#18.9.30.4 Ensure 'Turn off heap termination on corruption' is set to 'Disabled'[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.4: Ensure 'Turn off heap termination on corruption' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoHeapTerminationOnCorruption -> !0;
#
#
#18.9.30.5 Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.30.5: Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> PreXPSP2ShellProtocolBehavior -> !0;
#
#
#18.9.47.1 Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.47.1: Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive -> DisableFileSyncNGSC -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive -> !DisableFileSyncNGSC;
#
#
#18.9.47.2 Ensure 'Prevent the usage of OneDrive for file storage on Windows 8.1' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.47.2: Ensure 'Prevent the usage of OneDrive for file storage on Windows 8.1' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Skydrive -> DisableFileSync -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Skydrive -> !DisableFileSync;
#
#
#18.9.52.2.2 Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.2.2: Ensure 'Do not allow passwords to be saved' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> DisablePasswordSaving -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !DisablePasswordSaving;
#
#
#18.9.52.3.3.2 Ensure 'Do not allow drive redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.2: Ensure 'Do not allow drive redirection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisableCdm -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisableCdm;
#
#
#18.9.52.3.9.1 Ensure 'Always prompt for password upon connection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.9.1: Ensure 'Always prompt for password upon connection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fPromptForPassword -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fPromptForPassword;
#
#
#18.9.52.3.9.2 Ensure 'Require secure RPC communication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.9.2: Ensure 'Require secure RPC communication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fEncryptRPCTraffic -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fEncryptRPCTraffic;
#
#
#18.9.52.3.9.3 Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.9.3: Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MinEncryptionLevel -> !3;
#
#
#18.9.52.3.11.1 Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.11.1: Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> DeleteTempDirsOnExit -> !1;
#
#
#18.9.52.3.11.2 Ensure 'Do not use temporary folders per session' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.11.2: Ensure 'Do not use temporary folders per session' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> PerSessionTempDir -> !1;
#
#
#18.9.53.1 Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.53.1: Ensure 'Prevent downloading of enclosures' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds -> DisableEnclosureDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds -> !DisableEnclosureDownload;
#
#
#18.9.54.2 Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.54.2: Ensure 'Allow indexing of encrypted files' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search -> AllowIndexingEncryptedStoresOrItems -> !0;
#
#
#18.9.61.1 Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.61.1: Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> AutoDownload -> !4;
#
#
#18.9.61.2 Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.61.2: Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> DisableOSUpgrade -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> !DisableOSUpgrade;
#
#
#18.9.70.2.1 Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.70.2.1: Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent -> DefaultConsent -> !1;
#
#
#18.9.70.3 Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.70.3: Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> AutoApproveOSDumps -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !AutoApproveOSDumps;
#
#
#18.9.74.1 Ensure 'Allow user control over installs' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.74.1: Ensure 'Allow user control over installs' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer -> EnableUserControl -> !0;
#
#
#18.9.74.2 Ensure 'Always install with elevated privileges' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.74.2: Ensure 'Always install with elevated privileges' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer -> AlwaysInstallElevated -> !0;
#
#
#18.9.75.1 Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.75.1: Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> DisableAutomaticRestartSignOn -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -> !DisableAutomaticRestartSignOn;
#
#
#18.9.84.1 Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'[CIS - Microsoft Windows Server 2012 R2 - 18.9.84.1: Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -> EnableScriptBlockLogging -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -> !EnableScriptBlockLogging;
#
#
#18.9.84.2 Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.84.2: Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -> EnableTranscripting -> !0;
#
#
#18.9.86.1.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.1.1: Ensure 'Allow Basic authentication' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> AllowBasic -> !0;
#
#
#18.9.86.1.2 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.1.2: Ensure 'Allow unencrypted traffic' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> AllowUnencryptedTraffic -> !0;
#
#
#18.9.86.1.3 Ensure 'Disallow Digest authentication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.1.3: Ensure 'Disallow Digest authentication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> AllowDigest -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -> !AllowDigest;
#
#
#18.9.86.2.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.1: Ensure 'Allow Basic authentication' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> AllowBasic -> !0;
#
#
#18.9.86.2.3 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.3: Ensure 'Allow unencrypted traffic' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> AllowUnencryptedTraffic -> !0;
#
#
#18.9.86.2.4 Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.4: Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> DisableRunAs -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> !DisableRunAs;
#
#
#18.9.90.2 Ensure 'Configure Automatic Updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.90.2: Ensure 'Configure Automatic Updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> NoAutoUpdate -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> !NoAutoUpdate;
#
#
#18.9.90.3 Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.90.3: Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> ScheduledInstallDay -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> !ScheduledInstallDay;
#
#
#18.9.90.4 Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.90.4: Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -> NoAutoRebootWithLoggedOnUsers -> !0;
#
#
#
!376007 cis_win2012r2_memberL2_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2018 OSSEC Project
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://github.com/ossec/ossec-hids/blob/master/LICENSE
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceeded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# CIS Checks for Windows Server 2012 R2 Domain Controller L2
# Based on Center for Internet Security Benchmark v2.2.1 for Microsoft Windows Server 2012 R2 (https://workbench.cisecurity.org/benchmarks/288)
#
#
#2.3.7.6 Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
[CIS - Microsoft Windows Server 2012 R2 - Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> 5;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> 6;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> 7;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> 8;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> 9;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> a;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> b;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> c;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> d;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> e;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> f;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> CachedLogonsCount -> \w\w+;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> !CachedLogonsCount;
#
#
#2.3.10.4 Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 2.3.10.4: Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> DisableDomainCreds -> !1;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -> !DisableDomainCreds;
#
#
#18.3.5 Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.5: Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> KeepAliveTime -> !493e0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !KeepAliveTime;
#
#
#18.3.7 Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.7: Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> PerformRouterDiscovery  -> !0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !PerformRouterDiscovery;
#
#
#18.3.10 Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.10: Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> TcpMaxDataRetransmissions -> !3;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> !TcpMaxDataRetransmissions;
#
#
#18.3.11 Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
[CIS - Microsoft Windows Server 2012 R2 - 18.3.11: Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> TcpMaxDataRetransmissions -> !3;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -> !TcpMaxDataRetransmissions;
#
#
#18.4.9.1 Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.9.1: Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowLLTDIOOnDomain -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowLLTDIOOnPublicNet -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> EnableLLTDIO -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> ProhibitLLTDIOOnPrivateNet -> !0;
#
#
#18.4.9.2 Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.9.2: Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowRspndrOnDomain -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> AllowRspndrOnPublicNet -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> EnableRspndr -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD -> ProhibitRspndrOnPrivateNet -> !0;
#
#
#18.4.10.2 Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.10.2: Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet -> !Disabled;
#
#
#18.4.19.2.1 Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
[CIS - Microsoft Windows Server 2012 R2 - 18.4.19.2.1: Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> DisabledComponents -> !ff;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters -> !DisabledComponents;
#
#
#18.4.20.1 Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.20.1: Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> EnableRegistrars -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !EnableRegistrars;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableUPnPRegistrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableUPnPRegistrar;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableInBand802DOT11Registrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableInBand802DOT11Registrar;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableFlashConfigRegistrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableFlashConfigRegistrar;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> DisableWPDRegistrar -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -> !DisableWPDRegistrar;
#
#
#18.4.20.2 Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.20.2: Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI -> DisableWcnUi -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI -> !DisableWcnUi;
#
#
#18.4.21.2 Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.4.21.2: Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -> fBlockNonDomain -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -> !fBlockNonDomain;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
 -> !1;
#
#
#18.8.20.1.1 Ensure 'Turn off access to the Store' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.1: Ensure 'Turn off access to the Store' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> NoUseStoreOpenWith -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer -> !NoUseStoreOpenWith;
#
#
#18.8.20.1.2 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.2: Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableWebPnPDownload -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableWebPnPDownload;
#
#
#18.8.20.1.3 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.3: Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> PreventHandwritingDataSharing -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC -> !PreventHandwritingDataSharing;
#
#
#18.8.20.1.4 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.4: Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> PreventHandwritingErrorReports -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -> !PreventHandwritingErrorReports;
#
#
#18.8.20.1.5 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.5: Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> ExitOnMSICW -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard -> !ExitOnMSICW;
#
#
#18.8.20.1.6 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.6: Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoWebServices -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoWebServices;
#
#
#18.8.20.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.7: Ensure 'Turn off printing over HTTP' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> DisableHTTPPrinting -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers -> !DisableHTTPPrinting;
#
#
#18.8.20.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.8: Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> NoRegistration -> !1;
r:HKEY_LOCAL_MACHINE\Policies\Microsoft\Windows\Registration Wizard Control -> !NoRegistration;
#
#
#18.8.20.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.9: Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> DisableContentFileUpdates -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion -> !DisableContentFileUpdates;
#
#
#18.8.20.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.10: Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoOnlinePrintsWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoOnlinePrintsWizard;
#
#
#18.8.20.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.11: Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> NoPublishingWizard -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -> !NoPublishingWizard;
#
#
#18.8.20.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.12: Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> CEIP -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client -> !CEIP;
#
#
#18.8.20.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.13: Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> CEIPEnable -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows -> !CEIPEnable;
#
#
#18.8.20.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.20.1.14: Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> Disabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -> !Disabled;
#
#
#18.8.24.1 Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.24.1: Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International -> BlockUserInputMethodsForSignIn -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International -> !BlockUserInputMethodsForSignIn;
#
#
#18.8.29.5.1 Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.29.5.1: Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> DCSettingIndex -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> !DCSettingIndex;
#
#
#18.8.29.5.2 Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.29.5.2: Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> ACSettingIndex -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -> !ACSettingIndex;
#
#
#18.8.32.2 Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.32.2: Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc -> RestrictRemoteClients -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc -> !RestrictRemoteClients;
#
#
#18.8.39.5.1 Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.39.5.1: Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy -> DisableQueryRemoteServer -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy -> !DisableQueryRemoteServer;
#
#
#18.8.39.11.1 Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.39.11.1: Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d} -> ScenarioExecutionEnabled -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d} -> !ScenarioExecutionEnabled;
#
#
#18.8.41.1 Ensure 'Turn off the advertising ID' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.41.1: Ensure 'Turn off the advertising ID' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -> DisabledByGroupPolicy -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -> !DisabledByGroupPolicy;
#
#
#18.8.44.1.1 Ensure 'Enable Windows NTP Client' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.44.1.1: Ensure 'Enable Windows NTP Client' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient -> Enabled -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient -> !Enabled;
#
#
#18.8.44.1.2 Ensure 'Enable Windows NTP Server' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.8.44.1.2: Ensure 'Enable Windows NTP Server' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer -> Enabled -> !0;
#
#
#18.9.37.1 Ensure 'Turn off location' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.37.1: Ensure 'Turn off location' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors -> DisableLocation -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors -> !DisableLocation;
#
#
#18.9.52.3.2.1 Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.2.1: Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fSingleSessionPerUser -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fSingleSessionPerUser;
#
#
#18.9.52.3.3.1 Ensure 'Do not allow COM port redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.1: Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisableCcm -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisableCcm;
#
#
#18.9.52.3.3.3 Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.3: Ensure 'Do not allow LPT port redirection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisableLPT -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisableLPT;
#
#
#18.9.52.3.3.4 Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.3.4: Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> fDisablePNPRedir -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !fDisablePNPRedir;
#
#
#18.9.52.3.10.1 Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.10.1: Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba2;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba3;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba4;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba5;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba6;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba7;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba8;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba9;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbba\D;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbb\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbc\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbd\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbe\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbbf\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbc\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbd\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbe\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dbf\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dc\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:dd\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:de\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:df\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:e\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:f\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxIdleTime -> r:\w\w\w\w\w\w;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !MaxIdleTime;
#
#
#18.9.52.3.10.2 Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.52.3.10.2: Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> MaxDisconnectionTime -> !EA60;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -> !MaxDisconnectionTime;
#
#
#18.9.54.3 Ensure 'Set what information is shared in Search' is set to 'Enabled: Anonymous info'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.54.3: Ensure 'Set what information is shared in Search' is set to 'Enabled: Anonymous info'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search -> ConnectedSearchPrivacy -> !3;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search -> !ConnectedSearchPrivacy;
#
#
#18.9.59.1 Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.59.1: Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform -> NoGenTicket -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform -> !NoGenTicket;
#
#
#18.9.61.3 Ensure 'Turn off the Store application' is set to 'Enabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.61.3: Ensure 'Turn off the Store application' is set to 'Enabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> RemoveWindowsStore -> !1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore -> !RemoveWindowsStore;
#
#
#18.9.69.3.1 Ensure 'Join Microsoft MAPS' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.69.3.1: Ensure 'Join Microsoft MAPS' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet -> SpynetReporting -> !0;
#
#
#18.9.74.3 Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.74.3: Ensure 'Join Microsoft MAPS' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer -> SafeForScripting -> !0;
#
#
#18.9.86.2.2 Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.86.2.2: Ensure 'Allow remote server management through WinRM' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -> AllowAutoConfig -> !0;
#
#
#18.9.87.1 Ensure 'Allow Remote Shell Access' is set to 'Disabled'
[CIS - Microsoft Windows Server 2012 R2 - 18.9.87.1: Ensure 'Allow Remote Shell Access' is set to 'Disabled'] [any] [https://workbench.cisecurity.org/benchmarks/288]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS -> AllowRemoteShellAccess -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS -> !AllowRemoteShellAccess;
#


!16179 rootkit_files.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# rootkit_files.txt, (C) Daniel B. Cid
# Imported from the rootcheck project.
#
# Blank lines and lines starting with '#' are ignored.
#
# Each line must be in the following format:
# file_name ! Name ::Link to it
#
# Files that start with an '*' will be searched in the whole system.

# Bash door
tmp/mcliZokhb           ! Bash door ::/rootkits/bashdoor.php
tmp/mclzaKmfa           ! Bash door ::/rootkits/bashdoor.php

# adore Worm
dev/.shit/red.tgz       ! Adore Worm ::/rootkits/adorew.php
usr/lib/libt            ! Adore Worm ::/rootkits/adorew.php
usr/bin/adore           ! Adore Worm ::/rootkits/adorew.php
*/klogd.o               ! Adore Worm ::/rootkits/adorew.php
*/red.tar               ! Adore Worm ::/rootkits/adorew.php

# T.R.K rootkit
usr/bin/soucemask       ! TRK rootkit ::/rootkits/trk.php
usr/bin/sourcemask      ! TRK rootkit ::/rootkits/trk.php

# 55.808.A Worm
tmp/.../a               ! 55808.A Worm ::
tmp/.../r               ! 55808.A Worm ::

# Volc Rootkit
usr/lib/volc            ! Volc Rootkit ::
usr/bin/volc            ! Volc Rootkit ::

# Illogic
lib/security/.config    ! Illogic Rootkit ::rootkits/illogic.php
usr/bin/sia             ! Illogic Rootkit ::rootkits/illogic.php
etc/ld.so.hash          ! Illogic Rootkit ::rootkits/illogic.php
*/uconf.inv             ! Illogic Rootkit ::rootkits/illogic.php

# T0rnkit
usr/src/.puta           ! t0rn Rootkit ::rootkits/torn.php
usr/info/.t0rn          ! t0rn Rootkit ::rootkits/torn.php
lib/ldlib.tk            ! t0rn Rootkit ::rootkits/torn.php
etc/ttyhash             ! t0rn Rootkit ::rootkits/torn.php
sbin/xlogin             ! t0rn Rootkit ::rootkits/torn.php
*/ldlib.tk              ! t0rn Rootkit ::rootkits/torn.php
*/.t0rn                 ! t0rn Rootkit ::rootkits/torn.php
*/.puta                 ! t0rn Rootkit ::rootkits/torn.php

# RK17
bin/rtty                        ! RK17 ::
bin/squit                       ! RK17 ::
sbin/pback                      ! RK17 ::
proc/kset                       ! RK17 ::
usr/src/linux/modules/autod.o   ! RK17 ::
usr/src/linux/modules/soundx.o  ! RK17 ::

# Ramen Worm
usr/lib/ldlibps.so      ! Ramen Worm ::rootkits/ramen.php
usr/lib/ldlibns.so      ! Ramen Worm ::rootkits/ramen.php
usr/lib/ldliblogin.so   ! Ramen Worm ::rootkits/ramen.php
usr/src/.poop           ! Ramen Worm ::rootkits/ramen.php
tmp/ramen.tgz           ! Ramen Worm ::rootkits/ramen.php
etc/xinetd.d/asp        ! Ramen Worm ::rootkits/ramen.php

# Sadmind/IIS Worm
dev/cuc                 ! Sadmind/IIS Worm ::

# Monkit
lib/defs                ! Monkit ::
usr/lib/libpikapp.a     ! Monkit found ::

# RSHA
usr/bin/kr4p            ! RSHA ::
usr/bin/n3tstat         ! RSHA ::
usr/bin/chsh2           ! RSHA ::
usr/bin/slice2          ! RSHA ::
etc/rc.d/rsha           ! RSHA ::

# ShitC worm
bin/home                ! ShitC ::
sbin/home               ! ShitC ::
usr/sbin/in.slogind     ! ShitC ::

# Omega Worm
dev/chr                 ! Omega Worm ::

# rh-sharpe
bin/.ps                 ! Rh-Sharpe ::
usr/bin/cleaner         ! Rh-Sharpe ::
usr/bin/slice           ! Rh-Sharpe ::
usr/bin/vadim           ! Rh-Sharpe ::
usr/bin/.ps             ! Rh-Sharpe ::
bin/.lpstree            ! Rh-Sharpe ::
usr/bin/.lpstree        ! Rh-Sharpe ::
usr/bin/lnetstat        ! Rh-Sharpe ::
bin/lnetstat            ! Rh-Sharpe ::
usr/bin/ldu             ! Rh-Sharpe ::
bin/ldu                 ! Rh-Sharpe ::
usr/bin/lkillall        ! Rh-Sharpe ::
bin/lkillall            ! Rh-Sharpe ::
usr/include/rpcsvc/du   ! Rh-Sharpe ::

# Maniac RK
usr/bin/mailrc          ! Maniac RK ::

# Showtee / Romanian
usr/lib/.egcs           ! Showtee ::
usr/lib/.wormie         ! Showtee ::
usr/lib/.kinetic        ! Showtee ::
usr/lib/liblog.o        ! Showtee ::
usr/include/addr.h      ! Showtee / Romanian rootkit ::
usr/include/cron.h      ! Showtee ::
usr/include/file.h      ! Showtee / Romanian rootkit ::
usr/include/syslogs.h   ! Showtee / Romanian rootkit ::
usr/include/proc.h      ! Showtee / Romanian rootkit ::
usr/include/chk.h       ! Showtee ::
usr/sbin/initdl         ! Romanian rootkit ::
usr/sbin/xntps          ! Romanian rootkit ::

# Optickit
usr/bin/xchk            ! Optickit ::
usr/bin/xsf             ! Optickit ::

# LDP worm
dev/.kork           ! LDP Worm ::
bin/.login          ! LDP Worm ::
bin/.ps             ! LDP Worm ::

# Telekit
dev/hda06           ! TeLeKit trojan ::
usr/info/libc1.so   ! TeleKit trojan ::

# Tribe bot
dev/wd4     ! Tribe bot ::

# LRK
dev/ida/.inet       ! LRK rootkit ::rootkits/lrk.php
*/bindshell         ! LRK rootkit ::rootkits/lrk.php

# Adore Rootkit
etc/bin/ava         ! Adore Rootkit ::
etc/sbin/ava        ! Adore Rootkit ::

# Slapper
tmp/.bugtraq            ! Slapper installed ::
tmp/.bugtraq.c          ! Slapper installed ::
tmp/.cinik              ! Slapper installed ::
tmp/.b                  ! Slapper installed ::
tmp/httpd               ! Slapper installed ::
tmp./update             ! Slapper installed ::
tmp/.unlock             ! Slapper installed ::
tmp/.font-unix/.cinik   ! Slapper installed ::
tmp/.cinik              ! Slapper installed ::

# Scalper
tmp/.uua            ! Scalper installed ::
tmp/.a              ! Scalper installed ::

# Knark
proc/knark          ! Knark Installed ::rootkits/knark.php
dev/.pizda          ! Knark Installed ::rootkits/knark.php
dev/.pula           ! Knark Installed ::rootkits/knark.php
dev/.pula           ! Knark Installed ::rootkits/knark.php
*/taskhack          ! Knark Installed ::rootkits/knark.php
*/rootme            ! Knark Installed ::rootkits/knark.php
*/nethide           ! Knark Installed ::rootkits/knark.php
*/hidef             ! Knark Installed ::rootkits/knark.php
*/ered              ! Knark Installed ::rootkits/knark.php

# Lion worm
dev/.lib            ! Lion Worm ::rootkits/lion.php
dev/.lib/1iOn.sh    ! Lion Worm ::rootkits/lion.php
bin/mjy             ! Lion Worm ::rootkits/lion.php
bin/in.telnetd      ! Lion Worm ::rootkits/lion.php
usr/info/torn       ! Lion Worm ::rootkits/lion.php
*/1iOn\.sh          ! Lion Worm ::rootkits/lion.php

# Bobkit
usr/include/.../        ! Bobkit Rootkit ::rootkits/bobkit.php
usr/lib/.../            ! Bobkit Rootkit ::rootkits/bobkit.php
usr/sbin/.../           ! Bobkit Rootkit ::rootkits/bobkit.php
usr/bin/ntpsx           ! Bobkit Rootkit ::rootkits/bobkit.php
tmp/.bkp                ! Bobkit Rootkit ::rootkits/bobkit.php
usr/lib/.bkit-          ! Bobkit Rootkit ::rootkits/bobkit.php
*/bkit-                 ! Bobkit Rootkit ::rootkits/bobkit.php

# Hidrootkit
var/lib/games/.k        ! Hidr00tkit ::

# Ark
dev/ptyxx       ! Ark rootkit ::

# Mithra Rootkit
usr/lib/locale/uboot        ! Mithra`s rootkit ::

# Optickit
usr/bin/xsf         ! OpticKit ::
usr/bin/xchk        ! OpticKit ::

# LOC rookit
tmp/xp          ! LOC rookit ::
tmp/kidd0.c     ! LOC rookit ::
tmp/kidd0       ! LOC rookit ::

# TC2 worm
usr/info/.tc2k      ! TC2 Worm ::
usr/bin/util        ! TC2 Worm ::
usr/sbin/initcheck  ! TC2 Worm ::
usr/sbin/ldb        ! TC2 Worm ::

# Anonoiyng rootkit
usr/sbin/mech       ! Anonoiyng rootkit ::
usr/sbin/kswapd     ! Anonoiyng rootkit ::

# SuckIt
lib/.x              ! SuckIt rootkit ::
*/hide.log          ! Suckit rootkit ::
lib/sk              ! SuckIT rootkit ::

# Beastkit
usr/local/bin/bin       ! Beastkit rootkit ::rootkits/beastkit.php
usr/man/.man10          ! Beastkit rootkit ::rootkits/beastkit.php
usr/sbin/arobia         ! Beastkit rootkit ::rootkits/beastkit.php
usr/lib/elm/arobia      ! Beastkit rootkit ::rootkits/beastkit.php
usr/local/bin/.../bktd  ! Beastkit rootkit ::rootkits/beastkit.php

# Tuxkit
dev/tux             ! Tuxkit rootkit ::rootkits/Tuxkit.php
usr/bin/xsf         ! Tuxkit rootkit ::rootkits/Tuxkit.php
usr/bin/xchk        ! Tuxkit rootkit ::rootkits/Tuxkit.php
*/.file             ! Tuxkit rootkit ::rootkits/Tuxkit.php
*/.addr             ! Tuxkit rootkit ::rootkits/Tuxkit.php

# Old rootkits
usr/include/rpc/ ../kit     ! Old rootkits ::rootkits/Old.php
usr/include/rpc/ ../kit2    ! Old rootkits ::rootkits/Old.php
usr/doc/.sl                 ! Old rootkits ::rootkits/Old.php
usr/doc/.sp                 ! Old rootkits ::rootkits/Old.php
usr/doc/.statnet            ! Old rootkits ::rootkits/Old.php
usr/doc/.logdsys            ! Old rootkits ::rootkits/Old.php
usr/doc/.dpct               ! Old rootkits ::rootkits/Old.php
usr/doc/.gifnocfi           ! Old rootkits ::rootkits/Old.php
usr/doc/.dnif               ! Old rootkits ::rootkits/Old.php
usr/doc/.nigol              ! Old rootkits ::rootkits/Old.php

# Kenga3 rootkit
usr/include/. .         ! Kenga3 rootkit

# ESRK rootkit
usr/lib/tcl5.3          ! ESRK rootkit

# Fu rootkit
sbin/xc                 ! Fu rootkit
usr/include/ivtype.h    ! Fu rootkit
bin/.lib                ! Fu rootkit

# ShKit rootkit
lib/security/.config    ! ShKit rootkit
etc/ld.so.hash          ! ShKit rootkit

# AjaKit rootkit
lib/.ligh.gh            ! AjaKit rootkit
lib/.libgh.gh           ! AjaKit rootkit
lib/.libgh-gh           ! AjaKit rootkit
dev/tux                 ! AjaKit rootkit
dev/tux/.proc           ! AjaKit rootkit
dev/tux/.file           ! AjaKit rootkit

# zaRwT rootkit
bin/imin                ! zaRwT rootkit
bin/imout               ! zaRwT rootkit

# Madalin rootkit
usr/include/icekey.h    ! Madalin rootkit
usr/include/iceconf.h   ! Madalin rootkit
usr/include/iceseed.h   ! Madalin rootkit

# shv5 rootkit XXX http://www.askaboutskating.com/forum/.../shv5/setup
lib/libsh.so            ! shv5 rootkit
usr/lib/libsh           ! shv5 rootkit

# BMBL rootkit (http://www.giac.com/practical/GSEC/Steve_Terrell_GSEC.pdf)
etc/.bmbl               ! BMBL rootkit
etc/.bmbl/sk            ! BMBL rootkit

# rootedoor rootkit
*/rootedoor             ! Rootedoor rootkit

# 0vason rootkit
*/ovas0n                ! ovas0n rootkit ::/rootkits/ovason.php
*/ovason                ! ovas0n rootkit ::/rootkits/ovason.php

# Rpimp reverse telnet
*/rpimp                 ! rpv21 (Reverse Pimpage)::/rootkits/rpimp.php

# Cback Linux worm
tmp/cback              ! cback worm ::/rootkits/cback.php
tmp/derfiq             ! cback worm ::/rootkits/cback.php

# aPa Kit (from rkhunter)
usr/share/.aPa          ! Apa Kit

# enye-sec Rootkit
etc/.enyelkmHIDE^IT.ko  ! enye-sec Rootkit ::/rootkits/enye-sec.php

# Override Rootkit
dev/grid-hide-pid-     ! Override rootkit ::/rootkits/override.php
dev/grid-unhide-pid-   ! Override rootkit ::/rootkits/override.php
dev/grid-show-pids     ! Override rootkit ::/rootkits/override.php
dev/grid-hide-port-    ! Override rootkit ::/rootkits/override.php
dev/grid-unhide-port-  ! Override rootkit ::/rootkits/override.php

# PHALANX rootkit
usr/share/.home*        ! PHALANX rootkit ::
usr/share/.home*/tty    ! PHALANX rootkit ::
etc/host.ph1            ! PHALANX rootkit ::
bin/host.ph1            ! PHALANX rootkit ::

# ZK rootkit (http://honeyblog.org/junkyard/reports/redhat-compromise2.pdf)
# and from chkrootkit
usr/share/.zk                   ! ZK rootkit ::
usr/share/.zk/zk                ! ZK rootkit ::
etc/1ssue.net                   ! ZK rootkit ::
usr/X11R6/.zk                   ! ZK rootkit ::
usr/X11R6/.zk/xfs               ! ZK rootkit ::
usr/X11R6/.zk/echo              ! ZK rootkit ::
etc/sysconfig/console/load.zk   ! ZK rootkit ::

# Public sniffers
*/.linux-sniff          ! Sniffer log ::
*/sniff-l0g             ! Sniffer log ::
*/core_$                ! Sniffer log ::
*/tcp.log               ! Sniffer log ::
*/chipsul               ! Sniffer log ::
*/beshina               ! Sniffer log ::
*/.owned$               | Sniffer log ::

# Solaris worm -
# http://blogs.sun.com/security/entry/solaris_in_telnetd_worm_seen
var/adm/.profile        ! Solaris Worm ::
var/spool/lp/.profile   ! Solaris Worm ::
var/adm/sa/.adm         ! Solaris Worm ::
var/spool/lp/admins/.lp ! Solaris Worm ::

# Suspicious files
etc/rc.d/init.d/rc.modules  ! Suspicious file ::rootkits/Suspicious.php
lib/ldd.so                  ! Suspicious file ::rootkits/Suspicious.php
usr/man/muie                ! Suspicious file ::rootkits/Suspicious.php
usr/X11R6/include/pain      ! Suspicious file ::rootkits/Suspicious.php
usr/bin/sourcemask          ! Suspicious file ::rootkits/Suspicious.php
usr/bin/ras2xm              ! Suspicious file ::rootkits/Suspicious.php
usr/bin/ddc                 ! Suspicious file ::rootkits/Suspicious.php
usr/bin/jdc                 ! Suspicious file ::rootkits/Suspicious.php
usr/sbin/in.telnet          ! Suspicious file ::rootkits/Suspicious.php
sbin/vobiscum               ! Suspicious file ::rootkits/Suspicious.php
usr/sbin/jcd                ! Suspicious file ::rootkits/Suspicious.php
usr/sbin/atd2               ! Suspicious file ::rootkits/Suspicious.php
usr/bin/ishit               ! Suspicious file ::rootkits/Suspicious.php
usr/bin/.etc                ! Suspicious file ::rootkits/Suspicious.php
usr/bin/xstat               ! Suspicious file ::rootkits/Suspicious.php
var/run/.tmp                ! Suspicious file ::rootkits/Suspicious.php
usr/man/man1/lib/.lib       ! Suspicious file ::rootkits/Suspicious.php
usr/man/man2/.man8          ! Suspicious file ::rootkits/Suspicious.php
var/run/.pid                ! Suspicious file ::rootkits/Suspicious.php
lib/.so                     ! Suspicious file ::rootkits/Suspicious.php
lib/.fx                     ! Suspicious file ::rootkits/Suspicious.php
lib/lblip.tk                ! Suspicious file ::rootkits/Suspicious.php
usr/lib/.fx                 ! Suspicious file ::rootkits/Suspicious.php
var/local/.lpd              ! Suspicious file ::rootkits/Suspicious.php
dev/rd/cdb                  ! Suspicious file ::rootkits/Suspicious.php
dev/.rd/                    ! Suspicious file ::rootkits/Suspicious.php
usr/lib/pt07                ! Suspicious file ::rootkits/Suspicious.php
usr/bin/atm                 ! Suspicious file ::rootkits/Suspicious.php
tmp/.cheese                 ! Suspicious file ::rootkits/Suspicious.php
dev/.arctic                 ! Suspicious file ::rootkits/Suspicious.php
dev/.xman                   ! Suspicious file ::rootkits/Suspicious.php
dev/.golf                   ! Suspicious file ::rootkits/Suspicious.php
dev/srd0                    ! Suspicious file ::rootkits/Suspicious.php
dev/ptyzx                   ! Suspicious file ::rootkits/Suspicious.php
dev/ptyzg                   ! Suspicious file ::rootkits/Suspicious.php
dev/xdf1                    ! Suspicious file ::rootkits/Suspicious.php
dev/ttyop                   ! Suspicious file ::rootkits/Suspicious.php
dev/ttyof                   ! Suspicious file ::rootkits/Suspicious.php
dev/hd7                     ! Suspicious file ::rootkits/Suspicious.php
dev/hdx1                    ! Suspicious file ::rootkits/Suspicious.php
dev/hdx2                    ! Suspicious file ::rootkits/Suspicious.php
dev/xdf2                    ! Suspicious file ::rootkits/Suspicious.php
dev/ptyp                    ! Suspicious file ::rootkits/Suspicious.php
dev/ptyr                    ! Suspicious file ::rootkits/Suspicious.php
sbin/pback                  ! Suspicious file ::rootkits/Suspicious.php
usr/man/man3/psid           ! Suspicious file ::rootkits/Suspicious.php
proc/kset                   ! Suspicious file ::rootkits/Suspicious.php
usr/bin/gib                 ! Suspicious file ::rootkits/Suspicious.php
usr/bin/snick               ! Suspicious file ::rootkits/Suspicious.php
usr/bin/kfl                 ! Suspicious file ::rootkits/Suspicious.php
tmp/.dump                   ! Suspicious file ::rootkits/Suspicious.php
var/.x                      ! Suspicious file ::rootkits/Suspicious.php
var/.x/psotnic              ! Suspicious file ::rootkits/Suspicious.php
*/.log                      ! Suspicious file ::rootkits/Suspicious.php
*/ecmf                      ! Suspicious file ::rootkits/Suspicious.php
*/mirkforce                 ! Suspicious file ::rootkits/Suspicious.php
*/mfclean                   ! Suspicious file ::rootkits/Suspicious.php
!5534 rootkit_trojans.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# rootkit_trojans.txt, (C) Daniel B. Cid
#
# Imported from the rootcheck project.
# Some entries taken from the chkrootkit project.
#
# Blank lines and lines starting with '#' are ignored.
#
# Each line must be in the following format:
# file_name !string_to_search!Description

# Common binaries and public trojan entries
ls          !bash|^/bin/sh|dev/[^clu]|\.tmp/lsfile|duarawkz|/prof|/security|file\.h!
env         !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
echo        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chown       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chmod       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chgrp       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
cat         !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
bash        !proc\.h|/dev/[0-9]|/dev/[hijkz]!
sh          !proc\.h|/dev/[0-9]|/dev/[hijkz]!
uname       !bash|^/bin/sh|file\.h|proc\.h|^/bin/.*sh!
date        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cln]|^/bin/.*sh!
du          !w0rm|/prof|file\.h!
df          !bash|^/bin/sh|file\.h|proc\.h|/dev/[^clurdv]|^/bin/.*sh!
login       !elite|SucKIT|xlogin|vejeta|porcao|lets_log|sukasuk!
passwd      !bash|file\.h|proc\.h|/dev/ttyo|/dev/[A-Z]|/dev/[b-s,uvxz]!
mingetty    !bash|Dimensioni|pacchetto!
chfn        !bash|file\.h|proc\.h|/dev/ttyo|/dev/[A-Z]|/dev/[a-s,uvxz]!
chsh        !bash|file\.h|proc\.h|/dev/ttyo|/dev/[A-Z]|/dev/[a-s,uvxz]!
mail        !bash|file\.h|proc\.h|/dev/[^nu]!
su          !/dev/[d-s,abuvxz]|/dev/[A-D]|/dev/[F-Z]|/dev/[0-9]|satori|vejeta|conf\.inv!
sudo        !satori|vejeta|conf\.inv!
crond       !/dev/[^nt]|bash!
gpm         !bash|mingetty!
ifconfig    !bash|^/bin/sh|/dev/tux|session.null|/dev/[^cludisopt]!
diff        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^n]|^/bin/.*sh!
md5sum      !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
hdparm      !bash|/dev/ida!
ldd         !/dev/[^n]|proc\.h|libshow.so|libproc.a!

# Trojan entries for troubleshooting binaries
grep        !bash|givemer!
egrep       !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
find        !bash|/dev/[^tnlcs]|/prof|/home/virus|file\.h!
lsof        !/prof|/dev/[^apcmnfk]|proc\.h|bash|^/bin/sh|/dev/ttyo|/dev/ttyp!
netstat     !bash|^/bin/sh|/dev/[^aik]|/prof|grep|addr\.h!
top         !/dev/[^npi3st%]|proc\.h|/prof/!
ps          !/dev/ttyo|\.1proc|proc\.h|bash|^/bin/sh!
tcpdump     !bash|^/bin/sh|file\.h|proc\.h|/dev/[^bu]|^/bin/.*sh!
pidof       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^f]|^/bin/.*sh!
fuser       !bash|^/bin/sh|file\.h|proc\.h|/dev/[a-dtz]|^/bin/.*sh!
w           !uname -a|proc\.h|bash!

# Trojan entries for common daemons
sendmail    !bash|fuck!
named       !bash|blah|/dev/[0-9]|^/bin/sh!
inetd       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^un%]|^/bin/.*sh!
apachectl   !bash|^/bin/sh|file\.h|proc\.h|/dev/[^n]|^/bin/.*sh!
sshd        !check_global_passwd|panasonic|satori|vejeta|\.ark|/hash\.zk|bash|/dev[a-s]|/dev[A-Z]/!
syslogd     !bash|/usr/lib/pt07|/dev/[^cln]]|syslogs\.h|proc\.h!
xinetd      !bash|file\.h|proc\.h!
in.telnetd  !cterm100|vt350|VT100|ansi-term|bash|^/bin/sh|/dev[A-R]|/dev/[a-z]/!
in.fingerd  !bash|^/bin/sh|cterm100|/dev/!
identd      !bash|^/bin/sh|file\.h|proc\.h|/dev/[^n]|^/bin/.*sh!
init        !bash|/dev/h
tcpd        !bash|proc\.h|p1r0c4|hack|/dev/[^n]!
rlogin      !p1r0c4|r00t|bash|/dev/[^nt]!

# Kill trojan
killall     !/dev/[^t%]|proc\.h|bash|tmp!
kill        !/dev/[ab,d-k,m-z]|/dev/[F-Z]|/dev/[A-D]|/dev/[0-9]|proc\.h|bash|tmp!

# Rootkit entries
/etc/rc.d/rc.sysinit    !enyelkmHIDE! enye-sec Rootkit

# ZK rootkit (http://honeyblog.org/junkyard/reports/redhat-compromise2.pdf)
/etc/sysconfig/console/load.zk   !/bin/sh! ZK rootkit
/etc/sysconfig/console/load.zk   !usr/bin/run! ZK rootkit

# Modified /etc/hosts entries
# Idea taken from:
# http://blog.tenablesecurity.com/2006/12/detecting_compr.html
# http://www.sophos.com/security/analyses/trojbagledll.html
# http://www.f-secure.com/v-descs/fantibag_b.shtml
/etc/hosts  !^[^#]*avp.ch!Anti-virus site on the hosts file
/etc/hosts  !^[^#]*avp.ru!Anti-virus site on the hosts file
/etc/hosts  !^[^#]*awaps.net! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*ca.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*mcafee.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*microsoft.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*f-secure.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*sophos.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*symantec.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*my-etrust.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*nai.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*networkassociates.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*viruslist.ru! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*kaspersky! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*symantecliveupdate.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*grisoft.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*clamav.net! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*bitdefender.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*antivirus.com! Anti-virus site on the hosts file
/etc/hosts  !^[^#]*sans.org! Security site on the hosts file
!4471 system_audit_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Linux Audit - (C) 2007 Daniel B. Cid - dcid@ossec.net
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - p (process running)
#             - d (any file inside the directory)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

$php.ini=/etc/php.ini,/var/www/conf/php.ini,/etc/php5/apache2/php.ini;
$web_dirs=/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www;

# PHP checks
[PHP - Register globals are enabled] [any] []
f:$php.ini -> r:^register_globals = On;

# PHP checks
[PHP - Expose PHP is enabled] [any] []
f:$php.ini -> r:^expose_php = On;

# PHP checks
[PHP - Allow URL fopen is enabled] [any] []
f:$php.ini -> r:^allow_url_fopen = On;

# PHP checks
[PHP - Displaying of errors is enabled] [any] []
f:$php.ini -> r:^display_errors = On;

# PHP checks - consider open_basedir && disable_functions


## Looking for common web exploits (might indicate that you are owned).
## Using http://dcid.me/blog/logsamples/webattacks_links as a reference.
#[Web exploits - Possible compromise] [any] []
#d:$web_dirs -> .txt$ -> r:^<?php|^#!;

## Looking for common web exploits files (might indicate that you are owned).
## There are not specific, like the above.
## Using http://dcid.me/blog/logsamples/webattacks_links as a reference.
[Web exploits (uncommon file name inside htdocs) - Possible compromise  {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^.yop$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^id$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^.ssh$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^...$;

[Web exploits (uncommon file name inside htdocs) - Possible compromise {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> ^.shell$;

## Looking for outdated Web applications
## Taken from http://sucuri.net/latest-versions
[Web vulnerability - Outdated WordPress installation {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://sucuri.net/latest-versions]
d:$web_dirs -> ^version.php$ -> r:^\.wp_version && >:$wp_version = '4.4.2';

[Web vulnerability - Outdated Joomla installation {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://sucuri.net/latest-versions]
d:$web_dirs -> ^version.php$ -> r:var \.RELEASE && r:'3.4.8';

[Web vulnerability - Outdated osCommerce (v2.2) installation {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://sucuri.net/latest-versions]
d:$web_dirs -> ^application_top.php$ -> r:'osCommerce 2.2-;

## Looking for known backdoors
[Web vulnerability - Backdoors / Web based malware found - eval(base64_decode) {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> .php$ -> r:eval\(base64_decode\(\paWYo;

[Web vulnerability - Backdoors / Web based malware found - eval(base64_decode(POST)) {PCI_DSS: 6.5, 6.6, 11.4}] [any] []
d:$web_dirs -> .php$ -> r:eval\(base64_decode\(\S_POST;

[Web vulnerability - .htaccess file compromised {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://blog.sucuri.net/2011/05/understanding-htaccess-attacks-part-1.html]
d:$web_dirs -> ^.htaccess$ -> r:RewriteCond \S+HTTP_REFERERS \S+google;

[Web vulnerability - .htaccess file compromised - auto append {PCI_DSS: 6.5, 6.6, 11.4}] [any] [http://blog.sucuri.net/2011/05/understanding-htaccess-attacks-part-1.html]
d:$web_dirs -> ^.htaccess$ -> r:php_value auto_append_file;
!3290 system_audit_ssh.txt
#  SSH Rootcheck
#
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#


$sshd_file=/etc/ssh/sshd_config;


# Listen PORT != 22
# The option Port specifies on which port number ssh daemon listens for incoming connections.
# Changing the default port you may reduce the number of successful attacks from zombie bots, an attacker or bot doing port-scanning can quickly identify your SSH port.
[SSH Hardening - 1: Port 22 {PCI_DSS: 2.2.4}] [any] [1]
f:$sshd_file -> !r:^# && r:Port\.+22;


# Protocol 2
# The Protocol parameter dictates which version of the SSH communication and encryption protocols are in use.
# Version 1 of the SSH protocol has weaknesses.
[SSH Hardening - 2: Protocol 1 {PCI_DSS: 2.2.4}] [any] [2]
f:$sshd_file -> !r:^# && r:Protocol\.+1;


# PermitRootLogin no
# The option PermitRootLogin specifies whether root can log in using ssh.
# If you want log in as root, you should use the option "Match" and restrict it to a few IP addresses.
[SSH Hardening - 3: Root can log in] [any] [3]
f:$sshd_file -> !r:^\s*PermitRootLogin\.+no;


# PubkeyAuthentication yes
# Access only by public key
# Generally people will use weak passwords and have poor password practices. Keys are considered stronger than password.
[SSH Hardening - 4: No Public Key authentication {PCI_DSS: 2.2.4}] [any] [4]
f:$sshd_file -> !r:^\s*PubkeyAuthentication\.+yes;


# PasswordAuthentication no
# The option PasswordAuthentication specifies whether we should use password-based authentication.
# Use public key authentication instead of passwords
[SSH Hardening - 5: Password Authentication {PCI_DSS: 2.2.4}] [any] [5]
f:$sshd_file -> !r:^\s*PasswordAuthentication\.+no;


# PermitEmptyPasswords no
# The option PermitEmptyPasswords specifies whether the server allows logging in to accounts with a null password
# Accounts with null passwords are a bad practice.
[SSH Hardening - 6: Empty passwords allowed {PCI_DSS: 2.2.4}] [any] [6]
f:$sshd_file -> !r:^\s*PermitEmptyPasswords\.+no;


# IgnoreRhosts yes
# The option IgnoreRhosts specifies whether rhosts or shosts files should not be used in authentication.
# For security reasons it is recommended to no use rhosts or shosts files for authentication.
[SSH Hardening - 7: Rhost or shost used for authentication {PCI_DSS: 2.2.4}] [any] [7]
f:$sshd_file -> !r:^\s*IgnoreRhosts\.+yes;


# LoginGraceTime 30
# The option LoginGraceTime specifies how long in seconds after a connection request the server will wait before disconnecting if the user has not successfully logged in.
# 30 seconds is the recommended time for avoiding open connections without authenticate
[SSH Hardening - 8: Wrong Grace Time {PCI_DSS: 2.2.4}] [any] [8]
f:$sshd_file -> !r:^\s*LoginGraceTime\s+30\s*$;


# MaxAuthTries 4
# The MaxAuthTries parameter specifices the maximum number of authentication attempts permitted per connection. Once the number of failures reaches half this value, additional failures are logged.
# This should be set to 4.
[SSH Hardening - 9: Wrong Maximum number of authentication attempts {PCI_DSS: 2.2.4}] [any] [9]
f:$sshd_file -> !r:^\s*MaxAuthTries\s+4\s*$;
!5219 win_applications_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Application detection - (C) 2007 Daniel B. Cid - dcid@ossec.net
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

[Chat/IM/VoIP - Skype {PCI_DSS: 10.6.1}] [any] []
f:\Program Files\Skype\Phone;
f:\Documents and Settings\All Users\Documents\My Skype Pictures;
f:\Documents and Settings\Skype;
f:\Documents and Settings\All Users\Start Menu\Programs\Skype;
r:HKLM\SOFTWARE\Skype;
r:HKEY_LOCAL_MACHINE\Software\Policies\Skype;
p:r:Skype.exe;

[Chat/IM - Yahoo {PCI_DSS: 10.6.1}] [any] []
f:\Documents and Settings\All Users\Start Menu\Programs\Yahoo! Messenger;
r:HKLM\SOFTWARE\Yahoo;

[Chat/IM - ICQ {PCI_DSS: 10.6.1}] [any] []
r:HKEY_CURRENT_USER\Software\Mirabilis\ICQ;

[Chat/IM - AOL {PCI_DSS: 10.6.1}] [any] [http://www.aol.com]
r:HKEY_LOCAL_MACHINE\SOFTWARE\America Online\AOL Instant Messenger;
r:HKEY_CLASSES_ROOT\aim\shell\open\command;
r:HKEY_CLASSES_ROOT\AIM.Protocol;
r:HKEY_CLASSES_ROOT\MIME\Database\Content Type\application/x-aim;
f:\Program Files\AIM95;
p:r:aim.exe;

[Chat/IM - MSN {PCI_DSS: 10.6.1}] [any] [http://www.msn.com]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSNMessenger;
r:HKEY_CURRENT_USER\SOFTWARE\Microsoft\MSNMessenger;
f:\Program Files\MSN Messenger;
f:\Program Files\Messenger;
p:r:msnmsgr.exe;

[Chat/IM - ICQ {PCI_DSS: 10.6.1}] [any] [http://www.icq.com]
r:HKLM\SOFTWARE\Mirabilis\ICQ;

[P2P - UTorrent {PCI_DSS: 10.6.1}] [any] []
p:r:utorrent.exe;

[P2P - LimeWire {PCI_DSS: 11.4}] [any] []
r:HKEY_LOCAL_MACHINE\SOFTWARE\Limewire;
r:HKLM\software\microsoft\windows\currentversion\run -> limeshop;
f:\Program Files\limewire;
f:\Program Files\limeshop;

[P2P/Adware - Kazaa {PCI_DSS: 11.4}] [any] []
f:\Program Files\kazaa;
f:\Documents and Settings\All Users\Start Menu\Programs\kazaa;
f:\Documents and Settings\All Users\DESKTOP\Kazaa Media Desktop.lnk;
f:\Documents and Settings\All Users\DESKTOP\Kazaa Promotions.lnk;
f:%WINDIR%\System32\Cd_clint.dll;
f:%WINDIR%\Sysnative\Cd_clint.dll;
r:HKEY_LOCAL_MACHINE\SOFTWARE\KAZAA;
r:HKEY_CURRENT_USER\SOFTWARE\KAZAA;
r:HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN\KAZAA;

# http://vil.nai.com/vil/content/v_135023.htm
[Adware - RxToolBar {PCI_DSS: 11.4}] [any] [http://vil.nai.com/vil/content/v_135023.htm]
r:HKEY_CURRENT_USER\Software\Infotechnics;
r:HKEY_CURRENT_USER\Software\Infotechnics\RX Toolbar;
r:HKEY_CURRENT_USER\Software\RX Toolbar;
r:HKEY_CLASSES_ROOT\BarInfoUrl.TBInfo;
r:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RX Toolbar;
f:\Program Files\RXToolBar;

# http://btfaq.com/serve/cache/18.html
[P2P - BitTorrent {PCI_DSS: 10.6.1}] [any] [http://btfaq.com/serve/cache/18.html]
f:\Program Files\BitTorrent;
r:HKEY_CLASSES_ROOT\.torrent;
r:HKEY_CLASSES_ROOT\MIME\Database\Content Type\application/x-bittorrent;
r:HKEY_CLASSES_ROOT\bittorrent;
r:HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\BitTorrent;

# http://www.gotomypc.com
[Remote Access - GoToMyPC {PCI_DSS: 10.6.1}] [any] []
f:\Program Files\Citrix\GoToMyPC;
f:\Program Files\Citrix\GoToMyPC\g2svc.exe;
f:\Program Files\Citrix\GoToMyPC\g2comm.exe;
f:\Program Files\expertcity\GoToMyPC;
r:HKLM\software\microsoft\windows\currentversion\run -> gotomypc;
r:HKEY_LOCAL_MACHINE\software\citrix\gotomypc;
r:HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gotomypc;
p:r:g2svc.exe;
p:r:g2pre.exe;

[Spyware - Twain Tec Spyware {PCI_DSS: 11.4}] [any] []
r:HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TwaintecDll.TwaintecDllObj.1;
r:HKEY_LOCAL_MACHINE\SOFTWARE\twaintech;
f:%WINDIR%\twaintec.dll;

# http://www.symantec.com/security_response/writeup.jsp?docid=2004-062611-4548-99&tabid=2
[Spyware - SpyBuddy {PCI_DSS: 11.4}] [any] []
f:\Program Files\ExploreAnywhere\SpyBuddy\sb32mon.exe;
f:\Program Files\ExploreAnywhere\SpyBuddy;
f:\Program Files\ExploreAnywhere;
f:%WINDIR%\System32\sysicept.dll;
f:%WINDIR%\Sysnative\sysicept.dll;
r:HKEY_LOCAL_MACHINE\Software\ExploreAnywhere Software\SpyBuddy;

[Spyware - InternetOptimizer {PCI_DSS: 11.4}] [any] []
r:HKLM\SOFTWARE\Avenue Media;
r:HKEY_CLASSES_ROOT\\safesurfinghelper.iebho.1;
r:HKEY_CLASSES_ROOT\\safesurfinghelper.iebho;
!4282 win_audit_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Windows Audit - (C) 2007 Daniel B. Cid - dcid@ossec.net
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Application name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# Values can be preceded by: =: (for equal) - default
#                             r: (for ossec regexes)
#                             >: (for strcmp greater)
#                             <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# http://technet2.microsoft.com/windowsserver/en/library/486896ba-dfa1-4850-9875-13764f749bba1033.mspx?mfr=true
[Disabled Registry tools set {PCI_DSS: 10.6.1}] [any] []
r:HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System -> DisableRegistryTools -> 1;
r:HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System -> DisableRegistryTools -> 1;

# http://support.microsoft.com/kb/825750
[DCOM disabled {PCI_DSS: 10.6.1}] [any] []
r:HKEY_LOCAL_MACHINE\Software\Microsoft\OLE -> EnableDCOM -> N;

# http://web.mit.edu/is/topics/windows/server/winmitedu/security.html
[LM authentication allowed (weak passwords) {PCI_DSS: 10.6.1, 11.4}] [any] []
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -> LMCompatibilityLevel -> 0;
r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -> LMCompatibilityLevel -> 1;

# http://research.eeye.com/html/alerts/AL20060813.html
# Disabled by some Malwares (sometimes by McAfee and Symantec
# security center too).
[Firewall/Anti Virus notification disabled {PCI_DSS: 10.6.1}] [any] []
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center -> FirewallDisableNotify -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center -> antivirusoverride -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center -> firewalldisablenotify -> !0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center -> firewalldisableoverride -> !0;

# Checking for the microsoft firewall.
[Microsoft Firewall disabled {PCI_DSS: 10.6.1, 1.4}] [all] []
r:HKEY_LOCAL_MACHINE\software\policies\microsoft\windowsfirewall\domainprofile -> enablefirewall -> 0;
r:HKEY_LOCAL_MACHINE\software\policies\microsoft\windowsfirewall\standardprofile -> enablefirewall -> 0;

#http://web.mit.edu/is/topics/windows/server/winmitedu/security.html
[Null sessions allowed {PCI_DSS: 11.4}] [any] []
r:HKLM\System\CurrentControlSet\Control\Lsa -> RestrictAnonymous -> 0;

[Error reporting disabled {PCI_DSS: 10.6.1}] [any] [http://windowsir.blogspot.com/2007/04/something-new-to-look-for.html]
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting -> DoReport -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting -> IncludeKernelFaults -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting -> IncludeMicrosoftApps -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting -> IncludeWindowsApps -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting -> IncludeShutdownErrs -> 0;
r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting -> ShowUI -> 0;

# http://support.microsoft.com/default.aspx?scid=315231
[Automatic Logon enabled {PCI_DSS: 10.6.1}] [any] [http://support.microsoft.com/default.aspx?scid=315231]
r:HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon -> DefaultPassword;
r:HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon -> AutoAdminLogon -> 1;

[Winpcap packet filter driver found {PCI_DSS: 10.6.1}] [any] []
f:%WINDIR%\System32\drivers\npf.sys;
f:%WINDIR%\Sysnative\drivers\npf.sys;
!7319 win_malware_rcl.txt
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
# OSSEC Windows Malware list - (C) 2007 Daniel B. Cid - dcid@ossec.net
#
# Released under the same license as OSSEC.
# More details at the LICENSE file included with OSSEC or online
# at: https://www.gnu.org/licenses/gpl.html
#
# [Malware name] [any or all] [reference]
# type:<entry name>;
#
# Type can be:
#             - f (for file or directory)
#             - r (registry entry)
#             - p (process running)
#
# Additional values:
# For the registry and for directories, use "->" to look for a specific entry and another
# "->" to look for the value.
# Also, use " -> r:^\. -> ..." to search all files in a directory
# For files, use "->" to look for a specific value in the file.
#
# # Values can be preceded by: =: (for equal) - default
#                               r: (for ossec regexes)
#                               >: (for strcmp greater)
#                               <: (for strcmp  lower)
# Multiple patterns can be specified by using " && " between them.
# (All of them must match for it to return true).

# http://www.iss.net/threats/ginwui.html
[Ginwui Backdoor {PCI_DSS: 11.4}] [any] [http://www.iss.net/threats/ginwui.html]
f:%WINDIR%\System32\zsyhide.dll;
f:%WINDIR%\Sysnative\zsyhide.dll;
f:%WINDIR%\System32\zsydll.dll;
f:%WINDIR%\Sysnative\zsydll.dll;
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\zsydll;
r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows -> AppInit_DLLs -> r:zsyhide.dll;

# http://www.symantec.com/security_response/writeup.jsp?docid=2006-081312-3302-99&tabid=2
[Wargbot Backdoor {PCI_DSS: 11.4}] [any] []
f:%WINDIR%\System32\wgareg.exe;
f:%WINDIR%\Sysnative\wgareg.exe;
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wgareg;

# http://www.f-prot.com/virusinfo/descriptions/sober_j.html
[Sober Worm {PCI_DSS: 11.4}] [any] []
f:%WINDIR%\System32\nonzipsr.noz;
f:%WINDIR%\Sysnative\nonzipsr.noz;
f:%WINDIR%\System32\clonzips.ssc;
f:%WINDIR%\Sysnative\clonzips.ssc;
f:%WINDIR%\System32\clsobern.isc;
f:%WINDIR%\Sysnative\clsobern.isc;
f:%WINDIR%\System32\sb2run.dii;
f:%WINDIR%\Sysnative\sb2run.dii;
f:%WINDIR%\System32\winsend32.dal;
f:%WINDIR%\Sysnative\winsend32.dal;
f:%WINDIR%\System32\winroot64.dal;
f:%WINDIR%\Sysnative\winroot64.dal;
f:%WINDIR%\System32\zippedsr.piz;
f:%WINDIR%\Sysnative\zippedsr.piz;
f:%WINDIR%\System32\winexerun.dal;
f:%WINDIR%\Sysnative\winexerun.dal;
f:%WINDIR%\System32\winmprot.dal;
f:%WINDIR%\Sysnative\winmprot.dal;
f:%WINDIR%\System32\dgssxy.yoi;
f:%WINDIR%\Sysnative\dgssxy.yoi;
f:%WINDIR%\System32\cvqaikxt.apk;
f:%WINDIR%\Sysnative\cvqaikxt.apk;
f:%WINDIR%\System32\sysmms32.lla;
f:%WINDIR%\Sysnative\sysmms32.lla;
f:%WINDIR%\System32\Odin-Anon.Ger;
f:%WINDIR%\Sysnative\Odin-Anon.Ger;

# http://www.symantec.com/security_response/writeup.jsp?docid=2005-042611-0148-99&tabid=2
[Hotword Trojan {PCI_DSS: 11.4}] [any] []
f:%WINDIR%\System32\_;
f:%WINDIR%\Sysnative\_;
f:%WINDIR%\System32\explore.exe;
f:%WINDIR%\Sysnative\explore.exe;
f:%WINDIR%\System32\ svchost.exe;
f:%WINDIR%\Sysnative\ svchost.exe;
f:%WINDIR%\System32\mmsystem.dlx;
f:%WINDIR%\Sysnative\mmsystem.dlx;
f:%WINDIR%\System32\WINDLL-ObjectsWin*.DLX;
f:%WINDIR%\Sysnative\WINDLL-ObjectsWin*.DLX;
f:%WINDIR%\System32\CFXP.DRV;
f:%WINDIR%\Sysnative\CFXP.DRV;
f:%WINDIR%\System32\CHJO.DRV;
f:%WINDIR%\Sysnative\CHJO.DRV;
f:%WINDIR%\System32\MMSYSTEM.DLX;
f:%WINDIR%\Sysnative\MMSYSTEM.DLX;
f:%WINDIR%\System32\OLECLI.DL;
f:%WINDIR%\Sysnative\OLECLI.DL;

[Beagle worm {PCI_DSS: 11.4}] [any] []
f:%WINDIR%\System32\winxp.exe;
f:%WINDIR%\Sysnative\winxp.exe;
f:%WINDIR%\System32\winxp.exeopen;
f:%WINDIR%\Sysnative\winxp.exeopen;
f:%WINDIR%\System32\winxp.exeopenopen;
f:%WINDIR%\Sysnative\winxp.exeopenopen;
f:%WINDIR%\System32\winxp.exeopenopenopen;
f:%WINDIR%\Sysnative\winxp.exeopenopenopen;
f:%WINDIR%\System32\winxp.exeopenopenopenopen;
f:%WINDIR%\Sysnative\winxp.exeopenopenopenopen;

# http://symantec.com/security_response/writeup.jsp?docid=2007-071711-3132-99
[Gpcoder Trojan {PCI_DSS: 11.4}] [any] [http://symantec.com/security_response/writeup.jsp?docid=2007-071711-3132-99]
f:%WINDIR%\System32\ntos.exe;
f:%WINDIR%\Sysnative\ntos.exe;
f:%WINDIR%\System32\wsnpoem;
f:%WINDIR%\Sysnative\wsnpoem;
f:%WINDIR%\System32\wsnpoem\audio.dll;
f:%WINDIR%\Sysnative\wsnpoem\audio.dll;
f:%WINDIR%\System32\wsnpoem\video.dll;
f:%WINDIR%\Sysnative\wsnpoem\video.dll;
r:HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run -> userinit -> r:ntos.exe;

# [http://www.symantec.com/security_response/writeup.jsp?docid=2006-112813-0222-99&tabid=2
[Looked.BK Worm {PCI_DSS: 11.4}] [any] []
f:%WINDIR%\uninstall\rundl132.exe;
f:%WINDIR%\Logo1_.exe;
f:%Windir%\RichDll.dll;
r:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -> load -> r:rundl132.exe;

[Possible Malware - Svchost running outside system32 {PCI_DSS: 11.4}] [all] []
p:r:svchost.exe && !%WINDIR%\System32\svchost.exe;
f:!%WINDIR%\SysWOW64;

[Possible Malware - Inetinfo running outside system32\inetsrv {PCI_DSS: 11.4}] [all] []
p:r:inetinfo.exe && !%WINDIR%\System32\inetsrv\inetinfo.exe;
f:!%WINDIR%\SysWOW64;

[Possible Malware - Rbot/Sdbot detected {PCI_DSS: 11.4}] [any] []
f:%Windir%\System32\rdriv.sys;
f:%Windir%\Sysnative\rdriv.sys;
f:%Windir%\lsass.exe;

[Possible Malware File {PCI_DSS: 11.4}] [any] []
f:%WINDIR%\utorrent.exe;
f:%WINDIR%\System32\utorrent.exe;
f:%WINDIR%\Sysnative\utorrent.exe;
f:%WINDIR%\System32\Files32.vxd;
f:%WINDIR%\Sysnative\Files32.vxd;

# Modified /etc/hosts entries
# Idea taken from:
# http://blog.tenablesecurity.com/2006/12/detecting_compr.html
# http://www.sophos.com/security/analyses/trojbagledll.html
# http://www.f-secure.com/v-descs/fantibag_b.shtml
[Anti-virus site on the hosts file] [any] []
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:avp.ch|avp.ru|nai.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:avp.ch|avp.ru|nai.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:awaps.net|ca.com|mcafee.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:awaps.net|ca.com|mcafee.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:microsoft.com|f-secure.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:microsoft.com|f-secure.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:sophos.com|symantec.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:sophos.com|symantec.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:my-etrust.com|viruslist.ru;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:my-etrust.com|viruslist.ru;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:networkassociates.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:networkassociates.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:kaspersky|grisoft.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:kaspersky|grisoft.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:symantecliveupdate.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:symantecliveupdate.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:clamav.net|bitdefender.com;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:clamav.net|bitdefender.com;
f:%WINDIR%\System32\Drivers\etc\HOSTS -> r:antivirus.com|sans.org;
f:%WINDIR%\Sysnative\Drivers\etc\HOSTS -> r:antivirus.com|sans.org;
