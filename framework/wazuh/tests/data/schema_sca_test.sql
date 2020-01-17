/*
 * SQL Schema SCA tests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE sca_policy (name TEXT, file TEXT, id TEXT, description TEXT, `references` TEXT, hash_file TEXT);

CREATE TABLE IF NOT EXISTS sca_scan_info (
   id INTEGER PRIMARY KEY,
   start_scan INTEGER,
   end_scan INTEGER,
   policy_id TEXT REFERENCES sca_policy (id),
   pass INTEGER,
   fail INTEGER,
   invalid INTEGER,
   total_checks INTEGER,
   score INTEGER,
   hash TEXT
);


CREATE TABLE IF NOT EXISTS sca_check (
   scan_id INTEGER REFERENCES sca_scan_info (id),
   id INTEGER PRIMARY KEY,
   policy_id TEXT REFERENCES sca_policy (id),
   title TEXT,
   description TEXT,
   rationale TEXT,
   remediation TEXT,
   file TEXT,
   process TEXT,
   directory TEXT,
   registry TEXT,
   command TEXT,
   `references` TEXT,
   result TEXT,
   `status` TEXT,
   reason TEXT,
   condition TEXT
);
CREATE INDEX policy_id_index ON sca_check (policy_id);

CREATE TABLE sca_check_compliance (id_check INTEGER REFERENCES sca_check (id), `key` TEXT, `value` TEXT,
                                   PRIMARY KEY (id_check, `key`, `value`));
CREATE INDEX id_check_index ON sca_check_compliance (id_check);

CREATE TABLE sca_check_rules (id_check INTEGER REFERENCES sca_check (id), type TEXT, rule TEXT,
                              PRIMARY KEY (id_check, type, rule));
CREATE INDEX id_check_rules_index ON sca_check_rules (id_check);


INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1000,'system_audit','PHP - Register globals are enabled',NULL,NULL,NULL,'/etc/php.ini',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/php.ini not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1001,'system_audit','PHP - Expose PHP is enabled',NULL,NULL,NULL,'/etc/php.ini',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/php.ini not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1002,'system_audit','PHP - Allow URL fopen is enabled',NULL,NULL,NULL,'/etc/php.ini',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/php.ini not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1003,'system_audit','PHP - Displaying of errors is enabled',NULL,NULL,NULL,'/etc/php.ini',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/php.ini not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1004,'system_audit','Web exploits: ''.yop'' is an uncommon file name inside htdocs - Possible compromise',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1005,'system_audit','Web exploits: ''id'' is an uncommon file name inside htdocs - Possible compromise',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1006,'system_audit','Web exploits: ''.ssh'' is an uncommon file name inside htdocs',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1007,'system_audit','Web exploits: ''...'' is an uncommon file name inside htdocs - Possible compromise',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1008,'system_audit','Web exploits: ''.shell'' is an uncommon file name inside htdocs - Possible compromise',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1009,'system_audit','Web vulnerability - Outdated WordPress installation',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1010,'system_audit','Web vulnerability - Outdated Joomla installation',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1011,'system_audit','Web vulnerability - Outdated osCommerce (v2.2) installation',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1012,'system_audit','Web vulnerability - Backdoors / Web based malware found - eval(base64_decode)',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1013,'system_audit','Web vulnerability - Backdoors / Web based malware found - eval(base64_decode(POST))',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,NULL,'','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1014,'system_audit','Web vulnerability - .htaccess file compromised',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,'https://blog.sucuri.net/2011/05/understanding-htaccess-attacks-part-1.html','','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
339510093,1015,'system_audit','Web vulnerability - .htaccess file compromised - auto append',NULL,NULL,NULL,NULL,NULL,'/var/www,/var/htdocs,/home/httpd,/usr/local/apache,/usr/local/apache2,/usr/local/www',NULL,NULL,'https://blog.sucuri.net/2011/05/understanding-htaccess-attacks-part-1.html','','Not applicable','Directory /usr/local/www not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1500,'system_audit_ssh','SSH Hardening - 1: Port 22','The ssh daemon should not be listening on port 22 (the default value) for incoming connections.','Changing the default port you may reduce the number of successful attacks from zombie bots, an attacker or bot doing port-scanning can quickly identify your SSH port.','Change the Port option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1501,'system_audit_ssh','SSH Hardening - 2: Protocol 1','The SSH protocol should not be 1.','The Protocol parameter dictates which version of the SSH communication and encryption protocols are in use. Version 1 of the SSH protocol has weaknesses.','Change the Protocol option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1502,'system_audit_ssh','SSH Hardening - 3: Root can log in','The option PermitRootLogin should be set to no.','The option PermitRootLogin specifies whether root can log in using ssh. If you want log in as root, you should use the option "Match" and restrict it to a few IP addresses.','Change the PermitRootLogin option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1503,'system_audit_ssh','SSH Hardening - 4: No Public Key authentication','The option PubkeyAuthentication should be set yes.','Access only by public key. Generally people will use weak passwords and have poor password practices. Keys are considered stronger than password.','Change the PubkeyAuthentication option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1504,'system_audit_ssh','SSH Hardening - 5: Password Authentication','The option PasswordAuthentication should be set to no.','The option PasswordAuthentication specifies whether we should use password-based authentication. Use public key authentication instead of passwords.','Change the PasswordAuthentication option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1505,'system_audit_ssh','SSH Hardening - 6: Empty passwords allowed','The option PermitEmptyPasswords should be set to no.','The option PermitEmptyPasswords specifies whether the server allows logging in to accounts with a null password. Accounts with null passwords are a bad practice.','Change the PermitEmptyPasswords option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1506,'system_audit_ssh','SSH Hardening - 7: Rhost or shost used for authentication','The option IgnoreRhosts should be set to yes.','The option IgnoreRhosts specifies whether rhosts or shosts files should not be used in authentication. For security reasons it is recommended to no use rhosts or shosts files for authentication.','Change the IgnoreRhosts option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1507,'system_audit_ssh','SSH Hardening - 8: Wrong Grace Time.','The option LoginGraceTime should be set to 30.','The option LoginGraceTime specifies how long in seconds after a connection request the server will wait before disconnecting if the user has not successfully logged in. 30 seconds is the recommended time for avoiding open connections without authenticate.','Change the LoginGraceTime option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
175934594,1508,'system_audit_ssh','SSH Hardening - 9: Wrong Maximum number of authentication attempts','The option MaxAuthTries should be set to 4.','The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. Once the number of failures reaches half this value, additional failures are logged. This should be set to 4.','Change the MaxAuthTries option value in the sshd_config file.','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5000,'cis_debian','Ensure /tmp is configured','The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.','Making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw. This can be accomplished by either mounting tmpfs to /tmp, or creating a separate partition for /tmp.','Configure /etc/fstab as appropiate or enable systemd /tmp mounting and edit /etc/systemd/system/local-fs.target.wants/tmp.mount to configure the /tmp mount.','/etc/fstab',NULL,NULL,NULL,NULL,'https://tldp.org/HOWTO/LVM-HOWTO/,https://www.freedesktop.org/wiki/Software/systemd/APIFileSystems/','failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5001,'cis_debian','Ensure nodev option set on /tmp partition','The nodev mount option specifies that the filesystem cannot contain special devices.','Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp .','Edit /etc/systemd/system/local-fs.target.wants/tmp.mount to configure the /tmp and enable systemd /tmp mounting.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5002,'cis_debian','Ensure separate partition exists for /opt','The /opt directory is a world-writable directory used for temporary storage by all users and some applications.','Since the /opt directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition.','For new installations, during installation create a custom partition setup and specify a separate partition for /opt. For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.','/opt,/etc/fstab',NULL,NULL,NULL,NULL,'https://tldp.org/HOWTO/LVM-HOWTO/','failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5003,'cis_debian','Ensure separate partition exists for /var','The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.','Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition.','For new installations, during installation create a custom partition setup and specify a separate partition for /var. For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.','/etc/fstab',NULL,NULL,NULL,NULL,'https://tldp.org/HOWTO/LVM-HOWTO/','failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5004,'cis_debian','Ensure separate partition exists for /var/tmp','The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.','Since the /var/tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /var/tmp its own file system allows an administrator to set the noexec option on the mount, making /var/tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.','For new installations, during installation create a custom partition setup and specify a separate partition for /var/tmp . For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'failed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5005,'cis_debian','Ensure nodev option set on /var/tmp partition','The nodev mount option specifies that the filesystem cannot contain special devices.','Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp .','Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information. Run the following command to remount /var/tmp: # mount -o remount,nodev /var/tmp','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5006,'cis_debian','Ensure nodev option set on /home partition','The nodev mount option specifies that the filesystem cannot contain special devices.','Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices.','Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /home partition. See the fstab(5) manual page for more information. # mount -o remount,nodev /home','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5007,'cis_debian','Ensure nodev option set on /dev/shm partition','The nodev mount option specifies that the filesystem cannot contain special devices.','Since the /run/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions.','Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information. Run the following command to remount /dev/shm : # mount -o remount,nodev /dev/shm.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5008,'cis_debian','Ensure nosuid option set on /dev/shm partition','The nosuid mount option specifies that the filesystem cannot contain setuid files.','Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.','Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information. Run the following command to remount /dev/shm: # mount -o remount,nosuid /dev/shm.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5009,'cis_debian','Ensure noexec option set on /dev/shm partition','The noexec mount option specifies that the filesystem cannot contain executable binaries.','Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.','Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information. Run the following command to remount /dev/shm: # mount -o remount,noexec /dev/shm.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5010,'cis_debian','Ensure nodev option set on removable media partitions','The nodev mount option specifies that the filesystem cannot contain special devices.','Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions.','Edit the /etc/fstab file and add nodev to the fourth field (mounting options) of all removable media partitions. Look for entries that have mount points that contain words such as floppy or cdrom. See the fstab(5) manual page for more information.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5011,'cis_debian','Ensure nosuid option set on removable media partitions','The nosuid mount option specifies that the filesystem cannot contain setuid files.','Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.','Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) of all removable media partitions. Look for entries that have mount points that contain words such as floppy or cdrom. See the fstab(5) manual page for more information.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5012,'cis_debian','Ensure bootloader password is set (GRUB)','Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters','Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time).','Create an encrypted password with grub-mkpasswd-pbkdf2, add user and password to the grub configuration file and update the grub2 configuration.','/boot/grub/menu.lst',NULL,NULL,NULL,NULL,'https://help.ubuntu.com/community/Grub2/Passwords','','Not applicable','File /boot/grub/menu.lst not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5013,'cis_debian','Ensure bootloader password is set (LILO)','Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters','Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time).','Create an encrypted password with grub-mkpasswd-pbkdf2, add user and password to the grub configuration file and update the grub2 configuration.','/etc/lilo.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/lilo.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5014,'cis_debian','Ensure GDM login banner is configured','GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.','Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place.','Edit or create the file /etc/gdm3/greeter.dconf-defaults and add: banner-message-enable=true, banner-message-text=''Authorized uses only. All activity may be monitored and reported.''','/etc/inittab',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inittab not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5015,'cis_debian','Add nodev Option to /run/shm Partition','The nodev mount option specifies that the /run/shm (temporary filesystem stored in memory) cannot contain block or character special devices.','Since the /run/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /run/shm partitions.','Edit the /etc/fstab file and add nodev to the fourth field (mounting options of entries that have mount points that contain /run/shm . See the fstab(5) manual page for more information. # mount -o remount,nodev /run/shm','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5016,'cis_debian','Add nosuid Option to /run/shm Partition','The nosuid mount option specifies that the /run/shm (temporary filesystem stored in memory) will not execute setuid and setgid on executable programs as such, but rather execute them with the uid and gid of the user executing the program.','Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.','Edit the /etc/fstab file and add nosuid to the fourth field (mounting options). Look for entries that have mount points that contain /run/shm . See the fstab(5) manual page for more information. # mount -o remount,nosuid /run/shm.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5017,'cis_debian','Add noexec Option to /run/shm Partition','Set noexec on the shared memory partition to prevent programs from executing from there.','Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.','Edit the /etc/fstab file and add noexec to the fourth field (mounting options). Look for entries that have mount points that contain /run/shm . See the fstab(5) manual page for more information. # mount -o remount,noexec /run/shm.','/etc/fstab',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5018,'cis_debian','Ensure inetd is not installed','The inetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.','If there are no inetd services required, it is recommended that the daemon be removed.','Run the following commands to uninstall openbsd-inetd and inetutils-inetd: apt-get remove openbsd-inetd; apt-get remove inetutils-inetd','/etc/inetd.conf','inetd',NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5019,'cis_debian','Ensure FTP Server is not enabled','The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.','FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface.','Run the following command to disable vsftpd: # systemctl disable vsftpd','/etc/inetd.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5020,'cis_debian','Ensure FTP Server is not enabled','The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.','FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface.','Run the following command to disable vsftpd: # systemctl disable vsftpd','/etc/inetd.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5021,'cis_debian','Ensure IMAP and POP3 server is not enabled (IMAP)','exim is an open source IMAP and POP3 server for Linux based systems.','Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.','Run the following commands to remove exim: # apt-get remove exim4; # apt-get purge exim4','/etc/inetd.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5022,'cis_debian','Ensure IMAP and POP3 server is not enabled (POP3)','exim is an open source IMAP and POP3 server for Linux based systems.','Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.','Run the following commands to remove exim: # apt-get remove exim4; # apt-get purge exim4','/etc/inetd.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5023,'cis_debian','Ensure Samba is not enabled','The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.','If there is no need to mount directories and file systems to Windows systems, then this service can be deleted to reduce the potential attack surface.','Run the following command to disable smbd: # systemctl disable smbd','/etc/init.d/samba',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/init.d/samba not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5024,'cis_debian','Ensure NFS and RPC are not enabled','The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.','If the system does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface.','Run the following commands to disable nfs and rpcbind : # systemctl disable nfs-server; # systemctl disable rpcbind','/etc/init.d/nfs-common,/etc/init.d/nfs-user-server,/etc/init.d/nfs-kernel-server',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/init.d/nfs-kernel-server not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5025,'cis_debian','Ensure NIS Server is not enabled','The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.','The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used','Run the following command to disable nis: # systemctl disable nis','/etc/init.d/nis',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/init.d/nis not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5026,'cis_debian','Ensure HTTP server is not enabled','HTTP or web servers provide the ability to host web site content.','Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface.','Run the following command to disable apache2: # systemctl disable apache2','/etc/init.d/apache,/etc/init.d/apache2',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/init.d/apache2 not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5027,'cis_debian','Ensure DNS Server is not enabled','The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.','Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface.','Run the following command to disable named: # systemctl disable bind9','/etc/init.d/bind',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/init.d/bind not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5028,'cis_debian','Ensure HTTP Proxy Server is not enabled','Squid is a standard proxy server used in many distributions and environments.','If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface.','Run the following command to disable squid: # systemctl disable squid','/etc/init.d/squid',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/init.d/squid not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5029,'cis_debian','Ensure rsh client is not installed','The rsh package contains the client commands for the rsh services.','These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh , rcp and rlogin .','Run the following command to uninstall rsh: apt-get remove rsh-client rsh-redone-client','/etc/inetd.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5030,'cis_debian','Ensure telnet client is not installed','The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.','The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions.','Run the following command to uninstall telnet: # apt-get remove telnet','/etc/inetd.conf',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /etc/inetd.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5031,'cis_debian','Ensure IP forwarding is disabled','The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to tell the system whether it can forward packets or not.','Setting the flags to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router.','Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4.ip_forward = 0, net.ipv6.conf.all.forwarding = 0','/proc/sys/net/ipv4/ip_forward,/proc/sys/net/ipv6/ip_forward',NULL,NULL,NULL,NULL,NULL,'','Not applicable','File /proc/sys/net/ipv6/ip_forward not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5032,'cis_debian','Ensure source routed packets are not accepted','In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.','Setting net.ipv4.conf.all.accept_source_route, net.ipv4.conf.default.accept_source_route, net.ipv6.conf.all.accept_source_route and net.ipv6.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing.','Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4.conf.all.accept_source_route = 0, net.ipv4.conf.default.accept_source_route = 0, net.ipv6.conf.all.accept_source_route = 0, net.ipv6.conf.default.accept_source_route = 0','/proc/sys/net/ipv4/conf/all/accept_source_route',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5033,'cis_debian','Ensure broadcast ICMP requests are ignored','Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.','Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied.','Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4.icmp_echo_ignore_broadcasts = 1','/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5034,'cis_debian','Ensure SSH Protocol is set to 2','Older versions of SSH support two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure.','SSH v1 suffers from insecurities that do not affect SSH v2.','Edit the /etc/ssh/sshd_config file to set the parameter as follows: Protocol 2','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5035,'cis_debian','Ensure SSH IgnoreRhosts is enabled','The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication .','Setting this parameter forces users to enter a password when authenticating with ssh.','Edit the /etc/ssh/sshd_config file to set the parameter as follows: IgnoreRhosts yes','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5036,'cis_debian','Ensure SSH HostbasedAuthentication is disabled','The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts , or /etc/hosts.equiv , along with successful public key client host authentication. This option only applies to SSH Protocol Version 2.','Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an additional layer of protection.','Edit the /etc/ssh/sshd_config file to set the parameter as follows: HostbasedAuthentication no','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5037,'cis_debian','Ensure SSH root login is disabled','The PermitRootLogin parameter specifies if the root user can log in using ssh. The default is no.','Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su . This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident','Edit the /etc/ssh/sshd_config file to set the parameter as follows: PermitRootLogin no','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5038,'cis_debian','Ensure SSH PermitEmptyPasswords is disabled','The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings.','Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system','Edit the /etc/ssh/sshd_config file to set the parameter as follows: PermitEmptyPasswords no','/etc/ssh/sshd_config',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5039,'cis_debian','Ensure password fields are not empty','An account with an empty password field means that anybody may log in as that user without providing a password.','All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.','If any accounts in the /etc/shadow file do not have a password, run the following command to lock the account until it can be determined why it does not have a password: # passwd -l <username>','/etc/shadow',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
998963039,5040,'cis_debian','Ensure root is the only UID 0 account','Any account with UID 0 has superuser privileges on the system.','This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted.','Remove any users other than root with UID 0 or assign them a new UID if appropriate.','/etc/passwd',NULL,NULL,NULL,NULL,NULL,'passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
683548315,13000,'system_audit_pw','Ensure password creation requirements are configured','The pam_pwquality.so module and pam_cracklib.so module (depending on the Linux distribution used) checks the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more.','Strong passwords protect systems from being hacked through brute force methods.','Edit the /etc/pam.d/common-password and /etc/security/pwquality.conf files, or the /etc/pam.d/password-auth and /etc/pam.d/system-auth files, to include the appropriate options for pam_pwquality.so or pam_cracklib.so and to conform to site policy','/etc/pam.d/common-password,/etc/pam.d/password-auth,/etc/pam.d/system-auth,/etc/pam.d/system-auth-ac,/etc/pam.d/passwd,/etc/security/pwquality.conf',NULL,NULL,NULL,NULL,'https://linux-audit.com/configure-the-minimum-password-length-on-linux-systems/','','Not applicable','File /etc/security/pwquality.conf not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
683548315,13001,'system_audit_pw','Ensure password hashing algorithm is SHA-512','The password encryption should use a strong hashing algorithm such as SHA-256 or SHA-512 instead of MD5.','The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords.','Edit the /etc/pam.d/common-password file or /etc/pam.d/password-auth and /etc/pam.d/system-auth files (depending on the Linux distribution used) to include the sha512 option for pam_unix.so.','/etc/security/policy.conf,/etc/login.defs,/etc/pam.d/common-password,/etc/pam.d/password-auth,/etc/pam.d/system-auth,/etc/pam.d/system-auth-ac',NULL,NULL,NULL,NULL,'https://security.stackexchange.com/questions/77349/how-can-i-find-out-the-password-hashing-schemes-used-by-the-specific-unix-accoun,https://docs.oracle.com/cd/E26505_01/html/E27224/secsystask-42.html','','Not applicable','File /etc/pam.d/system-auth-ac not found','any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
683548315,13002,'system_audit_pw','Ensure passwords in /etc/shadow are hashed with SHA-512 or SHA-256','SHA-512 and SHA-256 are much stronger hashing algorithms than MD5.','The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords.','Set the default algorithm for password hashing in /etc/shadow to SHA-512 or SHA-256.','/etc/shadow',NULL,NULL,NULL,NULL,'https://linux-audit.com/password-security-with-linux-etc-shadow-file/,https://docs.oracle.com/cd/E19253-01/816-4557/concept-23/index.html','passed',NULL,NULL,'any');
INSERT INTO sca_check (scan_id,id,policy_id,title,description,rationale,remediation,file,process,directory,registry,command,"references","result",status,reason,condition) VALUES (
683548315,13003,'system_audit_pw','Ensure password expiration is 365 days or less','The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 365 days.','The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker''s window of opportunity.','Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs.','/etc/default/passwd,/etc/login.defs',NULL,NULL,NULL,NULL,'https://www.thegeekdiary.com/understanding-etclogin-defs-file','failed',NULL,NULL,'any');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5000,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5000,'cis','1.1.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5001,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5001,'cis','1.1.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5001,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5002,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5002,'cis','1.1.6');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5003,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5003,'cis','1.1.6');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5004,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5004,'cis','1.1.7');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5005,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5005,'cis','1.1.8');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5005,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5006,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5006,'cis','1.1.14');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5006,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5007,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5007,'cis','1.1.14');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5008,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5008,'cis','1.1.15');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5009,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5009,'cis','1.1.16');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5010,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5010,'cis','1.1.18');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5010,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5011,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5011,'cis','1.1.19');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5011,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5012,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5012,'cis','1.4.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5012,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5013,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5013,'cis','1.4.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5013,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5014,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5014,'cis','1.7.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5014,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5015,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5015,'cis','2.14');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5015,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5016,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5016,'cis','2.15');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5017,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5017,'cis','2.16');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5018,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5018,'cis','2.1.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5018,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5019,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5019,'cis','2.2.9');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5019,'pci_dss','2.2.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5020,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5020,'cis','2.2.9');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5020,'pci_dss','2.2.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5021,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5021,'cis','2.2.11');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5021,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5022,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5022,'cis','2.2.11');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5022,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5023,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5023,'cis','2.2.12');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5023,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5024,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5024,'cis','2.2.7');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5024,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5025,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5025,'cis','2.2.17');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5025,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5026,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5026,'cis','2.2.10');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5026,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5027,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5027,'cis','2.2.8');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5027,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5028,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5028,'cis','2.2.13');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5028,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5029,'cis_csc','2.6, 4.5');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5029,'cis','2.3.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5029,'pci_dss','2.2.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5030,'cis_csc','2.6, 4.5');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5030,'cis','2.3.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5030,'pci_dss','2.2.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5031,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5031,'cis','3.1.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5032,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5032,'cis','3.2.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5033,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5033,'cis','3.2.5');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5034,'cis_csc','14.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5034,'cis','5.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5034,'pci_dss','4.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5035,'cis_csc','9.2');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5035,'cis','5.2.8');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5035,'pci_dss','4.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5036,'cis_csc','16.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5036,'cis','5.2.9');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5036,'pci_dss','4.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5037,'cis_csc','4.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5037,'cis','5.2.10');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5037,'pci_dss','4.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5038,'cis_csc','16.3');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5038,'cis','5.2.11');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5038,'pci_dss','4.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5039,'cis_csc','4.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5039,'cis','6.2.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5039,'pci_dss','10.2.5');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5040,'cis_csc','5.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5040,'cis','6.2.5');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
5040,'pci_dss','10.2.5');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1006,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1004,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1005,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1007,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1008,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1010,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1009,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1012,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1011,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1014,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1013,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1015,'pci_dss','6.5, 6.6, 11.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1500,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1501,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1503,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1504,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1505,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1506,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1507,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
1508,'pci_dss','2.2.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
13000,'cis','5.3.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
13000,'cis_csc','4.4, 5.7, 16.12');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
13001,'cis','5.3.4');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
13001,'cis_csc','16.4, 16.14');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
13003,'cis','5.4.1.1');
INSERT INTO sca_check_compliance (id_check,"key",value) VALUES (
13003,'cis_csc','4.4, 16');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5000,'file','f:/etc/fstab -> !r:/tmp;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5001,'file','f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/tmp && !r:nodev;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5002,'file','f:/opt;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5002,'file','f:/etc/fstab -> !r:/opt;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5003,'file','f:/etc/fstab -> !r:/var;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5004,'file','f:/etc/fstab -> !r:/var/tmp;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5005,'file','f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/var/tmp && !r:nodev;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5006,'file','f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/home && !r:nodev ;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5007,'file','f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nodev;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5008,'file','f:/etc/fstab -> !r:^# && r:/dev/shm && !r:nosuid;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5009,'file','f:/etc/fstab -> !r:^# && r:/dev/shm && !r:noexec;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5010,'file','f:/etc/fstab -> !r:^# && r:/media && !r:nodev;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5011,'file','f:/etc/fstab -> !r:^# && r:/media && !r:nosuid;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5012,'file','f:/boot/grub/menu.lst -> !r:^# && !r:password;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5013,'file','f:/etc/lilo.conf -> !r:^# && !r:restricted;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5013,'file','f:/etc/lilo.conf -> !r:^# && !r:password=;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5014,'file','f:/etc/inittab -> !r:^# && r:id:5;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5015,'file','f:/etc/fstab -> !r:^# && r:ext2|ext3 && r:/run/shm && !r:nodev;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5016,'file','f:/etc/fstab -> !r:^# && r:/run/shm && !r:nosuid;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5017,'file','f:/etc/fstab -> !r:^# && r:/run/shm && !r:noexec;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5018,'process','p:inetd;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5018,'file','f:!/etc/inetd.conf -> !r:^# && r:wait;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5019,'file','f:/etc/inetd.conf -> !r:^# && r:/ftp;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5020,'file','f:/etc/inetd.conf -> !r:^# && r:tftp;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5021,'file','f:/etc/inetd.conf -> !r:^# && r:imap;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5022,'file','f:/etc/inetd.conf -> !r:^# && r:pop;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5023,'file','f:/etc/init.d/samba;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5024,'file','f:/etc/init.d/nfs-common;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5024,'file','f:/etc/init.d/nfs-user-server;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5024,'file','f:/etc/init.d/nfs-kernel-server;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5025,'file','f:/etc/init.d/nis;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5026,'file','f:/etc/init.d/apache;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5026,'file','f:/etc/init.d/apache2;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5027,'file','f:/etc/init.d/bind;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5028,'file','f:/etc/init.d/squid;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5029,'file','f:/etc/inetd.conf -> !r:^# && r:shell|login;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5030,'file','f:/etc/inetd.conf -> !r:^# && r:telnet;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5031,'file','f:/proc/sys/net/ipv4/ip_forward -> 1;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5031,'file','f:/proc/sys/net/ipv6/ip_forward -> 1;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5032,'file','f:/proc/sys/net/ipv4/conf/all/accept_source_route -> 1;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5033,'file','f:/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts -> 0;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5034,'file','f:/etc/ssh/sshd_config -> !r:^# && r:Protocol\.+2;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5035,'file','f:/etc/ssh/sshd_config -> !r:^# && r:IgnoreRhosts\.+no;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5036,'file','f:/etc/ssh/sshd_config -> !r:^# && r:HostbasedAuthentication\.+yes;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5037,'file','f:/etc/ssh/sshd_config -> !r:^# && r:PermitRootLogin\.+yes;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5038,'file','f:/etc/ssh/sshd_config -> !r:^# && r:^PermitEmptyPasswords\.+yes;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5039,'file','f:/etc/shadow -> r:^\w+::;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
5040,'file','f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1000,'file','f:$php.ini -> r:^register_globals = On;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1002,'file','f:$php.ini -> r:^allow_url_fopen = On;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1001,'file','f:$php.ini -> r:^expose_php = On;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1006,'directory','d:$web_dirs -> ^.ssh$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1008,'directory','d:$web_dirs -> ^.shell$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1007,'directory','d:$web_dirs -> ^...$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1004,'directory','d:$web_dirs -> ^.yop$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1005,'directory','d:$web_dirs -> ^id$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1003,'file','f:$php.ini -> r:^display_errors = On;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1011,'directory','d:$web_dirs -> ^application_top.php$ -> r:''osCommerce 2.2-;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1010,'directory','d:$web_dirs -> ^version.php$ -> r:var \.RELEASE && r:''3.4.8'';');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1009,'directory','d:$web_dirs -> ^version.php$ -> r:^\.wp_version && >:$wp_version = ''4.4.2'';');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1012,'directory','d:$web_dirs -> .php$ -> r:eval\(base64_decode\(\paWYo;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1014,'directory','d:$web_dirs -> ^.htaccess$ -> r:RewriteCond \S+HTTP_REFERERS \S+google;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1013,'directory','d:$web_dirs -> .php$ -> r:eval\(base64_decode\(\S_POST;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1015,'directory','d:$web_dirs -> ^.htaccess$ -> r:php_value auto_append_file;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1500,'file','f:$sshd_file -> !r:^# && r:Port\.+22;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1501,'file','f:$sshd_file -> !r:^# && r:Protocol\.+1;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1502,'file','f:$sshd_file -> !r:^\s*PermitRootLogin\.+no;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1503,'file','f:$sshd_file -> !r:^\s*PubkeyAuthentication\.+yes;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1504,'file','f:$sshd_file -> !r:^\s*PasswordAuthentication\.+no;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1505,'file','f:$sshd_file -> !r:^\s*PermitEmptyPasswords\.+no;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1506,'file','f:$sshd_file -> !r:^\s*IgnoreRhosts\.+yes;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1507,'file','f:$sshd_file -> !r:^\s*LoginGraceTime\s+30\s*$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
1508,'file','f:$sshd_file -> !r:^\s*MaxAuthTries\s+4\s*$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_pwquality.so\.+try_first_pass;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_pwquality.so\.+retry=\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_pwquality.so\.+try_first_pass;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_pwquality.so\.+retry=\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_pwquality.so\.+try_first_pass;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_pwquality.so\.+retry=\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth-ac -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_pwquality.so\.+try_first_pass;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth-ac -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_pwquality.so\.+retry=\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_cracklib.so\.+try_first_pass|^password\s*\t*required\s*\t*pam_pwquality.so\.+try_first_pass|^@include\s+common-password;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> !r:^password\s*\t*requisite\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*requisite\s*\t*pam_pwquality.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_cracklib.so\.+retry=\d+|^password\s*\t*required\s*\t*pam_pwquality.so\.+retry=\d+|^@include\s+common-password;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> r:pam_cracklib.so && !r:minlen=\d\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> r:pam_cracklib.so && !r:minlen=\d\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> r:pam_cracklib.so && !r:minlen=\d\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> r:pam_cracklib.so && !r:minlen=\d\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/security/pwquality.conf -> !r:^minlen=\d\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> r:pam_cracklib.so && !r:dcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> r:pam_cracklib.so && !r:dcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> r:pam_cracklib.so && !r:dcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> r:pam_cracklib.so && !r:dcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/security/pwquality.conf -> !r:^dcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> r:pam_cracklib.so && !r:lcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> r:pam_cracklib.so && !r:lcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> r:pam_cracklib.so && !r:lcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> r:pam_cracklib.so && !r:lcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/security/pwquality.conf -> !r:^lcredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> r:pam_cracklib.so && !r:ocredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> r:pam_cracklib.so && !r:ocredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> r:pam_cracklib.so && !r:ocredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> r:pam_cracklib.so && !r:ocredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/security/pwquality.conf -> !r:^ocredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/common-password -> r:pam_cracklib.so && !r:ucredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/password-auth -> r:pam_cracklib.so && !r:ucredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/system-auth -> r:pam_cracklib.so && !r:ucredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/pam.d/passwd -> r:pam_cracklib.so && !r:ucredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13000,'file','f:/etc/security/pwquality.conf -> !r:^ucredit=\p*\d+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/security/policy.conf -> !r:^# && r:^CRYPT_DEFAULT=1|^CRYPT_DEFAULT=2|^CRYPT_DEFAULT=2a|^CRYPT_DEFAULT=2x|^CRYPT_DEFAULT=2y|^CRYPT_DEFAULT=md5|^CRYPT_DEFAULT=__unix__;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/security/policy.conf -> !r:^CRYPT_DEFAULT=\d;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/login.defs -> !r:^# && r:^ENCRYPT_METHOD\s+MD5|^ENCRYPT_METHOD\s+DES;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/login.defs -> !r:^ENCRYPT_METHOD\s+SHA512|^ENCRYPT_METHOD\s+SHA256;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/common-password -> !r:^# && r:password\.+pam_unix.so\.+md5|password\.+pam_unix.so\.+des;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/common-password -> !r:^password\.+pam_unix.so\.+sha512|^password\.+pam_unix.so\.+sha256;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/password-auth -> !r:^# && r:password\.+pam_unix.so\.+md5|password\.+pam_unix.so\.+des;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/password-auth -> !r:^password\.+pam_unix.so\.+sha512|^password\.+pam_unix.so\.+sha256;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/system-auth -> !r:^# && r:password\.+pam_unix.so\.+md5|password\.+pam_unix.so\.+des;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/system-auth -> !r:^password\.+pam_unix.so\.+sha512|^password\.+pam_unix.so\.+sha256;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/system-auth-ac -> !r:^# && r:password\.+pam_unix.so\.+md5|password\.+pam_unix.so\.+des;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13001,'file','f:/etc/pam.d/system-auth-ac -> !r:^password\.+pam_unix.so\.+sha512|^password\.+pam_unix.so\.+sha256;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && !r:^\w+:NP:\d+:\d*:\d*:\d*:\d*:\d*:\d*$ && r:^\w+:\w\.*:\d+:\d*:\d*:\d*:\d*:\d*:\d*$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$1\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$2\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$2a\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$2x\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$2y\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$md5\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13002,'file','f:/etc/shadow -> !r:^# && r:\w+:\$__unix__\$\.+;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13003,'file','f:/etc/default/passwd -> !r:^MAXWEEKS=\d\d$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13003,'file','f:/etc/default/passwd -> !r:^MINWEEKS=\d;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13003,'file','f:/etc/default/passwd -> !r:^WARNWEEKS=\d;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13003,'file','f:/etc/login.defs -> !r:^PASS_MAX_DAYS\s*\t*\d\d$;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13003,'file','f:/etc/login.defs -> !r:^PASS_MIN_DAYS\s*\t*\d;');
INSERT INTO sca_check_rules (id_check,"type",rule) VALUES (
13003,'file','f:/etc/login.defs -> !r:^PASS_WARN_AGE\s*\t*\d;');
INSERT INTO sca_policy (name,file,id,description,"references",hash_file) VALUES (
'CIS benchmark for Debian/Linux','cis_debian_linux_rcl.yml','cis_debian','This document provides prescriptive guidance for establishing a secure configuration posture for Debian Linux systems running on x86 and x64 platforms. Many lists are included including filesystem types, services, clients, and network protocols. Not all items in these lists are guaranteed to exist on all distributions and additional similar items may exist which should be considered in addition to those explicitly mentioned.','https://www.cisecurity.org/cis-benchmarks/','5a71d1ba0fb6bc5a83dcb745df007ee5fa22e78fad5e1294880d868730ac62fe');
INSERT INTO sca_policy (name,file,id,description,"references",hash_file) VALUES (
'System audit for SSH hardening','system_audit_ssh.yml','system_audit_ssh','Guidance for establishing a secure configuration for SSH service vulnerabilities.','https://www.ssh.com/ssh/','bfa7204c70c5c0da65e351bdac27f56fe3074df17aea27475bee695770d2c951');
INSERT INTO sca_policy (name,file,id,description,"references",hash_file) VALUES (
'System audit for web-related vulnerabilities','system_audit_rcl.yml','system_audit','Guidance for establishing a secure configuration for web-related vulnerabilities.','(null)','f2323962b52c2cc1aa0c53a34871aabe242d571af423a33f831bd77336822f58');
INSERT INTO sca_policy (name,file,id,description,"references",hash_file) VALUES (
'System audit for password-related vulnerabilities','system_audit_pw.yml','system_audit_pw','Guidance for establishing a secure configuration for password vulnerabilities.','https://www.cisecurity.org/cis-benchmarks/','4fe1308a35e1d062718a8e39f9420a740e95a6f145030a0f7e8b169d2b94654b');
INSERT INTO sca_scan_info (id,start_scan,end_scan,policy_id,pass,"fail",invalid,total_checks,score,hash) VALUES (
175934594,1556125766,1556125766,'system_audit_ssh',3,6,0,9,33,'45efea77e3a836352e3bc30e6210daf931f4d84dfcce0b7ffa90f3838ff8cb61');
INSERT INTO sca_scan_info (id,start_scan,end_scan,policy_id,pass,"fail",invalid,total_checks,score,hash) VALUES (
339510093,1556125763,1556125763,'system_audit',0,0,16,16,0,'9a6b564cffa3a6e212a431c2e5fba5886471c896c66e818589a5a955f43d06a1');
INSERT INTO sca_scan_info (id,start_scan,end_scan,policy_id,pass,"fail",invalid,total_checks,score,hash) VALUES (
683548315,1556125770,1556125770,'system_audit_pw',1,1,2,4,50,'27cbeb402dc1b233e2e67cf663d2bf73568d92411c3f7c3cf6ff3d41801bdee0');
INSERT INTO sca_scan_info (id,start_scan,end_scan,policy_id,pass,"fail",invalid,total_checks,score,hash) VALUES (
998963039,1556125759,1556125759,'cis_debian',20,4,17,41,83,'beefc3a9cf4795ceeafb0f0fd6ae5e9d2ce9523b1c16d1afe274e3a1f4eccf90');
