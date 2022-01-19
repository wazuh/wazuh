/*
 * SQL Schema syscheck tests
 * Copyright (C) 2015, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE pm_event (id INTEGER PRIMARY KEY AUTOINCREMENT, date_first TEXT, date_last TEXT, log TEXT, pci_dss TEXT, cis TEXT);

INSERT INTO pm_event(id, date_first, date_last, log) VALUES (1, '2019-05-29 12:20:11', '2019-05-29 12:21:02', 'Starting syscheck scan.');
INSERT INTO pm_event(id, date_first, date_last, log) VALUES (2, '2019-05-29 12:20:26', '2019-05-29 12:21:16', 'Ending syscheck scan.');
INSERT INTO pm_event(id, date_first, date_last, log) VALUES (3, '2019-05-29 12:21:26', '2019-05-29 12:21:26', 'Starting rootcheck scan.');
INSERT INTO pm_event(id, date_first, date_last, log) VALUES (4, '2019-05-29 12:21:35', '2019-05-29 12:21:35', 'Ending rootcheck scan.');

CREATE TABLE scan_info (module TEXT PRIMARY KEY, first_start INTEGER, first_end INTEGER, start_scan INTEGER, end_scan INTEGER, fim_first_check INTEGER, fim_second_check INTEGER, fim_third_check INTEGER);
INSERT INTO scan_info(module, first_start, first_end, start_scan, end_scan, fim_first_check, fim_second_check, fim_third_check) VALUES ('fim', 1559134512, 1559134532, 1559134512, 1559134532, 1559134512, 1559132445, 1559132394);

CREATE TABLE fim_entry (full_path TEXT NOT NULL PRIMARY KEY, file TEXT, type TEXT NOT NULL CHECK (type IN ('file', 'registry_key', 'registry_value')), date INTEGER NOT NULL DEFAULT (strftime('%s', 'now')), changes INTEGER NOT NULL DEFAULT 1, arch TEXT CHECK (arch IN (NULL, '[x64]', '[x32]')), value_name TEXT, value_type TEXT, size INTEGER, perm TEXT, uid TEXT, gid TEXT, md5 TEXT, sha1 TEXT, uname TEXT, gname TEXT, mtime INTEGER, inode INTEGER, sha256 TEXT, attributes INTEGER DEFAULT 0, symbolic_path TEXT, checksum TEXT);

/* INSERT TEST VALUES TO FIM_ENTRY:
 * value_name is NULL when type is 'file' or 'registry_key'
 * value_type is NULL when type is 'file' or 'registry_key' or the value is invalid
 * arch is NULL when type is 'file'
 */

-- Files
INSERT INTO "fim_entry" VALUES('/sbin/runit','/sbin/runit','file',1578640725,1,NULL,NULL,NULL,18840,'100755','0','0','c80c63cc6759381819691a987f1d7683','a6cca2f27bc8be45d55247cd06d551d15091d226','root','root',1420542776,15470536,'47d90904042bf4557089f08cc287ff5af4048beaec56f37f31ade5d5c3489d25',0,NULL,NULL);
INSERT INTO "fim_entry" VALUES('/usr/bin/getconf','/usr/bin/getconf','file',1578640719,1,NULL,NULL,NULL,22944,'100755','0','0','7db6b10d542510318ba9a94e369fde26','a3901716d1a678e21398dcd0403a3b36bc1d07cb','root','root',1549397572,16393804,'72f5c4543d4bbe82c80c5d7d4e9c232d4414760aba7c3fc629eb3f91c25599bd',NULL,NULL,NULL);
INSERT INTO "fim_entry" VALUES('/usr/bin/frm.mailutils','/usr/bin/frm.mailutils','file',1578640720,1,NULL,NULL,NULL,23296,'100755','0','0','294a5e70b07ba6d0e8a8b6ad59622e94','ae7add46c901ce949d1e80defc5136e6b5d3a644','root','root',1459864318,16393800,'962d7e4d40c5076dc1e2ab2d1c3da539017e857d121cc6a4e6a105044bd10618',0,NULL,NULL);
INSERT INTO "fim_entry" VALUES('/usr/bin/apt-key','/usr/bin/apt-key','file',1578640718,1,NULL,NULL,NULL,20599,'100755','0','0','50141b833e183a0ea826ed500e25b8f1','f5792d780476ca9033c230937017532cfd1a4461','root','root',1558469542,16393728,'760885b6142d0c6e52df29cffa9026d1cfbc928b9d123979951e3ba547b5937b',0,NULL,NULL);

-- Registries
INSERT INTO "fim_entry" VALUES('registry_key_1','registry_key_1','registry_key',1578640718,1,'[x64]',NULL,NULL,4096,'perm','uid','gid','hash_md5','hash_sha1','root','root',12345678,1024,'hash_sha256',0,NULL,NULL);
INSERT INTO "fim_entry" VALUES('registry_value_1','registry_value_1','registry_value',1578640718,1,'[x32]','value_name','value_type',4096,'perm','uid','gid','hash_md5','hash_sha1','root','root',12345678,1024,'hash_sha256',NULL,NULL,NULL);
INSERT INTO "fim_entry" VALUES('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime','HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime','registry_key',1578640718,1,'[x32]','value_name','value_type',4096,'perm','uid','gid','hash_md5','hash_sha1','root','root',12345678,1024,'hash_sha256',NULL,NULL,NULL);
