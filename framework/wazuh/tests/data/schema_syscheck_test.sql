/*
 * SQL Schema syscheck tests
 * Copyright (C) 2015-2019, Wazuh Inc.
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
