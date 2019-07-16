/*
 * SQL Schema SCA tests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS pm_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_first TEXT,
    date_last TEXT,
    log TEXT,
    pci_dss TEXT,
    cis TEXT
);

CREATE INDEX IF NOT EXISTS pm_event_log ON pm_event (log);
CREATE INDEX IF NOT EXISTS pm_event_date ON pm_event (date_last);

INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (1, datetime(CURRENT_TIMESTAMP, 'localtime'),
                      datetime(CURRENT_TIMESTAMP, '-10 minutes', 'localtime'), 'Starting rootcheck scan.', 'pci', 'cis');
INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (2, datetime(CURRENT_TIMESTAMP, 'localtime'),
                      datetime(CURRENT_TIMESTAMP, 'localtime'), 'Ending rootcheck scan.', 'pci', 'cis');
INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (3, datetime(CURRENT_TIMESTAMP, '-1 hour', 'localtime'),
                      datetime(CURRENT_TIMESTAMP, '-1 hour', 'localtime'),
                      'System Audit: CIS - Testing against the CIS Debian Linux Benchmark v1.0. File: /etc/debian_version. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf .',
                      '1.5', '3.4 Debian Linux');
INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (4, datetime(CURRENT_TIMESTAMP, '-2 hour', 'localtime'),
                      datetime(CURRENT_TIMESTAMP, '-2 hour', 'localtime'),
                      'System Audit: CIS - Debian Linux - 1.4 - Robust partition scheme - /tmp is not on its own partition {CIS: 1.4 Debian Linux}. File: /etc/fstab. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf .',
                      '1.5', '1.4 Debian Linux');
INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (5, datetime(CURRENT_TIMESTAMP, '-3 hour', 'localtime'),
                      datetime(CURRENT_TIMESTAMP, '-3 hour', 'localtime'),
                      'System Audit: CIS - Debian Linux - 1.4 - Robust partition scheme - /opt is not on its own partition {CIS: 1.4 Debian Linux}. File: /opt. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf .',
                      '1.5', '1.4 Debian Linux');
INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (6, datetime(CURRENT_TIMESTAMP, '-4 hour', 'localtime'),
                      datetime(CURRENT_TIMESTAMP, '-4 hour', 'localtime'),
                      'System Audit: CIS - Debian Linux - 1.4 - Robust partition scheme - /var is not on its own partition {CIS: 1.4 Debian Linux}. File: /etc/fstab. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf .',
                      '1.5', '1.4 Debian Linux');
INSERT INTO pm_event (id, date_first, date_last, log, pci_dss, cis) VALUES (7, datetime(CURRENT_TIMESTAMP, '-5 hour', 'localtime'),
                      datetime(CURRENT_TIMESTAMP, '-5 hour', 'localtime'),
                      'System Audit: CIS - Debian Linux - 2.3 - SSH Configuration - Root login allowed {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}. File: /etc/ssh/sshd_config. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf .',
                      '4.1', '2.3 Debian Linux');
