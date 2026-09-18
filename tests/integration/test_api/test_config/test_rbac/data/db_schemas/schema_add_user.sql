/*
 * SQL Schema rbac tests
 * Copyright (C) 2015-2024, Wazuh Inc.
 * Created by Wazuh, Inc. <info@wazuh.com>.
 * This program is a free software, you can redistribute it and/or modify it under the terms of GPLv2.
 */

-- PRAGMA foreign_keys=OFF;
-- BEGIN TRANSACTION;

/* Testing */
INSERT INTO users VALUES('1000', 'test_user', 'pbkdf2:sha256:150000$ruxTeTrgoeyS6zlV$fb58ed2d737eea65e0de4214ce4b4b8f4cf9b04f660f08c67e1934551322fad8', 0, '2020-04-27 09:02:52.866608');
