/*
 * SQL Schema rbac tests
 * Copyright (C) 2015-2024, Wazuh Inc.
 * Created by Wazuh, Inc. <info@wazuh.com>.
 * This program is a free software, you can redistribute it and/or modify it under the terms of GPLv2.
 */

-- PRAGMA foreign_keys=OFF;
-- BEGIN TRANSACTION;

/* Testing */
INSERT INTO users VALUES('1000', 'test_user', 'pbkdf2:sha256:150000$QWFBPDUI$52f5eda84138dab4b5dd3bd3ddd1b34180abde1a68c1e70aa8825640c7660790', 0, '2020-04-27 09:02:52.866608');
