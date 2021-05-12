/*
 * SQL Schema AWS tests
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 1, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

 CREATE TABLE 'metadata' (
    key 'text' NOT NULL,
    value 'text' NOT NULL,
    PRIMARY KEY (key, value));

INSERT INTO metadata (key, value) VALUES (
    'version', '3.8');
