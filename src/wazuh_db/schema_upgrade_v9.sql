/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * May 21, 2021
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

INSERT INTO sync_info (component) VALUES ('fim_registry_key');
INSERT INTO sync_info (component) VALUES ('fim_registry_value');
