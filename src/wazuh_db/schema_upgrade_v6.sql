/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * October 5, 2020.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

$sql=SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'sys_osinfo' AND COLUMN_NAME = 'os_patch'
$RESULT = mysqli_query($conn,$sql);

if($RESULT){
        ALTER TABLE sys_osinfo ADD COLUMN os_patch TEXT DEFAULT NULL;
}

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 6);
