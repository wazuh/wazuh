/*
 * SQL Schema AWS tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 15, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE 'config' (
    bucket_path 'text' NOT NULL,
    aws_account_id 'text' NOT NULL,
    aws_region 'text' NOT NULL,
    log_key 'text' NOT NULL,
    processed_date 'text' NOT NULL,
    created_date 'integer' NOT NULL,
    PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020505Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020515Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020510Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020520Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020525Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020530Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020500Z.json.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'config' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'config/AWSLogs/123456789/Config/us-east-1/2019/4/15/ConfigHistory/123456789_Config_us-east-1_ConfigHistory_20190415T020535Z.json.gz',
    DATETIME('now'),
    '20230101');
