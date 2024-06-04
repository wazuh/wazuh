/*
 * SQL Schema AWS tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 1, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE 'cloudtrail' (
    bucket_path 'text' NOT NULL,
    aws_account_id 'text' NOT NULL,
    aws_region 'text' NOT NULL,
    log_key 'text' NOT NULL,
    processed_date 'text' NOT NULL,
    created_date 'integer' NOT NULL,
    PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0030Z_aaaa.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0000Z_aaab.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0000Z_aaaa.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0005Z_aaaa.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0020Z_aaaa.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0010Z_aaaa.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T0025Z_aaaa.json.gz',
    DATETIME('now'),
    '');

INSERT INTO 'cloudtrail' (
    bucket_path,
    aws_account_id,
    aws_region,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'AWSLogs/123456789/CloudTrail/us-east-1/2019/04/01/123456789_CloudTrail-us-east-1_20190401T00015Z_aaaa.json.gz',
    DATETIME('now'),
    '');
