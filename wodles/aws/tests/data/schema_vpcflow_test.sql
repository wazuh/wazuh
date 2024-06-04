/*
 * SQL Schema AWS tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 15, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE 'vpcflow' (
    bucket_path 'text' NOT NULL,
    aws_account_id 'text' NOT NULL,
    aws_region 'text' NOT NULL,
    flow_log_id 'text' NOT NULL,
    log_key 'text' NOT NULL,
    processed_date 'text' NOT NULL,
    created_date 'integer' NOT NULL,
    PRIMARY KEY (bucket_path, aws_account_id, aws_region, flow_log_id, log_key));

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T0945Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T0950Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T0955Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T0940Z_c23ab7.log.gz',
    DATETIME('now'),
    '');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T1000Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T115Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T1005Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');

INSERT INTO 'vpcflow' (
    bucket_path,
    aws_account_id,
    aws_region,
    flow_log_id,
    log_key,
    processed_date,
    created_date) VALUES (
    'test-bucket/',
    '123456789123',
    'us-east-1',
    'fl-1234',
    'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_fl-1234_20190415T110Z_c23ab7.log.gz',
    DATETIME('now'),
    '20230101');
