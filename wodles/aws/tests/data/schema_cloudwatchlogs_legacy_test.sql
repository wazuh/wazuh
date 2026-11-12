/*
 * SQL Schema AWS tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 15, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE 'cloudwatch_logs' (
    aws_region 'text' NOT NULL,
    aws_log_group 'text' NOT NULL,
    aws_log_stream 'text' NOT NULL,
    next_token 'text',
    start_time 'integer',
    end_time 'integer',
    PRIMARY KEY (aws_region, aws_log_group, aws_log_stream));

INSERT INTO 'cloudwatch_logs' (
    aws_region,
    aws_log_group,
    aws_log_stream,
    next_token,
    start_time,
    end_time) VALUES (
    'us-east-1',
    'test_log_group',
    'test_stream',
    'f/12345678123456781234567812345678123456781234567812345678/s',
    1640996200000,
    1659355591835
    );
