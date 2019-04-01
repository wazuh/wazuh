/*
 * SQL Schema AWS tests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 1, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

 CREATE table 'metadata' (
    key 'text' NOT NULL,
    value 'text' NOT NULL,
    PRIMARY KEY (key, value));

INSERT INTO metadata (key, value) VALUES (
    'version', '3.8');

CREATE TABLE custom (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, log_key));
CREATE TABLE cloudtrail (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                aws_region 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));
CREATE TABLE config (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                aws_region 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));
CREATE TABLE vpcflow (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                aws_region 'text' NOT NULL,
                                flow_log_id 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, aws_region, flow_log_id, log_key));
CREATE TABLE guardduty (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, log_key));

