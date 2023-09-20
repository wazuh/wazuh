/*
 * SQL Schema AWS tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 15, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE 'aws_services' (
    service_name 'text' NOT NULL,
    aws_account_id 'text' NOT NULL,
    aws_region 'text' NOT NULL,
    scan_date 'text' NOT NULL,
    PRIMARY KEY (service_name, aws_account_id, aws_region, scan_date));

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-01-26 00:00:00.0');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-02-06 18:58:32.504472');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-03-06 18:58:32.504472');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-04-06 18:58:32.504472');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-05-06 18:58:32.504472');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-06-06 18:58:32.504472');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-07-07 18:58:32.504472');

INSERT INTO 'aws_services' (
    service_name,
    aws_account_id,
    aws_region,
    scan_date) VALUES (
    'inspector',
    '123456789123',
    'us-east-1',
    '2022-08-26 00:00:00.0');
