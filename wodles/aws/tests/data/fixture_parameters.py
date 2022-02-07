# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

AWS_BASE_PARAMS = [
    [
        {"access_key": "AAAAAAAAAAAAAAAAAAAA"},
        {"secret_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        {"iam_role_arn": ""},
    ],
]


AWS_INTEGRATION_PARAMS = [
    AWS_BASE_PARAMS[0] + [
        {"db_name": ""},
        {"aws_profile": ""}
    ],
]


AWS_BUCKET_PARAMS = [
    AWS_BASE_PARAMS[0] + [
        {"access_key": "AAAAAAAAAAAAAAAAAAAA"},
        {"secret_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        {"iam_role_arn": ""},
        {"reparse": False},
        {"profile": ""},
        {"bucket": "test_bucket"},
        {"only_logs_after": ""},
        {"skip_on_error": False},
        {"account_alias": ""},
        {"prefix": ""},
        {"suffix": ""},
        {"delete_file": False},
        {"aws_organization_id": ""},
        {"region": ""},
        {"discard_field": ""},
        {"discard_regex": ""},
        {"sts_endpoint": ""},
        {"service_endpoint": ""}
    ],
]
