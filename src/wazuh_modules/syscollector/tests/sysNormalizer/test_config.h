#ifndef _TEST_CONFIG_H
#define _TEST_CONFIG_H
constexpr auto TEST_CONFIG_FILE_CONTENT
{
    R"({
        "exclusions": [
            {
                "target": "macos",
                "data_type": "packages",
                "field_name": "name",
                "pattern": ".*Siri.*"
            },
            {
                "target": "macos",
                "data_type": "packages",
                "field_name": "name",
                "pattern": ".*iTunes.*"
            }
        ],
        "dictionary": [
            {
                "target": "macos",
                "data_type": "packages",
                "src_field_name": "name",
                "pattern": "( For Mac|forMac).*",
                "action": "replace",
                "value": "",
                "dest_field_name": ""
            },
            {
                "target": "macos",
                "data_type": "packages",
                "src_field_name": "name",
                "pattern": "(Antivirus).*",
                "action": "replace",
                "value": "Anti-Virus",
                "dest_field_name": ""
            },
            {
                "target": "macos",
                "data_type": "packages",
                "src_field_name": "name",
                "pattern": "(Kaspersky).*",
                "action" : "add",
                "value":"Kaspersky",
                "dest_field_name": "vendor"
            }
        ]
    })"
};

constexpr auto TEST_CONFIG_FILE_NAME{"test_config.json"};

#endif //_TEST_CONFIG_H