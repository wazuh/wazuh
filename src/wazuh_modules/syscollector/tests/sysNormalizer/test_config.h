#ifndef _TEST_CONFIG_H
#define _TEST_CONFIG_H
constexpr auto TEST_CONFIG_FILE_CONTENT
{
    R"DELIMITER({
    "exclusions": [
        {
            "target": "macos",
            "data_type": "packages",
            "field_name": "name",
            "pattern": "(Siri)"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "field_name": "name",
            "pattern": "(iCloud)"
        }
    ],
    "dictionary": [
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*Microsoft.*",
            "add_field": "vendor",
            "add_value": "Microsoft"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*VMware.*",
            "add_field": "vendor",
            "add_value": "VMware"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*Symantec.*",
            "add_field": "vendor",
            "add_value": "Symantec"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*(Quick ).*",
            "add_field": "vendor",
            "add_value": "Quick Heal"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*QuickHeal.*",
            "add_field": "vendor",
            "add_value": "QuickHeal"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "replace_field": "name",
            "replace_pattern": "(zoom.us)",
            "replace_value": "zoom"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": "Kaspersky.*",
            "replace_pattern": "( For Mac)",
            "replace_field": "name",
            "replace_value": ""
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*McAfee.*",
            "add_field": "vendor",
            "add_value": "McAfee",
            "replace_field":"name",
            "replace_pattern":"( For Mac)",
            "replace_value":""
        },
        {
            "target": "macos",
            "data_type": "packages",
            "replace_field":"name",
            "replace_pattern":"(McAfee )",
            "replace_value":""
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*TotalDefense.*",
            "add_field": "vendor",
            "add_value": "TotalDefense",
            "replace_field":"name",
            "replace_pattern":"(forMac)",
            "replace_value":""
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*TotalDefense.*",
            "replace_field":"name",
            "replace_pattern":"(Antivirus)",
            "replace_value":"Anti-Virus"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "replace_field":"name",
            "replace_pattern":"(TotalDefense)",
            "replace_value":""
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name",
            "find_pattern": ".*AVG.*",
            "add_field": "vendor",
            "add_value": "AVG",
            "replace_field":"name",
            "replace_pattern":"(Antivirus)",
            "replace_value":"Anti-Virus"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "replace_field":"name",
            "replace_pattern":"(AVG)",
            "replace_value":""
        },
        {
            "target": "macos",
            "data_type": "packages",
            "replace_field": "name",
            "replace_pattern": "(AntivirusforMac)",
            "replace_value":"Antivirus"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "someinexistentfield",
            "find_pattern": "(somepattern)"
        },
        {
            "target": "macos",
            "data_type": "packages",
            "find_field": "name"
        }
    ]
    })DELIMITER"
};

constexpr auto TEST_CONFIG_FILE_NAME {"test_config.json"};

#endif //_TEST_CONFIG_H