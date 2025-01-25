# README #

Wazuh to AWS Security Hub integration

-------

### AWS Policy Requirements ###

AWS Securty Hub integration requires AWS policy securityhub:BatchImportFindings



```json
   {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GrantBatchImportFindings",
            "Effect": "Allow",
            "Action": "securityhub:BatchImportFindings",
            "Resource": "*"
        }
    ]
  }
  ```
See Also: [securityhub:BatchImportFindings](https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awssecurityhub.html#awssecurityhub-BatchEnableStandards)

---

### Setup ###

In `ossec.conf` add the following:
```xml  
<ossec_config>
    <integration>
      <name>custom-security_hub</name>
      <alert_format>json</alert_format>
      <level>5</level>
      <api_key>region_name=us-west-2</api_key>
      <hook_url>hook_url</hook_url>
    </integration>
</ossec_config>
```

See Also:
[How to integrate external software using Integrator](https://wazuh.com/blog/how-to-integrate-external-software-using-integrator/)

###### api_key ######

The __api_key__ field value is used to pass AWS session access parameters

Valid Key-Value Parameters

- aws_access_key_id  -- AWS access key ID
- aws_secret_access_key  -- AWS secret access key
- aws_session_token  -- AWS temporary session token
- region_name  -- Default region when creating new connections
- profile_name  -- The name of a profile to use. If not given, then the default profile is used.

examples

  ``<api_key>region_name=us-west-2 aws_access_key_id=AKIACCCCCCRTXP5VA aws_secret_access_key=WvtR123456X123456+YYYXXXZZZj</api_key>``

###### hook_url ######

The __hook_url__ field value is used to pass application config parameters

- ignore_rules -- a comma separated list of rules
- level_threshold -- level filter threshold

example

``<hook_url>ignore_rules=20,21,22,33</hook_url>``

-------

### Who made this scripted insanity ? ###

* [Pete Shipley](https://github.com/evilpete)
