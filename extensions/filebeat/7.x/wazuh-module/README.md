# Wazuh Filebeat module

## Hosting

The Wazuh Filebeat module is hosted at the following URLs

- Production:
  - https://packages.wazuh.com/4.x/filebeat/
- Development:
  - https://packages-dev.wazuh.com/pre-release/filebeat/
  - https://packages-dev.wazuh.com/staging/filebeat/

The Wazuh Filebeat module must follow the following nomenclature, where revision corresponds to X.Y values

- wazuh-filebeat-{revision}.tar.gz

Currently, we host the following modules

|Module|Version|
|:--|:--|
|wazuh-filebeat-0.1.tar.gz|From 3.9.x to 4.2.x included|
|wazuh-filebeat-0.2.tar.gz|From 4.3.x to 4.6.x included|
|wazuh-filebeat-0.3.tar.gz|4.7.x|
|wazuh-filebeat-0.4.tar.gz|From 4.8.x to current|


## How-To update module tar.gz file

To add a new version of the module it is necessary to follow the following steps:

1. Clone the wazuh/wazuh repository
2. Check out the branch that adds a new version
3. Access the directory: **extensions/filebeat/7.x/wazuh-module/**
4. Create a directory called: **wazuh**

```
# mkdir wazuh
```

5. Copy the resources to the **wazuh** directory

```
# cp -r _meta wazuh/
# cp -r alerts wazuh/
# cp -r archives wazuh/
# cp -r module.yml wazuh/
```

6. Set **root user** and **root group** to all elements of the **wazuh** directory (included)

```
# chown -R root:root wazuh
```

7. Set all directories with **755** permissions

```
# chmod 755 wazuh
# chmod 755 wazuh/alerts
# chmod 755 wazuh/alerts/config
# chmod 755 wazuh/alerts/ingest
# chmod 755 wazuh/archives
# chmod 755 wazuh/archives/config
# chmod 755 wazuh/archives/ingest
```

8. Set all yml/json files with **644** permissions

```
# chmod 644 wazuh/module.yml
# chmod 644 wazuh/_meta/config.yml
# chmod 644 wazuh/_meta/docs.asciidoc
# chmod 644 wazuh/_meta/fields.yml
# chmod 644 wazuh/alerts/manifest.yml
# chmod 644 wazuh/alerts/config/alerts.yml
# chmod 644 wazuh/alerts/ingest/pipeline.json
# chmod 644 wazuh/archives/manifest.yml
# chmod 644 wazuh/archives/config/archives.yml
# chmod 644 wazuh/archives/ingest/pipeline.json
```

9. Create **tar.gz** file

```
# tar -czvf wazuh-filebeat-0.4.tar.gz wazuh
```

10. Check the user, group, and permissions of the created file

```
# tree -pug wazuh
[drwxr-xr-x root     root    ]  wazuh
├── [drwxr-xr-x root     root    ]  alerts
│   ├── [drwxr-xr-x root     root    ]  config
│   │   └── [-rw-r--r-- root     root    ]  alerts.yml
│   ├── [drwxr-xr-x root     root    ]  ingest
│   │   └── [-rw-r--r-- root     root    ]  pipeline.json
│   └── [-rw-r--r-- root     root    ]  manifest.yml
├── [drwxr-xr-x root     root    ]  archives
│   ├── [drwxr-xr-x root     root    ]  config
│   │   └── [-rw-r--r-- root     root    ]  archives.yml
│   ├── [drwxr-xr-x root     root    ]  ingest
│   │   └── [-rw-r--r-- root     root    ]  pipeline.json
│   └── [-rw-r--r-- root     root    ]  manifest.yml
├── [drwxr-xr-x root     root    ]  _meta
│   ├── [-rw-r--r-- root     root    ]  config.yml
│   ├── [-rw-r--r-- root     root    ]  docs.asciidoc
│   └── [-rw-r--r-- root     root    ]  fields.yml
└── [-rw-r--r-- root     root    ]  module.yml
```

11. Upload file to development bucket
