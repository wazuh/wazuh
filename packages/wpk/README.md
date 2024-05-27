# WPK package

In this repository, you can find the necessary tools to build a WPK package.

## Building WPK packages

Usage: ./generate_wpk_package.sh [OPTIONS]
It is required to use -k or --aws-wpk-key, --aws-wpk-cert parameters

    -t,   --target-system <target> [Required] Select target wpk to build [linux/windows/macos].
    -b,   --branch <branch>        [Required] Select Git branch.
    -d,   --destination <path>     [Required] Set the destination path of package.
    -pn,  --package-name <name>    [Required] Path to package file (rpm, deb, apk, msi, pkg) to pack in wpk.
    -o,   --output <name>          [Required] Name to the output package.
    -k,   --key-dir <path>         [Optional] Set the WPK key path to sign package.
    --aws-wpk-key                  [Optional] AWS Secrets manager Name/ARN to get WPK private key.
    --aws-wpk-cert                 [Optional] AWS secrets manager Name/ARN to get WPK certificate.
    --aws-wpk-key-region           [Optional] AWS Region where secrets are stored.
    -c,   --checksum               [Optional] Generate checksum on destination folder. By default: no.
    --dont-build-docker            [Optional] Locally built docker image will be used instead of generating a new one. By default: yes.
    --tag <name>                   [Optional] Tag to use with the docker image.
    -h,   --help                   Show this help.

Please, visit the following link for the full WPK packages building documentation: [Generate Wazuh WPK packages automatically.](https://documentation.wazuh.com/current/development/packaging/generate-wpk-package.html)

## Workflows

There are workflows to generate both the necessary Docker images and to generate the WPKs of each of the operating systems:

- packages-upload-wpk-images.yml
It is responsible for building and uploading the images necessary for the WPK script to our ghcr bucket. The image name for all systems it is 'common_wpk_builder'. The parameters it accepts are:
  - docker_image_tag:
          Tag name of the Docker image to be uploaded.
          Use 'developer' to set branch name as tag.
          Use 'auto' to set branch version as tag.
          If using a custom tag, use only '-', '_', '.' and alphanumeric characters.
          Default is 'auto'.
  - source_reference:
          Branch from wazuh/wazuh repository to use.

- packages-build-wpk.yml
It is responsible for generating the WPKs for each system using the generate_wpk_package script. The parameters it accepts are:
  - source_reference:
          Branch/tag of wazuh/wazuh to generate WPKs.
  - docker_image_tag:
          Specify the docker tag used to build the package.
          Use 'developer' to set branch name as tag.
          Use 'auto' to set branch version as tag.
          Default is 'auto'.
  - wpk_reference:
          Package URL with the package to be packed in the WPK.
  - is_stage:
          Should set development/production nomenclature
          True if WPK name should have production format.
          False if WPK name should have developer format.
          Default is 'false'.
  - checksum:
          Generate package checksum
          Default is 'false'.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
