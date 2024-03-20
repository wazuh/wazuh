# WPK package

In this repository, you can find the necessary tools to build a WPK package.

## Building WPK packages

Usage: ./generate_wpk_package.sh [OPTIONS]
It is required to use -k or --aws-wpk-key, --aws-wpk-cert parameters

    -t,   --target-system <target> [Required] Select target wpk to build [linux/windows/macos]
    -b,   --branch <branch>        [Required] Select Git branch or tag e.g.
    -d,   --destination <path>     [Required] Set the destination path of package.
    -pn,  --package-name <name>    [Required for windows and macos] Package name to pack on wpk.
    -o,   --output <name>          [Required] Name to the output package.
    -k,   --key-dir <path>         [Optional] Set the WPK key path to sign package.
    --aws-wpk-key                  [Optional] AWS Secrets manager Name/ARN to get WPK private key.
    --aws-wpk-cert                 [Optional] AWS secrets manager Name/ARN to get WPK certificate.
    --aws-wpk-key-region           [Optional] AWS Region where secrets are stored.
    -a,   --architecture <arch>    [Optional] Target architecture of the package [x86_64].
    -j,   --jobs <number>          [Optional] Number of parallel jobs when compiling.
    -p,   --path <path>            [Optional] Installation path for the package. By default: /var/ossec.
    -c,   --checksum               [Optional] Generate checksum on destination folder. By default: no
    --dont-build-docker            [Optional] Locally built docker image will be used instead of generating a new one. By default: yes
    --tag <name>                   [Optional] Tag to use with the docker image.
    -h,   --help                   Show this help.

Please, visit the following link for the full WPK packages building documentation: [Generate Wazuh WPK packages automatically.](https://documentation.wazuh.com/current/development/packaging/generate-wpk-package.html)

## Workflows

There are workflows to generate both the necessary Docker images and to generate the WPKs of each of the operating systems:

- packages-upload-wpk-images.yml
It is responsible for building and uploading the images necessary for the WPK script to our ghcr bucket. The image for Linux systems has the name 'linux_wpk_builder_x86_64'. For Windows and MacOS systems it is 'common_wpk_builder'. The parameters it accepts are:

  - tag:
          Tag name of the Docker image to be uploaded.
          Use 'developer' to set branch name as tag.
          Use 'auto' to set branch version as tag.
          Default is 'auto'.

- packages-build-wpk.yml
It is responsible for generating the WPKs for each system using the generate_wpk_package script. The parameters it accepts are:
  - tag:
          Tag name of the Docker image to be downloaded.
          Use 'developer' to set branch name as tag.
          Use 'auto' to set branch version as tag.
          Default is 'auto'.
  - linux_branch:
          Branch name for compiling the Linux WPK.
          If empty, it will not be generated.
  - windows_package:
          Windows WPK name in S3 or link to download.
          If empty, it will not be generated.
  - macos_package:
          MacOS WPK name in S3 or link to download.
          If empty, it will not be generated.
  - revision:
          Revision used to naming WPK package.
          Default is '0'.
  - naming_format:
          Use 'release' if WPK name should have release format.
          Use 'developer' if WPK name should have developer format.
          Default is 'developer'.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
