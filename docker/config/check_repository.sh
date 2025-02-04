## variables
APT_KEY=https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH
GPG_SIGN="gpgcheck=1\ngpgkey=${APT_KEY}]"
REPOSITORY="[wazuh]\n${GPG_SIGN}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/pre-release/yum/\nprotect=1"
WAZUH_TAG=$(curl --silent https://api.github.com/repos/wazuh/wazuh/git/refs/tags | grep '["]ref["]:' | sed -E 's/.*\"([^\"]+)\".*/\1/'  | cut -c 11- | grep ^v${WAZUH_VERSION}$)

## check tag to use the correct repository
if [[ -n "${WAZUH_TAG}" ]]; then
  APT_KEY=https://packages.wazuh.com/key/GPG-KEY-WAZUH
  GPG_SIGN="gpgcheck=1\ngpgkey=${APT_KEY}]"
  REPOSITORY="[wazuh]\n${GPG_SIGN}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1"
fi

rpm --import "${APT_KEY}"
echo -e "${REPOSITORY}" | tee /etc/yum.repos.d/wazuh.repo
