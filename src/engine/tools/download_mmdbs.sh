#!/bin/bash
#
# Download MaxMind databases
#
# Usage: download_mmdbs.sh <licence_key>
#
# This script will download the MaxMind databases GeoLite2-City and GeoLite2-ASN
# and place them in /var/ossec/etc. The licence key is required to download the databases,
# you can get one for free at https://www.maxmind.com/en/geolite2/signup

GEOIP_TMP_FILE='/tmp/geoip.tar.gz'
BASE_URL='https://download.maxmind.com/app/geoip_download'

# Download and extract
download_and_extract() {
    local edition=$1
    local type=$2
    local url="${BASE_URL}?edition_id=${edition}&license_key=${GEOIP_LICENCE_KEY}&suffix=tar.gz"

    curl -sS $url >$GEOIP_TMP_FILE
    if [ $? -ne 0 ]; then
        echo "Error to download ${edition}"
        exit 1
    fi

    tar -xzf $GEOIP_TMP_FILE --wildcards "*/${edition}.mmdb" --strip=1
    if [ $? -ne 0 ]; then
        echo "Error to extract ${edition}"
        exit 1
    fi

    # Move to the correct location
    mv ${edition}.mmdb /var/ossec/etc
    chown wazuh:wazuh /var/ossec/etc/${edition}.mmdb

    # Enable the database
    echo "Enabling ${edition} database"
    $ENGINE_DIR/wazuh-engine geo add /var/ossec/etc/${edition}.mmdb $type

    rm $GEOIP_TMP_FILE
}

# Trap
trap 'rm -f $GEOIP_TMP_FILE' EXIT

# Recieve the licence key from arguments
GEOIP_LICENCE_KEY=$1

# Download all if keys are set
if [ -n "$GEOIP_LICENCE_KEY" ]; then
    for edition in GeoLite2-City GeoLite2-ASN; do
        if [ "$edition" == "GeoLite2-City" ]; then
            type="city"
        elif [ "$edition" == "GeoLite2-ASN" ]; then
            type="asn"
        fi
        download_and_extract $edition $type
    done
else
    echo "Usage: download_mmdbs.sh <licence_key>"
    exit 1
fi
