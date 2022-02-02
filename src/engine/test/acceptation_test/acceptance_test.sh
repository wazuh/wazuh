# ----------------------------- Analysisd section -----------------------------

# Script useful variables

CONFIG_SRC_DIR=./analysisd/config
CONFIG_DST_DIR=/var/ossec/etc
CONFIG_BACKUP_DIR=/var/ossec/backup/etc
LOGS_DIR=/var/ossec/logs
LOGS_BACKUP_DIR=/var/ossec/backup/logs
RULES_SRC_DIR=./analysisd/ruleset/rules
DECODERS_SRC_DIR=./analysisd/ruleset/decoders
RULES_DST_DIR=/var/ossec/etc/test/rules
DECODERS_DST_DIR=/var/ossec/etc/test/decoders

# Stop Wazuh manager

systemctl stop wazuh-manager.service

# Backup Wazuh files

mkdir -p $CONFIG_BACKUP_DIR
mkdir -p $LOGS_BACKUP_DIR
mv $CONFIG_DST_DIR/ossec.conf $CONFIG_BACKUP_DIR
mv $CONFIG_DST_DIR/local_internal_options.conf $CONFIG_BACKUP_DIR
mv $LOGS_DIR/* $LOGS_BACKUP_DIR

# Copy test files

cp $CONFIG_SRC_DIR/* $CONFIG_DST_DIR
chgrp ossec $CONFIG_DST_DIR/ossec.conf
chgrp ossec $CONFIG_DST_DIR/local_internal_options.conf

mkdir -p $RULES_DST_DIR
mkdir -p $DECODERS_DST_DIR
cp $RULES_SRC_DIR/* $RULES_DST_DIR
cp $DECODERS_SRC_DIR/* $DECODERS_DST_DIR

# Start Wazuh

systemctl start wazuh-manager.service

sleep 5

# Stop Wazuh manager

systemctl stop wazuh-manager.service

# Restore Wazuh files

mv $CONFIG_BACKUP_DIR/* $CONFIG_DST_DIR
mv $LOGS_BACKUP_DIR/* $LOGS_DIR

# Remove test ruleset

rm -rf $RULES_DST_DIR
rm -rf $DECODER_DST_DIR
