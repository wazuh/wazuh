echo "Current Status : Deploying current main target to current Wazuh Installation"
echo "----------------------------------------------------------------------------"
echo "Stopping Wazuh Manager Service..."
sudo systemctl stop wazuh-manager.service &
wait
echo "Deploy new wazuh-engine binary..."
sudo cp ./build/main /var/ossec/engine/wazuh-engine
echo "Starting Wazuh Manager Service..."
sudo systemctl start wazuh-manager.service &
wait
echo "----------------------------------------------------------------------------"
echo "Current Status : Deploy done. Checksums (MD5) available:"
sudo md5sum -b ./build/main
sudo md5sum -b /var/ossec/engine/wazuh-engine
