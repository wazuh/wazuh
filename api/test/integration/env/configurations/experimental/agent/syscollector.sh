sed -i '/name="syscollector"/,/\/wodle/s/<interval>.*/<interval>10s<\/interval>/' /var/ossec/etc/ossec.conf
sed -i '/name="syscollector"/,/\/wodle/s/<scan_on_start>.*/<scan_on_start>no<\/scan_on_start>/' /var/ossec/etc/ossec.conf
