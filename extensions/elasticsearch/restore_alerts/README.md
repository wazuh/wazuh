# Restore Wazuh alerts from Wazuh 2.x

After upgrading Wazuh from 2.x to 3.x, your alerts will not be lost, but you cannot visualize your old alerts in Kibana due to a change in the Wazuh alerts' template. So, in order to work again with your old alerts and the new ones, it is necessary to reindex your alerts in Elasticsearch, applying the new mapping.

To do so, you must download the `restore_alerts.sh` script from https://github.com/wazuh/wazuh/tree/master/extensions/elasticsearch/restore_alerts.sh and a Logstash's configuration file called `restore_alerts.conf` from https://github.com/wazuh/wazuh/tree/master/extensions/elasticsearch/restore_alerts.conf.

```shellsession
$ curl -so restore_alerts.sh https://raw.githubusercontent.com/wazuh/wazuh/masterextensions/elasticsearch/restore_alerts.sh
$ curl -so restore_alerts.conf https://raw.githubusercontent.com/wazuh/wazuh/masterextensions/elasticsearch/restore_alerts.conf
```

Once the script and the configuration file are downloaded, you can restore your Wazuh's alerts in two different ways: **restoring them from Elasticsearch** and index them in Elasticsearch or **restoring from your Wazuh's manager** and index them in Elasticsearch.

## Restore the alerts

Before you start restoring your alerts, you must stop Logstash.

```shellsession
# systemctl stop logstash
``` 

Once you stopped Logstash, you can run the `restore_alerts.sh` script as **superuser** to reindex your old Wazuh alerts.

```shellsession
# ./restore_alerts.sh 
```

> Note: the script needs Logstash to be installed in the same machine, so if the script can't find Logstash, the script will install it in order to do the job. After the reindex has finished, you can uninstall Logstash.

After that, the script will ask you for information to fill in some needed parameters:

* `reindex_type`: Store what kind of reindex do you want. It could be:
  - `ELS2ELS`: from Elasticsearch to Elasticsearch.
  - `WM2ELS`: from Wazuh's manager to Elasticsearch.

* `elastic_ip`: Is the Elasticsearch IP address. By default, is `localhost`.
* `dateFrom`: starting date as YYYY-MM-DD (2017-12-01).
* `dateTo`: end date as YYYY-MM-DD (2017-12-11).

> Note: if you want to reindex only a day, set `dateFrom` and `dateTo` to the same date.

Also, you can execute the script adding the values for the parameters as arguments:

```shellsession
# ./restore_alerts.sh date_from(yyyy-mm-dd) date_to(yyyy-mm-dd) elasticsearch_ip ELS2ELS|WM2ELS
```

Once the script has finished, you can start Logstash again:

```shellsession
# systemctl start logstash
```
## Check that the reindex has worked

Once the reindex of your alerts has finished, you can check that it works by asking Elasticsearch about the _indices_.

```shellsession
$ curl localhost:9200/_cat/indices?v
```

If everything worked well, it must appear something like this in the output:

```shellsession
$ curl -XGET localhost:9200/_cat/indices?v
health status index                           uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green open   wazuh-alerts-3.x-2017.12.12     vQ4YXsTuQLSDMnLk_Lp2Kw   5   1         58            0    115.1kb        115.1kb
green open   .kibana-6                       0jtvjQ4ERLmkKbCJ7Pl4Ww   1   1        241          110    226.5kb        226.5kb
green open   .wazuh-version                  AqVHhREjSgCpx07LJ45Dkg   5   1          1            0      7.1kb          7.1kb
green open   wazuh-alerts-2017.12.12         T3SZQRHGQEOBbVi79nDmhg   5   1         58            0    239.2kb        239.2kb
green open   .wazuh                          GV7tVKXsSb-BocyjxC07Iw   5   1          0            0      1.2kb          1.2kb
```
