# Settings

The **Inventory Harvester** does not provide any dedicated configuration options to change its behavior, although the way it operates relies on the settings from the indexer connector and the modules from which it processes events.

## Connection to Wazuh Indexer

As mentioned above, the Inventory Harvester module needs to connect to the Wazuh Indexer through the Indexer Connector module.

- Default Indexer Connector configuration block
```xml
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://0.0.0.0:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/filebeat/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/filebeat.pem</certificate>
      <key>/etc/filebeat/certs/filebeat-key.pem</key>
    </ssl>
  </indexer>
```

It is important to verify the status of the Wazuh Indexer **GET /_cluster/health**

- e.g. Response
```json
{
  "cluster_name": "wazuh-cluster",
  "status": "green",
  "timed_out": false,
  "number_of_nodes": 1,
  "number_of_data_nodes": 1,
  "discovered_master": true,
  "discovered_cluster_manager": true,
  "active_primary_shards": 15,
  "active_shards": 15,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 0,
  "delayed_unassigned_shards": 0,
  "number_of_pending_tasks": 0,
  "number_of_in_flight_fetch": 0,
  "task_max_waiting_in_queue_millis": 0,
  "active_shards_percent_as_number": 100
}
```

## Data to index

Once again, the **Inventory Harvester** does not have the ability to choose the information that will be indexed. All events received from agents are processed and indexed. To prevent specific information from being indexed, the corresponding feature must be disabled on the agent side, just as it works with database information.

- Disabling specific Inventory providers

Turn off specific providers individually
```xml
<wodle name="syscollector">
<disabled>no</disabled>
<interval>1h</interval>
<scan_on_start>yes</scan_on_start>
<hardware>yes</hardware>
<os>yes</os>
<network>yes</network>
<packages>yes</packages>
<ports all="no">yes</ports>
<processes>yes</processes>

<!-- Database synchronization settings -->
<synchronization>
    <max_eps>10</max_eps>
</synchronization>
</wodle>
```
**`<hotfixes>` provider is hidden by default**

- Disabling FIM components

To disable files monitoring the following configuration must not exist
```xml
<directories><FILEPATH_OF_MONITORED_FILE></directories>
```

To disabled registries monitoring the following configuration must not exist (Only Windows)
```xml
<windows_registry><REGISTRYPATH_OF_MONITORED_REGISTRY></windows_registry>
```
