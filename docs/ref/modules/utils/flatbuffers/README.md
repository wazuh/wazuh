# Flatbuffers

Various modules, such as the Vulnerability Detector, use FlatBuffers. FlatBuffers is a library that enables high-performance data serialization and deserialization without the need of unpacking or parsing, providing direct access to the required information.

Although the synchronization events received by Remoted are in JSON format, they require to augmentate the event data with additional **agent context** within this module. As a result, deserializing and re-serializing the data becomes unavoidable. Given this requirement, the augmented synchronization events are converted to FlatBuffers.

Another key use of FlatBuffers in the Vulnerability Detector module is for processing vulnerability feeds, specifically those following the CVE5 schema. In this case, FlatBuffers are used to avoid the deserialization overhead during scanning.

Due to the nature of FlatBuffers, the deserialization cost is significantly lower compared to JSON, regardless of the JSON library used. This makes FlatBuffers particularly well-suited for scanning operations, where deserialization performance is a critical factor.

## Flatbuffer schemas

### Common AgentInfo table
- Common agent information for FIM Delta, Inventory Delta and Synchronization events.

| Table         | Field          | Type       | Description |
|---------------|----------------|------------|-------------|
| **AgentInfo** | agent_id       | string     | Unique identifier of the agent, e.g., "001". |
|               | agent_ip       | string     | IP address of the agent. |
|               | agent_name     | string     | Name assigned to the agent. |
|               | agent_version  | string     | Version of the agent software, e.g., "v4.10.2". |
