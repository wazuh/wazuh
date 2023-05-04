# Amazon ELB Integration


|   |   |
|---|---|
| event.module | aws |

This integration processes logs from Amazon Elastic Load Balancing service.

## Compatibility

None

## Configuration

This integration uses the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following block:
```html
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[AWS ELB log path]</location>
  <log_format>json</log_format>
  <label key="event.module">aws</label>
  <label key="event.dataset">aws.elb</label>
</localfile>
```


## Schema

| Field | Description | Type |
|---|---|---|
| aws.elb.name | The name of the load balancer. | keyword |
| aws.elb.backend.ip | The IP address of the backend processing this connection. | keyword |
| aws.elb.backend.port | The port in the backend processing this connection. | keyword |
| aws.elb.request_processing_time.sec | The total time in seconds since the connection or request is received until it is sent to a registered backend. | float |
| aws.elb.backend_processing_time.sec | The total time in seconds since the connection is sent to the backend till the backend starts responding. | float |
| aws.elb.response_processing_time.sec | The total time in seconds since the response is received from the backend till it is sent to the client. | float |
| aws.elb.backend.http.response.status_code | The status code from the backend (status code sent to the client from ELB is stored in http.response.status_code) | long |
| aws.elb.ssl_cipher | The SSL cipher used in TLS/SSL connections. | keyword |
| aws.elb.ssl_protocol | The SSL protocol used in TLS/SSL connections. | keyword |
| aws.elb.type | The type of the load balancer for v2 Load Balancers. | keyword |
| aws.elb.target_group.arn | The ARN of the target group handling the request. | keyword |
| aws.elb.trace_id | The contents of the X-Amzn-Trace-Id header. | keyword |
| aws.elb.chosen_cert.arn | The ARN of the chosen certificate presented to the client in TLS/SSL connections. | keyword |
| aws.elb.matched_rule_priority | The priority value of the rule that matched the request, if a rule matched. | keyword |
| aws.elb.redirect_url | The URL used if a redirection action was executed. | keyword |
| aws.elb.error.reason | The error reason if the executed action failed. | keyword |
| aws.elb.listener | The ELB listener that received the connection. | keyword |
| aws.elb.action_executed | The action executed when processing the request (forward, fixed-response, authenticate...). It can contain several values. | keyword |
| aws.elb.chosen_cert.serial | he serial number of the chosen certificate presented to the client in TLS/SSL connections. | keyword |
| aws.elb.classification | The classification for desync mitigation. | keyword |
| aws.elb.classification_reason | The classification reason code. | keyword |
| aws.elb.connection_time.ms | The total time of the connection in milliseconds, since it is opened till it is closed. | long |
| aws.elb.incoming_tls_alert | The integer value of TLS alerts received by the load balancer from the client, if present. | keyword |
| aws.elb.protocol | The protocol of the load balancer (http or tcp). | keyword |
| aws.elb.target_port | List of IP addresses and ports for the targets that processed this request. | keyword |
| aws.elb.target_status_code | List of status codes from the responses of the targets. | keyword |
| aws.elb.tls_handshake_time.ms | The total time for the TLS handshake to complete in milliseconds once the connection has been established. | long |
## Decoders

| Name | Description |
|---|---|
| decoder/aws-elb/0 | Decoder for Amazon ELB logs |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Amazon Elastic Load Balancing | [#16766](#) |
