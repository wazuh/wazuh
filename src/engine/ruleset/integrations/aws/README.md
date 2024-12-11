# AWS Base Integration


|   |   |
|---|---|
| event.module | aws |
| event.dataset | aws-cloudtrail, aws-elb, aws-s3access |
This integration processes events from AWS

## Compatibility

None

## Configuration

*S3*:
 Add to the ossec.conf file in the monitored agent the following configuration block to enable the integration with Amazon S3:
 https://documentation.wazuh.com/current/amazon/services/supported-services/server-access.html#amazon-server-access

 ```xml
 <wodle name="aws-s3">
   <disabled>no</disabled>
   <interval>10m</interval>
   <run_on_start>yes</run_on_start>
   <skip_on_error>yes</skip_on_error>
   <bucket type="server_access">
     <aws_profile>default</aws_profile>
   </bucket>
 </wodle>
 ```
*cloudtrail*:
 Add to the ossec.conf file in the monitored agent the following configuration block to enable the integration with CloudTrail:

 https://documentation.wazuh.com/current/amazon/services/supported-services/cloudtrail.html#amazon-cloudtrail

 ```xml
 <wodle name="aws-s3">
   <disabled>no</disabled>
   <interval>10m</interval>
   <run_on_start>yes</run_on_start>
   <skip_on_error>yes</skip_on_error>
   <bucket type="cloudtrail">
     <name>wazuh-cloudtrail</name>
     <aws_profile>default</aws_profile>
   </bucket>
 </wodle>
 ```

*ELB*:
 This integration uses the logcollector source localfile to ingest the logs from the agent.
 Add to the ossec.conf file in the monitored agent the following block:
 ALB https://documentation.wazuh.com/current/amazon/services/supported-services/elastic-load-balancing/alb.html#amazon-alb
 CLB https://documentation.wazuh.com/current/amazon/services/supported-services/elastic-load-balancing/clb.html#amazon-clb
 NLB https://documentation.wazuh.com/current/amazon/services/supported-services/elastic-load-balancing/nlb.html#amazon-nlb

 ```xml
 <wodle name="aws-s3">
   <disabled>no</disabled>
   <interval>10m</interval>
   <run_on_start>yes</run_on_start>
   <skip_on_error>yes</skip_on_error>
   <bucket type="alb">
     <name>wazuh-aws-wodle</name>
     <path>ALB</path>
     <aws_profile>default</aws_profile>
   </bucket>
 </wodle>

 <wodle name="aws-s3">
   <disabled>no</disabled>
   <interval>10m</interval>
   <run_on_start>yes</run_on_start>
   <skip_on_error>yes</skip_on_error>
   <bucket type="clb">
     <name>wazuh-aws-wodle</name>
     <path>CLB</path>
     <aws_profile>default</aws_profile>
   </bucket>
 </wodle>

 <wodle name="aws-s3">
   <disabled>no</disabled>
   <interval>10m</interval>
   <run_on_start>yes</run_on_start>
   <skip_on_error>yes</skip_on_error>
   <bucket type="nlb">
     <name>wazuh-aws-wodle</name>
     <path>NLB</path>
     <aws_profile>default</aws_profile>
   </bucket>
 </wodle>

 ```


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/aws-s3/0 | Decoder for Wazuh wodle of AWS S3 server access logs |
| decoder/aws-elb/0 | Decoder for Wazuh wodle of AWS ELB (ALB, CLB, NLB) logs |
| decoder/aws-json/0 | Partial JSON decoder for AWS wodle events |
| decoder/aws-cloudtrail/0 | Decoder for Wazuh wodle of AWS CloudTrail Logs |
## Rules

| Name | Description |
|---|---|
## Outputs

| Name | Description |
|---|---|
## Filters

| Name | Description |
|---|---|
## Changelog

| Version | Description | Details |
|---|---|---|
| 0.0.2-dev | Created integration for Amazon Wodle | [#17648](https://github.com/wazuh/wazuh/pull/17648) |
| 0.0.1-dev | Created base integration for AWS | [#16766](#) |
