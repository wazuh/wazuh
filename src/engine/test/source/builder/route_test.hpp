#include <route.hpp>

namespace testRoutes
{
const json::Json existQNQ = json::Json(R"(
        {
            "name": "Exist wazuh.queue and wazuh.no_queue",
            "check": [
                {
                    "wazuh.queue": "+ef_exists"
                },
                {
                    "wazuh.no_queue": "+ef_exists"
                }
            ],
            "target": "existQNQ"
        }
    )");

const json::Json queue49or50 = json::Json(R"~(
        {
            "name": "Exist wazuh.queue and is 49 or 50",
            "check": "+ef_exists/wazuh.queue AND (+i_eq/wazuh.queue/49 OR +i_eq/wazuh.queue/50)",
            "target": "queue49or50"
        }
    )~");


const json::Json allowAll = json::Json(R"(
        {
            "name": "Allow all",
            "target": "allowAll"
        }
    )");

const std::vector<std::string> sampleEvents4550Str = {
    R"(1:[123] (hostname_test_bench) any->/var/some_location:::1 - - [26/Dec/2016:16:16:29 +0200] "GET /favicon.ico HTTP/1.1" 404 209)",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:192.168.33.1 - - [26/Dec/2016:16:22:00 +0000] "GET / HTTP/1.1" 200 484 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36")",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:127.0.0.1 - - [02/Feb/2019:05:38:45 +0100] "-" 408 152 "-" "-")",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:monitoring-server - - [29/May/2017:19:02:48 +0000] "GET /status HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2")",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:[Mon Dec 26 16:17:53 2016] [notice] Apache/2.2.22 (Ubuntu) configured -- resuming normal operations)",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 21 21:56:12 localhost sshd[3430]: Invalid user test from 10.0.2.2)",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:{"aws":{"source":"cloudtrail","eventVersion":"some-event-version","eventID":"some-event-id","eventTime":"2018-08-24T17:20:08Z","log_file":"some-log-file.json.gz","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/console/home","MobileVersion":"No"},"eventType":"AwsConsoleSignIn","errorMessage":"Failed authentication","responseElements":{"ConsoleLogin":"Failure"},"awsRegion":"us-east-1","eventName":"ConsoleLogin","userIdentity":{"userName":"some-user-name","accessKeyId":"some-access-key","type":"IAMUser","principalId":"some-principal-id","accountId":"0303456"},"eventSource":"signin.amazonaws.com","userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0","sourceIPAddress":"7.222.123.101","recipientAccountId":"1020304050607080"},"integration":"aws"})",
    R"(1:[123] (hostname_test_bench) any->/var/some_location:{"flow":{"start":"2020-06-26T11:00:02.970011-0400","bytes_toclient":4660,"bytes_toserver":1074,"pkts_toclient":8,"pkts_toserver":7},"app_proto":"tls","tls":{"ja3s":{"string":"742,48172,30210-30","hash":"391231ba5675e42807b9e1f457b2614e"},"ja3":{"string":"718,4682-2687-2686-41992-41911-53292-53297-41969-22905-41926-41924-94181-94711-15-23-95-12-11-205,0-33-50-53-6-61-39-23-34-85-81,93-04-52,3-9-3","hash":"3f1ea03f5822e8021b60cc3e4b233181"},"notafter":"2026-06-25T17:36:29","notbefore":"2016-06-27T17:36:29","version":"TLS 1.2","sni":"host.domain.net","fingerprint":"36:3f:ee:2a:1c:fa:de:ad:be:ef:42:99:cf:a9:b0:91:01:eb:a9:cc","serial":"72:A9:2C:51","issuerdn":"C=Unknown, ST=Unknown, L=Unknown, O=Unknown, OU=Unknown, CN=Unknown","subject":"C=Unknown, ST=Unknown, L=Unknown, O=Unknown, OU=Unknown, CN=Unknown"},"alert":{"severity":3,"category":"","signature":"SURICATA TLS on unusual port","rev":1,"signature_id":2610003,"gid":1,"action":"allowed"},"proto":"TCP","dest_port":8443,"dest_ip":"10.128.2.48","src_port":64389,"src_ip":"10.137.3.54","event_type":"alert","in_iface":"enp0s31f6","flow_id":991192778198299,"timestamp":"2020-06-26T11:00:03.342282-0400"})",
    R"(2:10.0.0.1:Mar  1 18:48:50.483 UTC: %SEC-6-IPACCESSLOGSP: list INBOUND-ON-F11 denied igmp 198.51.100.2 -> 224.0.0.2 (20), 1 packet)",
    R"(2:10.0.0.1:Feb 14 09:40:10.326: %ASA-3-106010: Deny inbound tcp src DMZ:10.10.100.50/726 dst inside:192.168.1.25/515)",
    R"(2:10.0.0.1:Mar  1 18:48:50.483 UTC: %ASA-2-106007: Deny inbound UDP from outside_address/outside_port to inside_address/inside_port due to DNS {Response|Query}.)",
    R"(2:10.0.0.1:Mar  1 18:46:11: %ASA-6-106013: Dropping echo request from 172.16.0.10 to PAT address)",
    R"(2:10.0.0.1:Mar  1 18:46:11: %ASA-2-106016: Deny IP spoof from (0.0.0.0) to 192.88.99.47 on interface Mobile_Traffic)"};
} // namespace
