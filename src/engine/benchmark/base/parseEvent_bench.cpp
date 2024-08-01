#include <base/parseEvent.hpp>

#include <list>

#include <benchmark/benchmark.h>

namespace
{
// Sample events
const std::vector<std::string>
    sampleEventsStr = {R"(1:[123] (hostname_test_bench) any->/var/some_location:::1 - - [26/Dec/2016:16:16:29 +0200] "GET /favicon.ico HTTP/1.1" 404 209)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:::1 - - [26/Dec/2016:16:16:29 +0200] "GET /favicon.ico HTTP/1.1" 404 209)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:192.168.33.1 - - [26/Dec/2016:16:22:00 +0000] "GET / HTTP/1.1" 200 484 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:127.0.0.1 - - [02/Feb/2019:05:38:45 +0100] "-" 408 152 "-" "-")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:monitoring-server - - [29/May/2017:19:02:48 +0000] "GET /status HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:::1 - - [26/Dec/2016:16:16:48 +0200] "-" 408 -)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:[Mon Dec 26 16:15:55.103786 2016] [core:notice] [pid 11379] AH00094: Command line: '/usr/local/Cellar/httpd24/2.4.23_2/bin/httpd')",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:[Fri Sep 09 10:42:29.902022 2011] [core:error] [pid 35708:tid 4328636416] [client 72.15.99.187] File does not exist: /usr/local/apache2/htdocs/favicon.ico)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:[Thu Jun 27 06:58:09.169510 2019] [include:warn] [pid 15934] [client 123.123.123.123:12345] AH01374: mod_include: Options +Includes (or IncludesNoExec) wasn't set, INCLUDES filter removed: /test.html)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:[Mon Dec 26 16:22:08 2016] [error] [client 192.168.33.1] File does not exist: /var/www/favicon.ico)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:[Mon Dec 26 16:17:53 2016] [notice] Apache/2.2.22 (Ubuntu) configured -- resuming normal operations)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 21 21:56:12 localhost sshd[3430]: Invalid user test from 10.0.2.2)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 19 15:30:04 slave22 sshd[18406]: Did not receive identification string from 2.125.160.217)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 00:13:02 precise32 sudo:      tsg : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/vagrant ; USER=root ; COMMAND=/bin/ls)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:20:10 precise32 sudo:  vagrant : TTY=pts/0 ; PWD=/home/vagrant ; USER=root ; COMMAND=/bin/cat /var/log/auth.log)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:19:55 precise32 groupadd[7996]: new group: name=mysql, GID=111)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:19:55 precise32 useradd[8002]: new user: name=mysql, UID=106, GID=111, home=/nonexistent, shell=/bin/false)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 21 21:54:44 localhost sshd[3402]: Accepted publickey for vagrant from 10.0.2.2 port 63673 ssh2: RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 22 16:45:20 slave22 sshd[2738]: Failed password for root from 202.196.224.106 port 1786 ssh2)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:20:10 precise32 sudo: pam_unix(sudo:session): session opened for user root by vagrant(uid=1000))",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb  9 21:20:03 precise32 sshd[8317]: subsystem request for sftp by user vagrant)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:20:10 precise32 sudo: pam_unix(sudo:session): session closed for user root)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 21 21:54:44 localhost sshd[3402]: Accepted publickey for vagrant from 10.0.2.2 port 63673 ssh2: RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:20:10 precise32 sudo:  vagrant : TTY=pts/0 ; PWD=/home/vagrant ; USER=root ; COMMAND=/bin/cat /var/log/auth.log)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:Feb 24 09:19:55 precise32 groupadd[7996]: new group: name=mysql, GID=111)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:{"aws":{"source":"cloudtrail","eventVersion":"some-event-version","eventID":"some-event-id","eventTime":"2018-08-24T17:20:08Z","log_file":"some-log-file.json.gz","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/console/home","MobileVersion":"No"},"eventType":"AwsConsoleSignIn","errorMessage":"Failed authentication","responseElements":{"ConsoleLogin":"Failure"},"awsRegion":"us-east-1","eventName":"ConsoleLogin","userIdentity":{"userName":"some-user-name","accessKeyId":"some-access-key","type":"IAMUser","principalId":"some-principal-id","accountId":"0303456"},"eventSource":"signin.amazonaws.com","userAgent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0","sourceIPAddress":"7.222.123.101","recipientAccountId":"1020304050607080"},"integration":"aws"})",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:{"aws":{"authentication_type":"AuthHeader","bucket_owner":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be","bucket":"awsexamplebucket1","bytes_sent":2662992,"cipher_suite":"ECDHE-RSA-AES128-GCM-SHA256","error_code":"NoSuchBucket","host_header":"s3.us-west-2.amazonaws.com","host_id":"s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234=","http_status":200,"key":"/photos/2019/08/puppy.jpg","object_sent":3462992,"operation":"REST.GET.VERSIONING","referer":"http://www.amazon.com/webservices","remote_ip":"192.0.2.3","request_id":"3E57427F3EXAMPLE","request_uri":"GET /awsexamplebucket1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1","requester":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be","signature_version":"SigV2","source":"s3_server_access","time":"06/Feb/2019:00:00:38 +0000","tls_version":"TLSv1.2","total_time":70,"turn_around_time":10,"user_agent":"curl/7.15.1","version_id":"3HL4kqtJvjVBH40Nrjfkd"},"integration":"aws"})",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:http 2019-10-11T15:01:12.376735Z app/filebeat-aws-elb-test/c86a326e7dc14222 81.2.69.193:56398 10.0.0.192:80 -1 -1 -1 460 - 125 0 "GET http://filebeat-aws-elb-test-12030537.eu-central-1.elb.amazonaws.com:80/ HTTP/1.1" "curl/7.58.0" - - arn:aws:elasticloadbalancing:eu-central-1:627959692251:targetgroup/test-lb-instances/8f04c4fe71f5f794 "Root=1-5da09932-2c342a443bfb96249aa50ed7" "-" "-" 0 2019-10-11T15:01:06.657000Z "forward" "-" "-")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0" - - arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "-" "-" 0 2018-07-02T22:22:48.364000Z "forward,redirect" "-" "-" "10.0.0.1:80" "200" "-" "-")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:lessons.example.com 192.168.0.1 - - [09/Jun/2020:12:10:39 -0700] "GET /A%20Beka%20G1%20Howe/029_AND_30/15%20reading%20elephants.mp4 HTTP/1.1" 206 7648063 "http://lessons.example.com/A%20Beka%20G1%20Howe/029_AND_30/15%20reading%20elephants.mp4" "Mozilla/5.0 (Linux; Android 5.1.1; KFFOWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/81.2.16 like Chrome/81.0.4044.138 Safari/537.36")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:192.168.0.1 - userNameTest [09/Jun/2020:12:10:39 -0700] "GET /A%20Beka%20G1%20Howe/029_AND_30/15%20reading%20elephants.mp4 HTTP/1.1" 206 7648063 "http://lessons.example.com/A%20Beka%20G1%20Howe/029_AND_30/15%20reading%20elephants.mp4" "Mozilla/5.0 (Linux; Android 5.1.1; KFFOWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/81.2.16 like Chrome/81.0.4044.138 Safari/537.36")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:lessons.example.com 192.168.0.1 - - [09/Jun/2020:12:10:39 -0700] "GET /A%20Beka%20G1%20Howe/029_AND_30/15%20reading%20elephants.mp4 HTTP/1.1" 206 7648063 "http://lessons.example.com/A%20Beka%20G1%20Howe/029_AND_30/15%20reading%20elephants.mp4" "Mozilla/5.0 (Linux; Android 5.1.1; KFFOWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/81.2.16 like Chrome/81.0.4044.138 Safari/537.36")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:2016/10/25 14:49:34 [error] 54053#0: *1 open() "/usr/local/Cellar/nginx/1.10.2_1/html/favicon.ico" failed (2: No such file or directory), client: 127.0.0.1, server: localhost, request: "GET /favicon.ico HTTP/1.1", host: "localhost:8080", referrer: "http://localhost:8080/")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:2016/10/25 14:50:44 [error] 54053#0: *3 open() "/usr/local/Cellar/nginx/1.10.2_1/html/adsasd" failed (2: No such file or directory), client: 127.0.0.1, server: localhost, request: "GET /adsasd HTTP/1.1", host: "localhost:8080")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:2019/10/30 23:26:34 [error] 205860#205860: *180289 FastCGI sent in stderr: "PHP message: PHP Warning:  Declaration of FEE_Field_Terms::wrap($content, $taxonomy, $before, $sep, $after) should be compatible with FEE_Field_Post::wrap($content, $post_id = 0) in /var/www/xxx/web/wp-content/plugins/front-end-editor/php/fields/post.php on line 0)",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:2021-02-14 10:45:48.113 UTC,"postgres","postgres",86,"172.24.0.1:48978",6028ff3a.56,5,"idle",2021-02-14 10:45:14 UTC,3/4,0,LOG,00000,"statement: BEGIN;",,,,,,,,,"psql","client backend")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:2021-01-04 00:51:56.843 UTC,\"postgres\",\"postgres\",105,\"172.24.0.1:44618\",5ff26691.69,8,\"SELECT\",2021-01-04 00:51:29 UTC,3/136,0,LOG,00000,\"duration: 0.455 ms  execute py:0x7fde12d61b80: SELECT * from information_schema.tables WHERE table_name = $1\",\"parameters: $1 = 'tables'\",,,,,,,,\"\"")",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:{"timestamp":"2021-01-27T01:28:11.488362+0100","flow_id":1805461738637437,"in_iface":"enp6s0","event_type":"alert","src_ip":"81.2.69.143","src_port":80,"dest_ip":"10.31.64.240","dest_port":47592,"proto":"TCP","ether":{"src_mac":"00:03:2d:3f:e5:63","dest_mac":"00:1b:17:00:01:18"},"alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"GPL ATTACK_RESPONSE id check returned root","category":"Potentially Bad Traffic","severity":2,"metadata":{"protocols":["tcp","smtp"],"mitre_attack":["t1190"],"cvss_v2_temporal":["7.9"],"cve":["2019-91325"],"cvss_v3_temporal":["7.1"],"attack_target":["smtp-server","server"],"cvss_v2_base":["8.1"],"rule_source":["acme-rule-factory"],"priority":["medium"],"filename":["exploit.rules"],"updated_at":["2019-06-11"],"capec_id":["248"],"created_at":["2019-06-01"],"hostile":["src_ip"],"cvss_v3_base":["7.3"],"cwe_id":["20"]}},"http":{"hostname":"testmynids.org","url":"/uid/index.html","http_user_agent":"curl/7.58.0","http_content_type":"text/html","http_method":"GET","protocol":"HTTP/1.1","status":200,"length":39},"app_proto":"http","flow":{"pkts_toserver":6,"pkts_toclient":5,"bytes_toserver":496,"bytes_toclient":876,"start":"2021-01-22T23:28:38.673917+0100"}})",
                       R"(1:[123] (hostname_test_bench) any->/var/some_location:{"flow":{"start":"2020-06-26T11:00:02.970011-0400","bytes_toclient":4660,"bytes_toserver":1074,"pkts_toclient":8,"pkts_toserver":7},"app_proto":"tls","tls":{"ja3s":{"string":"742,48172,30210-30","hash":"391231ba5675e42807b9e1f457b2614e"},"ja3":{"string":"718,4682-2687-2686-41992-41911-53292-53297-41969-22905-41926-41924-94181-94711-15-23-95-12-11-205,0-33-50-53-6-61-39-23-34-85-81,93-04-52,3-9-3","hash":"3f1ea03f5822e8021b60cc3e4b233181"},"notafter":"2026-06-25T17:36:29","notbefore":"2016-06-27T17:36:29","version":"TLS 1.2","sni":"host.domain.net","fingerprint":"36:3f:ee:2a:1c:fa:de:ad:be:ef:42:99:cf:a9:b0:91:01:eb:a9:cc","serial":"72:A9:2C:51","issuerdn":"C=Unknown, ST=Unknown, L=Unknown, O=Unknown, OU=Unknown, CN=Unknown","subject":"C=Unknown, ST=Unknown, L=Unknown, O=Unknown, OU=Unknown, CN=Unknown"},"alert":{"severity":3,"category":"","signature":"SURICATA TLS on unusual port","rev":1,"signature_id":2610003,"gid":1,"action":"allowed"},"proto":"TCP","dest_port":8443,"dest_ip":"10.128.2.48","src_port":64389,"src_ip":"10.137.3.54","event_type":"alert","in_iface":"enp0s31f6","flow_id":991192778198299,"timestamp":"2020-06-26T11:00:03.342282-0400"})",
                       R"(2:10.0.0.1:Feb 14 09:40:10.326: %ASA-2-106001: Inbound TCP connection denied from ::1/4040 to ::2/5050 flags tcp_flags on interface interface_name)",
                       R"(2:10.0.0.1:Mar  1 18:48:50.483 UTC: %SEC-6-IPACCESSLOGP: list ACL-IPv4-E0/0-IN permitted tcp 192.168.1.3(1024) -> 192.168.2.1(22), 1 packet)",
                       R"(2:10.0.0.1:Mar  1 18:46:11: %SEC-6-IPACCESSLOGRP: list 177 denied igmp 198.51.100.197 -> 224.0.0.22, 1 packet)",
                       R"(2:10.0.0.1:Feb 14 09:40:10.326: %SEC-6-IPACCESSLOGP: list ACL-IPv4-E0/0-IN permitted tcp 192.168.1.3(1025) (Ethernet0/0 000e.9b5a.9839) -> 192.168.2.1(22), 1 packet)",
                       R"(2:10.0.0.1:Mar  1 18:48:50.483 UTC: %SEC-6-IPACCESSLOGSP: list INBOUND-ON-F11 denied igmp 198.51.100.2 -> 224.0.0.2 (20), 1 packet)",
                       R"(2:10.0.0.1:Mar  1 18:46:11: %ASA-2-106001: Inbound TCP connection denied from IP_address/port to IP_address/port flagstcp_flags on interface interface_name)",
                       R"(2:10.0.0.1:Feb 14 09:40:10.326: %ASA-3-106010: Deny inbound tcp src DMZ:10.10.100.50/726 dst inside:192.168.1.25/515)",
                       R"(2:10.0.0.1:Mar  1 18:48:50.483 UTC: %ASA-2-106007: Deny inbound UDP from outside_address/outside_port to inside_address/inside_port due to DNS {Response|Query}.)",
                       R"(2:10.0.0.1:Mar  1 18:46:11: %ASA-6-106013: Dropping echo request from 172.16.0.10 to PAT address)",
                       R"(2:10.0.0.1:Feb 14 09:40:10.326: %ASA-3-106014: Deny inbound icmp src inside:10.10.1.132 dst inside:192.3.69.136 (type 0, code 0))",
                       R"(2:10.0.0.1:Mar  1 18:48:50.483 UTC: %ASA-3-106014: Deny inbound icmp src fw111:10.10.10.10 dst fw111:10.10.10.10(type 8, code 0))",
                       R"(2:10.0.0.1:Mar  1 18:46:11: %ASA-2-106016: Deny IP spoof from (0.0.0.0) to 192.88.99.47 on interface Mobile_Traffic)"};
} // namespace

// Parse Events
static void parseWazuhEvent_batch(benchmark::State& state)
{

    const auto sizeOfEvents = sampleEventsStr.size();
    auto current = 0;

    for (auto _ : state)
    {
        try
        {
            current = (current + 1) % sizeOfEvents;
            base::Event e;
            benchmark::DoNotOptimize(e = base::parseEvent::parseWazuhEvent(sampleEventsStr[current]));
            benchmark::ClobberMemory();
        }
        catch (const std::exception& e)
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(parseWazuhEvent_batch)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();

// Copy events | Copy json
static void copyEvents_batch(benchmark::State& state)
{

    const auto sizeOfEvents = sampleEventsStr.size();
    auto current = 0;
    std::vector<base::Event> events {};

    std::transform(sampleEventsStr.begin(),
                   sampleEventsStr.end(),
                   std::back_inserter(events),
                   [](const auto& e) { return base::parseEvent::parseWazuhEvent(e); });

    for (auto _ : state)
    {
        current = (current + 1) % sizeOfEvents;
        base::Event e;
        benchmark::DoNotOptimize(e = std::make_shared<json::Json>(*events[current]));
        benchmark::ClobberMemory();
    }
}

BENCHMARK(copyEvents_batch)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();
