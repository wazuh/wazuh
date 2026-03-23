/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Febrary 6, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSAHELPER_WRAPPER_TEST_H
#define _RSAHELPER_WRAPPER_TEST_H

#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>

const std::string KEY_1024 {
    R"(-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMnJK5L5WX6p5ky2
6xYj7vMlgTYsqWjVpUqqcLV4cyA0gz8pHrlFU/b9Vc3jTrGaGeR9Ghs8SFYAZLr7
9+ojyv1eza8qNodCt8JFP2+RwQRyRsynAj9hcx99tIAR0auw22y9erwk++7zGNQp
C5BIKE674Icg3cYQvDXCVVDvBASVAgMBAAECgYEAoHKcekZY+hWAcPl1nmo+Iwps
XrZOknRm9SLncfRvnmkC/2Lj8i+FHzy7UHXw6dl9wygSbRuW7QNtFR0rOPry+O8V
xXP7S5K/eyCF4AJeCvddCF6aCr+bZhevmo911f8q2HoQh0tR+VhRp6b9w5cxjPVY
vHf3syLlP2FawyjBjOECQQD9zB9qzFESm3kF3a1v8eWTh6P2qiSeiHC4bzjNdHXB
IwCtF1EuK/UqFW7+eXztzOjHIDNMcitr+ZJFijpgtpg5AkEAy4l9gOnJ9p5BFTUP
m3qbjzoDqhkl4Vv8+AJkawTy53LIchrLEeJmSwZkWkAK1G8n7N976HuGeDYHc2jZ
ODm3PQJAcXZ3OTS8rffpxBCVwC1BuJH0YIsyMdnHovy+RUPifQTcAYYiGeU3Bqhs
ZcIEcv+ftZ4UsQF9nhkGJqakcKZRKQJACVhRs9aIGFOhx1h9U/UoKUZPnsKy04sG
rVhmxecfQ/MoMtz6D+MmMTGk7+Pa23ATFDQam0z4mpJYezsIJiW4PQJBAMgxBQgq
8HlZaesQ8B4HwTi/p9hi6yLVjgrAyx23BtvuXO8Fu8eM90Fv8N/5/ANCkkg4wPiV
a0p7lYapNJeFHlM=
-----END PRIVATE KEY-----)"};
const std::string CERT_1024 {
    R"(-----BEGIN CERTIFICATE-----
MIICQDCCAamgAwIBAgIUNDB6glpu6Zbnf9o28LeoTB+q2ukwDQYJKoZIhvcNAQEL
BQAwMjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExDjAMBgNVBAMM
BVdhenVoMB4XDTI0MDcxMjE4NDYyN1oXDTI1MDcxMjE4NDYyN1owMjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExDjAMBgNVBAMMBVdhenVoMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJySuS+Vl+qeZMtusWI+7zJYE2LKlo1aVK
qnC1eHMgNIM/KR65RVP2/VXN406xmhnkfRobPEhWAGS6+/fqI8r9Xs2vKjaHQrfC
RT9vkcEEckbMpwI/YXMffbSAEdGrsNtsvXq8JPvu8xjUKQuQSChOu+CHIN3GELw1
wlVQ7wQElQIDAQABo1MwUTAdBgNVHQ4EFgQUqX6L6O3Js9drf8uGR9G3k1vdPVQw
HwYDVR0jBBgwFoAUqX6L6O3Js9drf8uGR9G3k1vdPVQwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOBgQCzTfGnS9FZ3LbcfeJ564vYhh12Ne7HuYAuD+Yv
ljw631Gg6zDlA7wErTKnqbw6JfIefvVbTDh0MAtoLDSDexyRdDgkF/9oF2HlShDo
voB3XMElqJ1TBvbHAG+6+yvXPLkKTGpVXqxBGYo5bT5qYJ8Ktxhy1UBlR9j9Lkd8
fRlnFw==
-----END CERTIFICATE-----)"};
const std::string KEY_2048 {
    R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDTgVbac4E1/wlW
oOXfI1HLhm8lj7KAgQdND6v15g2Fx2pXXp6rhAoaGeVT+BAdOg1ItH74Bm69vqvx
PFpkB1TNdCckFsHzhmbif+GnvToceZ+hZc2UzMyGs6HdJ5H9uQpWuwYZEY+DKetJ
Pry0LJEiD1480YxBroB8kovIO918XMXhF/0J0wJYiCFvGBvXmcT6X1gNftKF1VLD
S86fiv85F6jWBDrop2iNeiT4W5UYnatFIyfRbNX0mX4m91QTTsNxcUib7mDhQtdP
8XAAJ8VuyitnUKtq7/UrD6VL35MO9yhJDIuvs34MSBaQuXfZ+QQG4hGybpVG9hTW
cepsTlpxAgMBAAECggEAH1ri+QWl7SRUSmnAn6Deemar9Dc7sOiaoCZSSY+uXNvK
/GLZm6G6gai/IlX5xZYalrcIxP+Ry+1daNOYBDuWAH4CDiFAOuL86QJ+UzNZTxQK
Fzo+t5rY40tJaWjOsCeOIdIeEvn90DsXAh0b3+C6L1YfPrLuBmVhROvQxIF40fuw
bPlrdU6OjLb7zam84eo28+jOJaMZgt9IDJdHsrhyRG82seYvPYKJhtCZq+G1qtJo
fSJgKar/O1DxcwMb2vuPgwl0RsRuBiYhYlKCfubYhjr4JGlchLNQ2IDYS/Ccpm/Z
UGzqTWKO2ZfKqk9dOvS7ypYY8uqM5PLjWd5wEEuVxQKBgQD5hYBuMp05I6/jAa06
XNVPsIfAxJmzaNcReZvqmaK4CKx6P0B2aAVsnEBaD91yTXEnxZF943jFnrz1bLzP
HKnxjscF065Zgz7esnCF4mFC74Op2XLLirJJTfI+b7NrIjVSBQ7LedrtfY+7GzVP
6paugbqynHqnKhSbpLSt2i5GlwKBgQDY/yeCgfYWD1Oz2Ubfl3EKQ3aW3Duzej+a
ZTja4UB121DP01F/CVaW4AQxvsNbvOHAuDStrcD1Mj3UjYaREGlB9YpwurkgW32e
wKf8g8gfls0PxK+kbjb5GRXBy/qamqGTFeIDJZ5YJg/SLVPTfHwptecZtTz3X+R6
ZStsA+JQNwKBgDj/6T3DLC1QXK6TxHmvmT7yCaDciGv2iCLCz/5AiG5X9OacKmKi
EpMkAoNQWnrw++dk9351hzJFt86sv1jkqGG5BvfqykpCdAs1YgUDmMpMopwbQ2EB
1wZt2ueuZqMTlnCdHSsYNA3KgBny9jPCWBeXJQoGOvKS51BCyM9qJuYTAoGAecVN
va4Ck8SMGyv92rFYbQMIxIXYNtKOaK0O571p9/lX8xhJ7nkmD0qs7+F2Lb/kC8sT
PLd5xd8o1WOKNVO5TZtl0fbmtmLBLto8KrclEZ0FfCjKzAJRdR3/mJ5IBoRp0WmB
SHTO0/agADkRhmegIaQDiOisysEULR8i692OHacCgYEA4UF66MOfKGhDFpEylUXP
p188QrIYAzfMmCzqLrQSHFAZfngEWWp5fQehV3GwddbguEbdclnkawr8PIpVKYLE
JGT7GNuF+/HlkfiyfYooKotSMnVZim2yUK26ow+R1egwCEzlPqbtXPJyCNkbfAzX
n5cnXrfe5a4sLl1Ubxi3VDU=
-----END PRIVATE KEY-----)"};
const std::string CERT_2048 {
    R"(-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUXXLvP3R0HSq0UCdR6WSqH89/qKAwDQYJKoZIhvcNAQEL
BQAwMjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExDjAMBgNVBAMM
BXdhenVoMB4XDTI0MDcxMTE4NDczNloXDTI1MDcxMTE4NDczNlowMjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExDjAMBgNVBAMMBXdhenVoMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA04FW2nOBNf8JVqDl3yNRy4ZvJY+y
gIEHTQ+r9eYNhcdqV16eq4QKGhnlU/gQHToNSLR++AZuvb6r8TxaZAdUzXQnJBbB
84Zm4n/hp706HHmfoWXNlMzMhrOh3SeR/bkKVrsGGRGPgynrST68tCyRIg9ePNGM
Qa6AfJKLyDvdfFzF4Rf9CdMCWIghbxgb15nE+l9YDX7ShdVSw0vOn4r/OReo1gQ6
6KdojXok+FuVGJ2rRSMn0WzV9Jl+JvdUE07DcXFIm+5g4ULXT/FwACfFbsorZ1Cr
au/1Kw+lS9+TDvcoSQyLr7N+DEgWkLl32fkEBuIRsm6VRvYU1nHqbE5acQIDAQAB
oz0wOzAdBgNVHQ4EFgQUn17YPOxMTB907b81YUKmvg04tJ8wCQYDVR0jBAIwADAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAdZGocU0DixhxNPRIe
eXhMoKyxRwJw50uBqj/zrGUFTVEWD+fBfy3Fa4C4p73d5mE2zT+oQnzsdZ6vHXh5
R+1H35gpq8u+Q1e2m+IbrxAh4/loBG8lhdNpo3l2RN/Q34OghnEucgVq42V45/z7
xQ6h3mCaT367YdaiSUkV/pgdxWt/DkOV0Ax/anPbCAN/wUwJTFMubSHjiVoXLYZr
pz8dh4BjkDh3l1f3dGeqMg2Mvti0Jj8KMpVrDsLZbjcsqty/pyHzld2hG4dgibhg
7t4km0UHB0qY1LqWLltfBfK98D7hyYx9vUeEVBLInwL39gHThfQS0RF/b42uCGl9
eJFC
-----END CERTIFICATE-----)"};
const std::string KEY_4096 {
    R"(-----BEGIN PRIVATE KEY-----
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
WPcend6P6DGy/HOl9VshExIxHYVc+Jk=
-----END PRIVATE KEY-----)"};
const std::string CERT_4096 {
    R"(-----BEGIN CERTIFICATE-----
MIIFODCCAyCgAwIBAgIUHQAXewNXoEf6fabfbXZvdJ5ipkAwDQYJKoZIhvcNAQEL
BQAwKjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ4wDAYDVQQKDAVXYXp1aDAe
Fw0yNDA2MTMyMjIyNTRaFw0yNTA2MTMyMjIyNTRaMCExCzAJBgNVBAYTAlVTMRIw
EAYDVQQDDAkxMC4wLjAuNDAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQDMwDLres9zL9DO27RJb8w+FGZByYHQ0Txl+VgfDnGs50MBRdOnFMSkRkPeXe5l
3ZmQocci/gOdmVt2i2u73mlqfRhSlhsC9luTA/u21osNtkuedKe9rxBUAC2OBmhn
aUfiFGWA3HnvkEafQwcqVH2uC5AQyqHNcaq8y2UOK9h2M7+1gjJrk80AW/EbbiAW
ld3hptlxw+J/ev5IO4VhqAC9i4xx43jmlWA2tWSfhW6eUxko4sFxhiMROQIDRQhU
U+ANmxN08yVNofSpvMDztRw2rmVdObYBYP2sxhLM0UYl/MCCiEZuRXY1pruV54QO
+JNsoeFXdsAc+bwIpfGjkyKWh0oJWpJE057HddAi/ubHWeoKLR9NT2XJK4amycOL
kSoCKLQldtHwzF3AEWSiPtWTc9207c4anYodFvg8yj1lbNwM9gpkRx4Bkb8Fa9KP
AOBErvwBHnbRYw6OvGvGJ/VSrUta1xRHp8wEqpBz5h7bgOg//ACMGOXOSSQlfayK
fSN9fI1TPxNL09S4FZCyMqEFVmYW+KKpuW1EsfYHgW+pJbOVwl4vXzkvKKaRucVG
aQFdHAE09G0b0t+37J0Jk8LY65T6e7f4gP89tF0ert3/k1nM218Rq9FRJQKutHAc
VkgeKHGJiMPT03Nn5P1hf247kXf+j6UYPQmsynDMw37vAwIDAQABo18wXTAbBgNV
HREEFDASggV3YXp1aIIJd2F6dWguY29tMB0GA1UdDgQWBBTs0Rc05uBXGw9h3kFv
FxaXPDRSDjAfBgNVHSMEGDAWgBQkMSNQkA9Q1vy1YtuOOqP1HlfxVDANBgkqhkiG
9w0BAQsFAAOCAgEAUrFXW2rZANQwcyK9nvZlzKKgjtAZTfPeqmiw2Wcrp3/GcOYB
9SvEI7yGEtJ5qeshZ01a4bzFIdgobnwp6RkFVzdshhDoAgksLGeMC4vqMQGw9TXt
l7EA0YQzosqz+IeX3d4qHdGNywNGBtIgZbDePEQWxL7JUpK88BXRMk2X+4/Rl0rQ
wIFzY7287EACRiTKjE6KxiGpOLLqoD8RxOOG3KBs/0Tc+nyoFUdqHYxmFK5jgwCh
K5OU36fGfkhNIsRynVeDsr6oEaJvEkE8zauIjrl2fkloh21abP75vw2vNqFP4riR
mzo6zpOwsubI+eRjYYvJoWhw3xbJEg1f4HH7oVnY9qv/zTjlW8Xu7U2ZbytVJsMc
IbyiuD2KwU4IPibD0Omx9tHD+DJQvR5h+1qy7OQ8r2NtcFgb6Uc2UWVmO0FP+Ftf
GcbHG+XVcEgW0heL9PmcmeUmpmaNL3i1RfIeYQdi9OzVvcxTsgxKK1zovA8S3wm9
52g5pPpDFwyvn1EQmQdfKH5BB09g65qIpdhajTJcRWUklT5PfDKYDVh3xiKh3/h4
lMc8/nhdnPZPa9UhtVPYPE7mdRo50VtNmrJYPAh0cu1kyItvsevrQR6zBDotXDRn
NmK25PCs3z9nMvIYzFWyOdUeXjpKYkr1Ut9XdmdplxXGXS53w+M1ZKawHeE=
-----END CERTIFICATE-----)"};

class RSAHelperTest : public ::testing::Test
{
protected:
    RSAHelperTest() = default;
    virtual ~RSAHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};

class RSAHelperTest2 : public ::testing::TestWithParam<std::pair<std::string, std::string>>
{
protected:
    RSAHelperTest2() = default;
    virtual ~RSAHelperTest2() = default;

    static void SetUpTestSuite()
    {
        const auto createKeys {[](const std::string& fileName, const std::string& content)
                               {
                                   std::ofstream output(fileName, std::ios::binary);
                                   if (output.good())
                                   {
                                       output << content;
                                   }
                               }};

        createKeys("1024.key", KEY_1024);
        createKeys("1024.cert", CERT_1024);
        createKeys("2048.key", KEY_2048);
        createKeys("2048.cert", CERT_2048);
        createKeys("4096.key", KEY_4096);
        createKeys("4096.cert", CERT_4096);
    }

    static void TearDownTestSuite()
    {
        for (const auto& path : std::filesystem::directory_iterator("./"))
        {
            if (path.path().string().find(".key") != std::string::npos ||
                path.path().string().find(".cert") != std::string::npos)
            {
                std::filesystem::remove_all(path.path());
            }
        }
    }
};

#endif //_RSAHELPER_WRAPPER_TEST_H
