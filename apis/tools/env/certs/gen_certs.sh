#!/bin/bash

if [ $(basename $PWD) != 'certs' ]; then
cd 'certs'
fi

fs='.'

if [[ ! -e $fs/cfssl ]]; then
curl -s -L -o $fs/cfssl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
curl -s -L -o $fs/cfssljson https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
chmod 755 $fs/cfssl*
fi

cfssl=$fs/cfssl
cfssljson=$fs/cfssljson

if [[ ! -e $fs/root-ca.pem ]]; then

cat << EOF | $cfssl gencert -initca - | $cfssljson -bare root-ca -
{
  "CN": "Wazuh",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
  {
    "C": "US",
    "L": "San Francisco",
    "O": "Wazuh",
    "OU": "Wazuh Root CA"
  }
 ]
}
EOF

fi

if [[ ! -e $fs/ca-config.json ]]; then
$cfssl print-defaults config > ca-config.json
fi

gencert() {
    name=$1
    profile=$2
cat << EOF | $cfssl gencert -ca=root-ca.pem -ca-key=root-ca-key.pem -config=ca-config.json -profile=$profile -hostname="$name,127.0.0.1,localhost" - | $cfssljson -bare $name -
{
  "CN": "$i",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
  {
    "C": "US",
    "L": "California",
    "O": "Wazuh",
    "OU": "Wazuh"
  }
  ],
  "hosts": [
    "$i",
    "127.0.0.1",
    "localhost"
  ]
}
EOF
openssl pkcs8 -topk8 -inform pem -in $name-key.pem -outform pem -nocrypt -out $name.key
}

hosts=(wazuh-indexer wazuh-manager)
for i in "${hosts[@]}"; do
    gencert $i www
done
