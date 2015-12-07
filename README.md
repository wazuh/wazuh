OSSEC v2.8 Copyright (C) 2014 Trend Micro Inc.

# Information about OSSEC 

OSSEC is a full platform to monitor and control your systems. It mixes together 
all the aspects of HIDS (host-based intrusion detection), log monitoring and 
SIM/SIEM together in a simple, powerful and open source solution.

Visit our website for the latest information.  [ossec.github.io](http://ossec.github.io)



## Current Releases 

The current stable releases are available on the ossec website. 

* Releases can be downloaded from: [Downloads](http://ossec.github.io/downloads.html)
* Release documentation is available at: [docs](http://ossec.github.io/docs/)

## Development ##

The development version is hosted on GitHub and just a simple git clone away. 

[![Build Status](https://travis-ci.org/ossec/ossec-hids.png?branch=master)](https://travis-ci.org/ossec/ossec-hids)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/1847/badge.svg)](https://scan.coverity.com/projects/1847)


## Quick install 

```
$ (ossec_version="2.8.2" ; ossec_checksum="a0f403270f388fbc6a0a4fd46791b1371f5597ec" ; cd /tmp/ && wget https://github.com/ossec/ossec-hids/archive/${ossec_version}.tar.gz && mv ${ossec_version}.tar.gz ossec-hids-${ossec_version}.tar.gz && checksum=$(sha1sum ossec-hids-${ossec_version}.tar.gz | cut -d" " -f1); if [ $checksum == $ossec_checksum ]; then tar xfz ossec-hids-${ossec_version}.tar.gz && cd ossec-hids-${ossec_version} && sudo ./install.sh ; else "Wrong checksum. Download again or check if file has been tampered with."; fi)

```

Then follow the prompts.  You should still Read the Documentation [here](http://ossec.github.io/docs/).

## Credits and Thanks ##

* OSSEC comes with a modified version of zlib and a small part 
  of openssl (sha1 and blowfish libraries)
* This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/).
* This product includes cryptographic software written by Eric 
  Young (eay@cryptsoft.com)
* This product include software developed by the zlib project 
  (Jean-loup Gailly and Mark Adler).
* This product include software developed by the cJSON project 
  (Dave Gamble)


