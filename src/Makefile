# Makefile
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

none:
		@echo "Nothing selected ..."
		@echo "\"make all\" to compile everything."
		@echo "\"make server\" to build the server."
		@echo "\"make local\" to build the local."
		@echo "\"make agent\" to build the agent."
		@echo "\"make libs\" to build the libraries only."
		@echo "\"make clean\" to clean anything built"
		@echo "\"make setagent\" to set agent install"
		@echo "\"make setlocal\" to set local install"

clean:
		@/bin/sh ./Makeall clean
		rm -f ../bin/ossec*
		rm -f ../bin/manage_agents

all:
		@/bin/sh ./Makeall all

build:
		@/bin/sh ./Makeall build

libs:
		@/bin/sh ./Makeall libs

server:
		@/bin/sh ./InstallServer.sh

local:
		@/bin/sh ./InstallServer.sh local
        
agent:
		@/bin/sh ./InstallAgent.sh
        
setagent:
		@echo "CEXTRA=-DCLIENT" >> ./Config.OS
setlocal:
		@echo "CEXTRA=-DLOCAL" >> ./Config.OS
setfullsubject:
		@echo "FEXTRA=-DCLEANFULL" >> ./Config.OS
