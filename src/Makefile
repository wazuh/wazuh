# Makefile
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

none:
		@echo "Nothing selected ..."
		@echo "\"make all\" to compile everything."
		@echo "\"make server\" to build the server."
		@echo "\"make agent\" to build the agent."
		@echo "\"make libs\" to build the libraries only."
		@echo "\"make clean\" to clean anything built"

clean:
		@/bin/sh ./Makeall clean
		rm -f ../bin/ossec*
		rm -f ../bin/addagent

all:
		@/bin/sh ./Makeall all

build:
		@/bin/sh ./Makeall build

libs:
		@/bin/sh ./Makeall libs

server:
		@/bin/sh ./InstallServer.sh

agent:
		@/bin/sh ./InstallAgent.sh
