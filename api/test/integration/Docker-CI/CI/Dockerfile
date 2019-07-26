FROM phusion/baseimage
 
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y openssh-server supervisor
RUN apt-get install python3 python3-pip git -y
RUN pip3 install tavern
RUN pip3 install pytest==4.5.0

RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout dev-flask-poc

ADD entrypoint.sh /scripts/entrypoint.sh
