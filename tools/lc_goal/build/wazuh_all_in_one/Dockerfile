FROM ubuntu:20.04
LABEL Description="Build indexer environment"

ENV HOME /root
ENV DEBIAN_FRONTEND noninteractive

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y --no-install-recommends install \
      build-essential \
      clang \
      gdb \
      wget

RUN apt-get update && apt-get -y --no-install-recommends install \
      curl \
      python \
      python3-pip \
      gcc \
      g++ \
      make \
      libc6-dev \
      policycoreutils \
      automake \
      autoconf \
      libtool \
      libssl-dev \
      ca-certificates


RUN apt-get update && apt-get -y --no-install-recommends install \
      debconf \
      adduser \
      procps \
      gnupg \
      apt-transport-https \
      systemd \
      gawk \
      lsof

RUN pip3 install \
      boto3==1.17.85 \
      botocore==1.20.85 \
      jmespath==0.9.5 \
      python-dateutil==2.8.1 \
      six==1.14.0 \
      urllib3==1.26.5 \
      s3transfer==0.4.2 \
      pyarrow==8.0.0 \
      numpy==1.21.6

RUN apt-get update && apt-get -y --no-install-recommends install \
      vim \
      iputils-ping \
      net-tools \
      ssh

RUN curl -OL https://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
        tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
        ./bootstrap --no-system-curl && make -j$(nproc) && \
        make install && \
        cd .. && rm -rf cmake-*

RUN apt-get update && apt-get -y --no-install-recommends install \
	git

WORKDIR /root

RUN curl -Ls https://github.com/wazuh/wazuh/archive/v4.4.4.tar.gz | tar zx
RUN cd wazuh-4.4.4 && make -C src clean && make -C src clean-deps
RUN cd wazuh-4.4.4 && make TARGET=server -C src deps 
# Set server instalation
RUN sed -i '935 i USER_INSTALL_TYPE="server"' wazuh-4.4.4/install.sh 
RUN cd wazuh-4.4.4 && make TARGET=server -C src
RUN cd wazuh-4.4.4 && ./install.sh 

# Install wazuh indexer
RUN curl -sO https://packages.wazuh.com/4.4/wazuh-install.sh
RUN curl -sO https://packages.wazuh.com/4.4/config.yml
RUN for node in indexer-node wazuh-manager dashboard-node; do \
            sed -i 's/<'"${node}"'-ip>/10.5.0.2/' config.yml; \
      done
RUN cp config.yml config.yml.bkp
# Generate certificates: wazuh-install-files.tar
RUN bash wazuh-install.sh --generate-config-files
RUN bash wazuh-install.sh --wazuh-indexer node-1  || true
RUN curl -sO https://packages.wazuh.com/4.4/wazuh-certs-tool.sh
RUN cp config.yml.bkp config.yml
RUN bash ./wazuh-certs-tool.sh -A
RUN tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
RUN rm -rf ./wazuh-certificates


# Install Indexer
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN apt-get update && apt-get -y --no-install-recommends install \
      wazuh-indexer

RUN NODE_NAME=node-1 && \
      mkdir -p /etc/wazuh-indexer/certs && \
      tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem && \
      mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/$NODE_NAME.pem && \
      mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/$NODE_NAME-key.pem && \
      chmod 500 /etc/wazuh-indexer/certs && \
      chmod 400 /etc/wazuh-indexer/certs/* && \
      chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs 

RUN update-rc.d wazuh-indexer defaults 95 10

# Install filebeat
RUN apt-get update && apt-get -y --no-install-recommends install \
      filebeat \
      daemon

# Fix daemon syntax
RUN sed -i '89s/\$exec.*/-f \$exec -d/' /etc/init.d/wazuh-indexer

# Config 
RUN curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.4/tpl/wazuh/filebeat/filebeat.yml
RUN sed -i 's/127.0.0.1/10.5.0.2/' /etc/filebeat/filebeat.yml
RUN filebeat keystore create
RUN echo admin | filebeat keystore add username --stdin --force
RUN echo admin | filebeat keystore add password --stdin --force
RUN curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.4/extensions/elasticsearch/7.x/wazuh-template.json
RUN chmod go+r /etc/filebeat/wazuh-template.json
RUN curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.2.tar.gz | tar -xvz -C /usr/share/filebeat/module
RUN update-rc.d filebeat defaults 95 10

RUN NODE_NAME=wazuh-1 && \
      mkdir -p /etc/filebeat/certs && \
      tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem && \
      mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem && \
      mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem && \
      chmod 500 /etc/filebeat/certs && \
      chmod 400 /etc/filebeat/certs/* && \
      chown -R root:root /etc/filebeat/certs

# Install Dashboad

RUN apt-get update && apt-get -y --no-install-recommends install \
      debhelper \
      tar \
      libcap2-bin

RUN bash wazuh-install.sh --wazuh-dashboard dashboard || true
RUN apt-get update && apt-get -y --no-install-recommends install \
      wazuh-dashboard

RUN NODE_NAME=dashboard && \
      mkdir -p /etc/wazuh-dashboard/certs && \
      tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem && \
      mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem && \
      mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem && \
      chmod 500 /etc/wazuh-dashboard/certs && \
      chmod 400 /etc/wazuh-dashboard/certs/* && \
      chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

#COPY build/wazuh_all_in_one/entrypoint.sh entrypoint.sh
#ENTRYPOINT ["./entrypoint.sh"]
