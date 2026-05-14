FROM ubuntu:22.04 AS builder

ARG COVERITY_HOME="/opt/cov-analysis"

COPY coverity_tool.tgz /tmp/

RUN mkdir -p $COVERITY_HOME && \
    tar -zxf /tmp/coverity_tool.tgz -C $COVERITY_HOME --strip-components=1

FROM ubuntu:22.04

ARG COVERITY_HOME="/opt/cov-analysis"
ENV PATH="$COVERITY_HOME/bin:$PATH"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl make cmake gcc g++ file && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder $COVERITY_HOME $COVERITY_HOME

ENTRYPOINT ["cov-build", "--dir", "cov-int"]
