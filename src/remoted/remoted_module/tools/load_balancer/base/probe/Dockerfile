FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# The probe runs INSIDE the lab network on purpose: that is the agent's real view, with
# Docker DNS resolving the balancer and node names, so certificate hostname verification
# is exercised exactly as an agent would exercise it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-requests openssl curl ca-certificates jq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /probe
ENTRYPOINT ["sleep", "infinity"]
