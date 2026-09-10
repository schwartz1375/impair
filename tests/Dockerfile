# SPDX-License-Identifier: GPL-3.0-only
# Minimum-Go compatibility image for local tests, not a deployment image.
ARG GO_IMAGE=golang:1.22-bookworm
FROM ${GO_IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iproute2 nftables iputils-ping ethtool iperf3 python3 tcpdump
WORKDIR /src
CMD ["make", "test"]
