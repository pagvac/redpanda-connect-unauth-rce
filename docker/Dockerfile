# Self-contained target + PoC for the Redpanda Connect unauth RCE demo.
#
# The vulnerable service and the exploit both run as an unprivileged, non-personal
# user ("demo"), so the `id` payload output shows the service account rather than
# the researcher's workstation username.
#
# The official v4.109.0 linux_arm64 release is downloaded and its sha256 verified
# at BUILD time (nothing large is committed to the repo). The PoC then re-verifies
# the same digest on screen at run time.
#
# Build:  docker build -t rp-connect-rce-demo .
# Record: docker run --rm --hostname target rp-connect-rce-demo
#
# For an x86_64 host, override the two build args with the linux_amd64 asset and
# digest (a single swap; they flow through to the runtime verification too):
#   docker build \
#     --build-arg ASSET=redpanda-connect_4.109.0_linux_amd64.tar.gz \
#     --build-arg SHA256=b73c40bf7ebe6acf690d38aa50c57deec5c754dc08d1a85091679b663eab9f4a \
#     -t rp-connect-rce-demo .
FROM python:3.12-slim

ARG VERSION=4.109.0
ARG ASSET=redpanda-connect_4.109.0_linux_arm64.tar.gz
ARG SHA256=780b29006370366f6aed22672c3ac5702b2f69e9641e789eda3bdc1b33a8f624

# Neutral, non-root service account. The RCE payload runs `id`; this is what it prints.
RUN useradd --create-home --uid 1000 --shell /bin/bash demo

WORKDIR /home/demo/poc

# Download the official release and verify the published checksum at build time.
ADD https://github.com/redpanda-data/connect/releases/download/v${VERSION}/${ASSET} rc.tar.gz
RUN echo "${SHA256}  rc.tar.gz" | sha256sum -c -

# Expose the same asset/digest to the PoC so its runtime verification matches the
# build-time one for whichever architecture was selected above.
ENV RC_ASSET=${ASSET} RC_SHA256=${SHA256}

COPY rp_connect_rce_poc.py .
RUN chown -R demo:demo /home/demo/poc

USER demo
CMD ["python3", "-W", "ignore", "rp_connect_rce_poc.py"]
