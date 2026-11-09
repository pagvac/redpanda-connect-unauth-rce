# Containerized demo target

Runs the vulnerable Redpanda Connect service **and** the PoC inside a throwaway
container as an unprivileged, non-personal user (`demo`), so the `id` payload
output shows `uid=1000(demo)` instead of your workstation username. Nothing about
your host leaks into the recording.

The official v4.109.0 `linux_arm64` release is downloaded and its published sha256
verified at build time; the PoC re-verifies the same digest on screen at run time.

## Build once (off camera)

```
docker build -t rp-connect-rce-demo .
```

## Record this one command

```
docker run --rm --hostname target rp-connect-rce-demo
```

Expected output ends with the command execution proof, twice (blind file marker and
in-band HTTP response body):

```
uid=1000(demo) gid=1000(demo) groups=1000(demo)
```

`--rm` discards the container after each run and `--hostname target` keeps your real
machine name out of frame in case any payload ever prints `hostname`/`uname`.

## Other architectures

The build defaults to `linux_arm64`. For an x86_64 host, override the two build args
with the `linux_amd64` asset and its published digest. This single swap covers both
the build-time checksum and the PoC's runtime verification, because the Dockerfile
passes the same values into the container as `RC_ASSET` / `RC_SHA256`:

```
docker build \
  --build-arg ASSET=redpanda-connect_4.109.0_linux_amd64.tar.gz \
  --build-arg SHA256=b73c40bf7ebe6acf690d38aa50c57deec5c754dc08d1a85091679b663eab9f4a \
  -t rp-connect-rce-demo .
```

Published digests for v4.109.0:

- `linux_arm64` (default): `780b29006370366f6aed22672c3ac5702b2f69e9641e789eda3bdc1b33a8f624`
- `linux_amd64`: `b73c40bf7ebe6acf690d38aa50c57deec5c754dc08d1a85091679b663eab9f4a`

## Notes

- `rp_connect_rce_poc.py` here is identical to the parent-directory PoC except that
  the release asset and expected digest default to `linux_arm64` and are overridable
  via the `RC_ASSET` / `RC_SHA256` environment variables.
