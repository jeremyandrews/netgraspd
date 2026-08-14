# netgraspd, built in one stage and shipped in another.
#
# Two things about running a packet capture in a container are not obvious and
# are not optional:
#
#   --network=host    A container on a bridge network sees the bridge, not your
#                     LAN. Every broadcast and multicast frame netgraspd exists
#                     to read is on the host's segment, so without host
#                     networking the daemon starts, captures nothing, and looks
#                     like it is working.
#
#   --cap-add=NET_RAW Opening a capture handle needs it. Nothing else in this
#                     daemon does, so drop the rest.
#
# Together, for the capture command:
#
#   docker run --network=host --cap-drop=ALL --cap-add=NET_RAW --user root \
#              -v /etc/netgrasp.toml:/etc/netgrasp.toml:ro \
#              -v netgraspd-state:/var/lib/netgraspd \
#              ghcr.io/jeremyandrews/netgraspd:latest run --config /etc/netgrasp.toml
#
# Every other command needs none of that and runs as the image's unprivileged
# user by default. See the note above `USER` for why the binary is not setcap-ed.
#
# The image is multi-architecture by construction: it pins no architecture and
# builds whatever the platform it is built for needs, so `--platform
# linux/arm64` produces the Raspberry Pi image.

# ---------------------------------------------------------------------------
# Build.
# ---------------------------------------------------------------------------
FROM rust:1.90-trixie AS build

# libpcap to link against, and pkg-config to find it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first, so that editing the daemon does not rebuild the world.
# The dummy sources are replaced below; touching main.rs is what makes cargo
# notice.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src

COPY . .
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked

# ---------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------
FROM debian:trixie-slim

# libpcap at runtime, and ca-certificates because `update-fingerprints` and the
# UniFi enricher speak TLS. The slim image has neither.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcap0.8 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --shell /usr/sbin/nologin netgraspd \
 && mkdir -p /var/lib/netgraspd \
 && chown netgraspd:netgraspd /var/lib/netgraspd

COPY --from=build /src/target/release/netgraspd /usr/local/bin/netgraspd
COPY --from=build /src/netgrasp.toml.example /usr/share/netgraspd/netgrasp.toml.example

# Deliberately no `setcap` on the binary, which is the obvious thing to do and
# is wrong here.
#
# A file with capabilities cannot be exec'd at all unless those capabilities are
# in the process's bounding set, so a `setcap`-ed binary in this image turns
# `docker run netgraspd stats` into "exec: operation not permitted" for anybody
# who has not also passed --cap-add=NET_RAW. Every read-only command would need
# the capability it does not use.
#
# So the default user is unprivileged and the binary is plain: `stats`,
# `people`, `maintain` and `devices` all work with no capabilities at all.
# **Capture is the exception and needs both --cap-add=NET_RAW and --user root**,
# because Docker adds a capability to the bounding set but cannot put it in a
# non-root process's permitted set without file capabilities. Root inside a
# container that has dropped every capability but NET_RAW has no more privilege
# than the file-capability arrangement would have given it.
#
#   docker run --network=host --cap-drop=ALL --cap-add=NET_RAW --user root \
#              netgraspd:latest run --no-table
#
# docker-compose.yml does exactly that for the daemon and nothing special for
# anything else.

USER netgraspd
WORKDIR /var/lib/netgraspd
VOLUME ["/var/lib/netgraspd"]

# No HEALTHCHECK that hits the network: this daemon has no listening port by
# design. `netgraspd stats` is the health check, and it is a command an operator
# runs rather than something that should run every thirty seconds forever.

ENTRYPOINT ["/usr/local/bin/netgraspd"]
CMD ["run", "--no-table"]
