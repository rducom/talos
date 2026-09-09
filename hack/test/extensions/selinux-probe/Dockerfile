# syntax=docker/dockerfile:1
# The selinux-probe test extension. Build it with build.sh, which writes an OCI layout the imager reads through
# ociPath; the image is never pushed anywhere.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY probe/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /selinux-probe .

# The rootfs of the main service: a real /etc, and busybox linked dynamically against musl, so that runc creates
# its mount points in a directory the image ships and the loader of a dynamic binary runs under the domain.
# The imager refuses world-writable entries.
FROM alpine:3.22 AS rootfs
RUN rm -rf /tmp /var/tmp /root /home /media /mnt /opt /srv && echo "probe" > /etc/probe.conf

FROM scratch
COPY manifest.yaml /manifest.yaml
COPY --from=rootfs / /rootfs/usr/local/lib/containers/selinux-probe/
COPY --from=build /selinux-probe /rootfs/usr/local/lib/containers/selinux-probe/usr/local/bin/selinux-probe
COPY --from=build /selinux-probe /rootfs/usr/local/lib/containers/selinux-probe-config/usr/local/bin/selinux-probe
# the entrypoint of selinux-probe-host is this binary of the host, bind-mounted with /usr/local/sbin
COPY --from=build /selinux-probe /rootfs/usr/local/sbin/selinux-probe-host
COPY --from=rootfs /etc/probe.conf /rootfs/usr/local/lib/containers/selinux-probe-host/etc/probe.conf
COPY specs/ /rootfs/usr/local/etc/containers/
