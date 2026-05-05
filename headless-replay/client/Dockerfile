# Headless wine client for replay-net.
# linux/amd64 forced via compose so Apple Silicon hosts get Rosetta translating
# the 64-bit wine process. 32-bit Windows PEs (DXRender.exe, dom_replay.dll,
# version.dll) load INTO that 64-bit wine via wow64 thunks (new-wow64 mode) —
# no separate linux/i386 ELFs, no qemu-i386 in the picture at all.
#
# Why a custom build of wine 10.0?
#   * Debian wine 8 (apt) has incomplete shell32 stubs (SHGetFolderPathW etc.)
#     -> DXRender crashes.
#   * WineHQ wine 11 i386 binaries hit qemu-i386 mmap-alignment assertions on
#     Apple Silicon Docker (dlls/ntdll/unix/virtual.c).
#   * Wine 10+ with --enable-archs=x86_64 only ("new-wow64") gives us complete
#     Win32 stubs while keeping every ELF amd64. Rosetta translates the whole
#     stack; qemu-i386 never runs.
#
# Build takes 30-90min under Rosetta on Apple Silicon. Cached aggressively
# after first build. Final image is ~2GB; expected for full wine + runtime.

# ---------------------------------------------------------------------------
# Stage 1: wine-builder — compile wine 10.0 from source, amd64 only.
# ---------------------------------------------------------------------------
FROM debian:bookworm AS wine-builder

ENV DEBIAN_FRONTEND=noninteractive

# IMPORTANT: do NOT `dpkg --add-architecture i386`. The whole point of the
# new-wow64 build is to stay pure amd64.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential gcc g++ make autoconf bison flex gettext pkg-config \
      git wget ca-certificates xz-utils \
      gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 \
      gcc-mingw-w64-i686 g++-mingw-w64-i686 \
      libfreetype-dev libx11-dev libxext-dev libxrandr-dev libxcursor-dev \
      libxi-dev libxxf86vm-dev libxinerama-dev libxcomposite-dev \
      libgl-dev libgnutls28-dev libpulse-dev libudev-dev libdbus-1-dev \
      libxml2-dev libxslt1-dev libsane-dev libusb-1.0-0-dev libv4l-dev \
      libgphoto2-dev libcapi20-dev libcups2-dev libfontconfig-dev \
      libkrb5-dev libtiff-dev libpcap-dev libmpg123-dev libosmesa6-dev \
      libgsm1-dev liblcms2-dev libldap2-dev libsdl2-dev libunwind-dev \
      libvulkan-dev libvkd3d-dev \
      libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
 && rm -rf /var/lib/apt/lists/*

# Wine 10's --enable-archs=x86_64 requires an x86_64 PE cross-compiler to
# build kernel32.dll / ntdll.dll etc. as Windows PEs. We add both x86_64 and
# i686 mingw toolchains; the i686 one is harmless overhead but lets wine's
# build pick up wow64-thunk PE artifacts if it asks for them.

# libnetapi-dev does not exist on bookworm; wine ./configure will warn and
# fall back to its built-in netapi32 implementation, which is fine.

WORKDIR /build

# Wine 10.0 source tarball.
ARG WINE_TARBALL_URL=https://dl.winehq.org/wine/source/10.0/wine-10.0.tar.xz
RUN wget -q "${WINE_TARBALL_URL}" -O wine-10.0.tar.xz \
 && tar -tf wine-10.0.tar.xz | head -3 \
 && tar -xf wine-10.0.tar.xz \
 && rm wine-10.0.tar.xz

WORKDIR /build/wine-10.0

# --enable-archs=x86_64 is the critical flag: it builds wine in new-wow64 mode
# where a single 64-bit wine process can host 32-bit PEs via wow64 thunks.
# --disable-tests trims build time significantly.
RUN ./configure \
      --prefix=/opt/wine10 \
      --enable-archs=x86_64 \
      --disable-tests

RUN make -j"$(nproc)"

RUN make install


# ---------------------------------------------------------------------------
# Stage 2: runtime — slim image with wine 10.0 + replay client deps.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Pure amd64. Do NOT add i386 architecture.
# python3-opencv from apt would drag in X libs we don't want, so we use
# opencv-python-headless from pip with --break-system-packages (debian
# bookworm marks the system Python as PEP 668 / externally-managed).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libfreetype6 libx11-6 libxext6 libxrandr2 libxcursor1 libxi6 \
      libxxf86vm1 libxinerama1 libxcomposite1 \
      libgl1 libgnutls30 libpulse0 libudev1 libdbus-1-3 \
      libxml2 libxslt1.1 libfontconfig1 \
      libkrb5-3 libgssapi-krb5-2 libtiff6 libpcap0.8 libmpg123-0 \
      libosmesa6 libgsm1 liblcms2-2 libldap-2.5-0 \
      libsdl2-2.0-0 libunwind8 libvulkan1 \
      libgstreamer1.0-0 libgstreamer-plugins-base1.0-0 \
      libgl1-mesa-dri libglx-mesa0 mesa-utils \
      xvfb x11-utils xdotool \
      imagemagick \
      python3 python3-pip python3-numpy \
      netcat-openbsd procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Pull the compiled wine 10 tree from the builder stage.
COPY --from=wine-builder /opt/wine10 /opt/wine10

# Put wine10 on PATH directly. Symlinking individual binaries breaks because
# wine64 looks for wine64-preloader as a sibling — when invoked through a
# symlink in /usr/local/bin, the sibling lookup misses. Instead, prepend
# /opt/wine10/bin to PATH so wine64 (and friends) resolve their dependencies
# in their own dir.
#
# `wine` alias (new-wow64 builds ship only wine64): provide it as a tiny
# wrapper so existing scripts don't need changes.
ENV PATH="/opt/wine10/bin:${PATH}"
RUN printf '#!/bin/sh\nexec /opt/wine10/bin/wine64 "$@"\n' > /usr/local/bin/wine \
 && chmod +x /usr/local/bin/wine

RUN pip3 install --no-cache-dir --break-system-packages opencv-python-headless

WORKDIR /app

COPY dom_driver.py /app/dom_driver.py
COPY entrypoint.sh /app/entrypoint.sh
COPY screenshot-x11.sh /app/screenshot-x11.sh
RUN chmod +x /app/entrypoint.sh /app/screenshot-x11.sh

ENTRYPOINT ["/app/entrypoint.sh"]
