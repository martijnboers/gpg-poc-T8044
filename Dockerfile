FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# --- LAYER 1: HEAVY COMPILATION (Cached) ---
# Install all build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    bzip2 \
    python3 \
    python3-pip \
    python3-venv \
    transfig \
    imagemagick \
    ghostscript \
    patchelf \
    gdb \
    rng-tools \
    pinentry-tty \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/build

# Download GnuPG 2.5.16
ENV GNUPG_VER=2.5.16
RUN wget -q https://gnupg.org/ftp/gcrypt/gnupg/gnupg-${GNUPG_VER}.tar.bz2 && \
    tar xf gnupg-${GNUPG_VER}.tar.bz2

WORKDIR /root/build/gnupg-${GNUPG_VER}

# Build using Speedo (This takes the longest, so we keep it early)
RUN make -f build-aux/speedo.mk native

# Setup Python Environment
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"
RUN pip install asn1crypto

# Setup Global Envars for GnuPG
ENV INSTALL_DIR="/root/build/gnupg-${GNUPG_VER}/PLAY/inst"
ENV PATH="$INSTALL_DIR/bin:$PATH"
ENV LD_LIBRARY_PATH="$INSTALL_DIR/lib:$LD_LIBRARY_PATH"

# --- LAYER 2: VOLATILE SCRIPTS (Fast Rebuilds) ---
# Changes to these files will only trigger a rebuild from this point onwards.

WORKDIR /root
COPY poc_gen.py /root/poc_gen.py
COPY reproduction.sh /root/reproduction.sh
RUN chmod +x /root/reproduction.sh

CMD ["/bin/bash"]
