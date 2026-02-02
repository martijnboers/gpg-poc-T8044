FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# --- LAYER 1: HEAVY COMPILATION (Cached) ---
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

# Build using Speedo
RUN make -f build-aux/speedo.mk native

# Setup Env
ENV INSTALL_DIR="/root/build/gnupg-${GNUPG_VER}/PLAY/inst"
ENV PATH="$INSTALL_DIR/bin:$PATH"
ENV LD_LIBRARY_PATH="$INSTALL_DIR/lib:$LD_LIBRARY_PATH"

# Setup Python
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"
RUN pip install asn1crypto

# --- LAYER 2: SCRIPTS (Fast Rebuilds) ---
WORKDIR /root
COPY poc_gen.py /root/poc_gen.py
COPY reproduction.sh /root/reproduction.sh
RUN chmod +x /root/*.sh

CMD ["/bin/bash"]
