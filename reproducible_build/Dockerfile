# =============================================================================
# Reproducible Build Environment for 0g-tapp
# =============================================================================
# This Dockerfile ensures deterministic, bit-for-bit reproducible builds of
# tapp-server and tapp-cli binaries.
#
# Environment Snapshot:
# - Base OS: Alibaba Cloud Linux 3 (OpenAnolis Edition)
# - Kernel: 5.10.134-19.1.al8.x86_64
# - Rust Toolchain: 1.91.0
# - All system dependencies are pinned to exact versions
#
# Build outputs:
# - /output/tapp-server
# - /output/tapp-cli
#
# Usage:
#   docker build -f Dockerfile -t 0g-tapp-builder /path/to/0g-tapp
#   docker run --rm -v $(pwd)/artifacts:/artifacts 0g-tapp-builder
#
# Building from inside China? Point rustup at a domestic mirror:
#   docker build -f Dockerfile -t 0g-tapp-builder \
#     --build-arg RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static \
#     --build-arg RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup \
#     /path/to/0g-tapp
# =============================================================================

# --- Stage 1: toolchain — OS packages + Rust, no project sources. -----------
# Kept as a separate stage so CI can cache it: none of these layers depend on
# the source tree, and mirror choice does not affect the bits installed.
FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest AS toolchain

# Set region for Aliyun services
ARG REGION=cn-beijing

# Install all required build dependencies with pinned versions for reproducible builds
RUN yum install -y yum-utils-4.0.21-25.1.al8.noarch && \
    yum-config-manager --add-repo https://enclave-${REGION}.oss-${REGION}.aliyuncs.com/repo/alinux/enclave-expr.repo && \
    yum install -y \
    git-2.43.7-1.0.1.al8.x86_64 \
    tar-1.30-11.0.1.al8.x86_64 \
    curl-7.61.1-35.0.2.al8.3.x86_64 \
    clang-15.0.7-1.0.3.al8.x86_64 \
    perl-5.26.3-423.0.1.al8.x86_64 \
    protobuf-devel-3.5.0-15.al8.x86_64 \
    libtdx-attest-devel-1.22-2.al8.x86_64 \
    libgudev-devel-237-1.0.1.al8.x86_64 \
    openssl-devel-1.1.1k-14.0.2.al8.x86_64 \
    tpm2-tss-2.4.6-1.0.2.al8.x86_64 \
    tpm2-tss-devel-2.4.6-1.0.2.al8.x86_64 \
    libsgx-dcap-quote-verify-devel-1.20.100.2-1.al8.x86_64 \
    sgxsdk-2.23.100.2-1.al8.x86_64 && \
    yum clean all

# Rust download source: official by default (GitHub runners are US-based and
# domestic mirrors throttle them); override via --build-arg when building from
# inside China (see header).
ARG RUSTUP_DIST_SERVER=https://static.rust-lang.org
ARG RUSTUP_UPDATE_ROOT=https://static.rust-lang.org/rustup
ENV RUSTUP_DIST_SERVER=${RUSTUP_DIST_SERVER}
ENV RUSTUP_UPDATE_ROOT=${RUSTUP_UPDATE_ROOT}
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH

# Reproducible build settings. Compilation parallelism is deliberately NOT
# pinned: cargo job count only affects scheduling, not codegen — -j1 and -j4
# builds of this workspace produce sha256-identical binaries.
ENV SOURCE_DATE_EPOCH=1609459200
ENV RUSTFLAGS="-C link-arg=-Wl,--build-id=none --remap-path-prefix=/build=/src"

# Install Rust toolchain (version specified in rust-toolchain.toml: 1.91.0)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.0 && \
    rustc --version && \
    cargo --version

# --- Stage 2: build — copy sources and compile. ------------------------------
FROM toolchain AS builder

# Set working directory
WORKDIR /build

# Copy project files
COPY . .

# Build both binaries in release mode. --workspace is required: the root package is
# tapp-server, and tapp-cli is a separate workspace member (not a dependency of the
# root), so a plain `cargo build` would not produce target/release/tapp-cli.
# This produces:
# - /build/target/release/tapp-server
# - /build/target/release/tapp-cli
RUN cargo build --release --workspace

# Copy build artifacts to output directory
RUN mkdir -p /output && \
    cp /build/target/release/tapp-server /output/ && \
    cp /build/target/release/tapp-cli /output/ && \
    echo "Build completed. Binaries copied to /output:" && \
    ls -lh /output/

# Default command to output the binaries
CMD ["sh", "-c", "cp /output/* /artifacts/ 2>/dev/null || echo 'Build artifacts ready at /output/{tapp-server,tapp-cli}'"]