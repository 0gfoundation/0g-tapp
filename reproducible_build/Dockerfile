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
# =============================================================================

FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest

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

# Configure Rust installation with Aliyun mirrors
#ENV RUSTUP_UPDATE_ROOT=https://mirrors.aliyun.com/rustup/rustup
#ENV RUSTUP_DIST_SERVER=https://mirrors.aliyun.com/rustup
ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
ENV RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH

# Reproducible build settings
ENV SOURCE_DATE_EPOCH=1609459200
ENV RUSTFLAGS="-C link-arg=-Wl,--build-id=none --remap-path-prefix=/build=/src"
ENV CARGO_BUILD_JOBS=1

# Install Rust toolchain (version specified in rust-toolchain.toml: 1.91.0)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.0 && \
    rustc --version && \
    cargo --version

ENV RUSTUP_UPDATE_ROOT=https://mirrors.aliyun.com/rustup/rustup
ENV RUSTUP_DIST_SERVER=https://mirrors.aliyun.com/rustup

# Set working directory
WORKDIR /build

# Copy project files
COPY . .

# Build both binaries in release mode
# This produces:
# - /build/target/release/tapp-server
# - /build/target/release/tapp-cli
RUN cargo build --release

# Copy build artifacts to output directory
RUN mkdir -p /output && \
    cp /build/target/release/tapp-server /output/ && \
    cp /build/target/release/tapp-cli /output/ && \
    echo "Build completed. Binaries copied to /output:" && \
    ls -lh /output/

# Default command to output the binaries
CMD ["sh", "-c", "cp /output/* /artifacts/ 2>/dev/null || echo 'Build artifacts ready at /output/{tapp-server,tapp-cli}'"]