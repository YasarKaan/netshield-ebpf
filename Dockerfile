# Multi-stage build for Go NetShield Agent with eBPF compilation
FROM golang:1.25-alpine AS builder

# Install compilation toolchain and kernel/bpf dependencies
RUN apk add --no-cache \
    clang18 \
    llvm18 \
    make \
    gcc \
    musl-dev \
    elfutils-dev \
    libbpf-dev \
    libpcap-dev \
    linux-headers \
    git

# Ensure clang and llvm are aliased/linked correctly
RUN ln -sf /usr/bin/clang-18 /usr/bin/clang && \
    ln -sf /usr/bin/llvm-strip-18 /usr/bin/llvm-strip

WORKDIR /app

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy application source
COPY . .

# Run go generate to compile the XDP program and generate Go loading bindings
RUN go generate ./internal/loader/...

# Build the netshield executable for Linux
RUN CGO_ENABLED=0 GOOS=linux go build -a -o netshield ./cmd/netshield

# Final minimal runtime image
FROM alpine:3.20

# Install runtime utilities often useful for XDP/iptables setups
RUN apk add --no-cache iptables iproute2 tcpdump

WORKDIR /app

# Copy built agent binary and default configuration
COPY --from=builder /app/netshield /app/netshield
COPY config.example.yaml /app/config.yaml

# Expose API and Prometheus ports
EXPOSE 8080
EXPOSE 2112

ENTRYPOINT ["/app/netshield"]
CMD ["--config", "/app/config.yaml"]
