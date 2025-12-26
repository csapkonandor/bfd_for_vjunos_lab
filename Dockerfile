## ============================
## 1. Build stage
# ============================
#FROM debian:stable-slim AS build
#
# # Build type: Release (default) or Debug 
#ARG BUILD_TYPE=Release
#
#RUN apt-get update && \
#    apt-get install -y --no-install-recommends \
#        build-essential \
#        cmake \
#        pkg-config \
#        git \
#        && rm -rf /var/lib/apt/lists/*

#WORKDIR /src

# Copy project
#COPY . .

# Build
#RUN mkdir -p build && cd build && \
#    cmake .. -DCMAKE_BUILD_TYPE=${BUILD_TYPE} && \
#    make -j$(nproc)


# ============================
# 2. Runtime stage
# ============================
FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
	gdbserver \
        net-tools \
	procps \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from build stage
#COPY --from=build /src/build/bfd_initiator /app/
#COPY --from=build /src/build/bfd_responder /app/
#COPY --from=build /src/build/bfdctl /app/
COPY ./build/bfd_initiator /app/
COPY ./build/bfd_responder /app/
COPY ./build/bfdctl /app/


# Expose BFD ports
# single-hop BFD
EXPOSE 3784/udp

# multihop BFD
EXPOSE 4784/udp

# echo (single-hop only)
EXPOSE 6784/udp

# Default command (can be overridden)
CMD ["/bin/bash"]
