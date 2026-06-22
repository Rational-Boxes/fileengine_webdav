# Single-stage build on Fedora (matches the project's known-good build env).
# Multi-stage slimming is a later refinement.
FROM fedora:43

RUN dnf -y install \
        gcc-c++ cmake make pkgconf-pkg-config git \
        grpc-devel grpc-plugins protobuf-devel protobuf-compiler \
        poco-devel openldap-devel libpq-devel libpqxx-devel \
    && dnf clean all

WORKDIR /src
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --target webdav_bridge -j"$(nproc)" \
    && install -Dm755 build/webdav_bridge /usr/local/bin/webdav_bridge

WORKDIR /app
EXPOSE 8088
# Config is supplied via environment variables at run time.
ENTRYPOINT ["/usr/local/bin/webdav_bridge"]
