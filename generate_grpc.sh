#!/bin/bash
# Script to generate gRPC files.
#
# Idempotent on purpose: CMake may re-run this whenever the outputs look stale,
# and a plain `cp` fails with "File exists" if it loses a race for the header
# (it stats, then opens O_EXCL). One codegen target should mean no concurrent
# runs — this is belt and braces so a rebuild can never fail on the copy.
set -euo pipefail

PROTO_DIR="../proto"
PROTO_FILE="$PROTO_DIR/fileservice.proto"
OUTPUT_DIR="./proto/src"
INCLUDE_DIR="./proto/include"

mkdir -p $OUTPUT_DIR
mkdir -p $INCLUDE_DIR

protoc --plugin=protoc-gen-grpc=/usr/bin/grpc_cpp_plugin --grpc_out=$OUTPUT_DIR --cpp_out=$OUTPUT_DIR -I $PROTO_DIR $PROTO_FILE

# Copy header files to include directory
cp -f "$OUTPUT_DIR"/*.h "$INCLUDE_DIR"/