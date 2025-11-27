#!/bin/bash

# Build the goga application
echo "Building goga application..."
CGO_ENABLED=0 \
go build -trimpath -buildvcs=false \
   -ldflags="-s -w" \
   -o goga ./cmd/goga


if [ $? -eq 0 ]; then
    echo "Build successful! Executable 'goga' created in the current directory."
else
    echo "Build failed."
    exit 1
fi
