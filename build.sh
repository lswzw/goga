#!/bin/bash

# Build the goga application
echo "Building goga application..."
go build -o goga ./cmd/goga

if [ $? -eq 0 ]; then
    echo "Build successful! Executable 'goga' created in the current directory."
else
    echo "Build failed."
    exit 1
fi
