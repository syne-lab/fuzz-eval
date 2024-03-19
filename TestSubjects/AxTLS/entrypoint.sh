#!/bin/sh

# Check if the environment variable exists and is equal to a specific value
if [ -n "$FUZZERPATH" ] && [ -n "$AFLTYPE" ]; then
    export FUZZERCC=${FUZZERPATH}/afl-clang
	export FUZZERCXX=${FUZZERPATH}/afl-clang++
fi
# Execute your main application or command
exec "$@"