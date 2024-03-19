#!/bin/bash
if [[ -v FUZZEVAL_TAG  ]]; then
	docker build --build-arg="baseimage=${FUZZEVAL_TAG}/platform-20.04:platform" -t ${FUZZEVAL_TAG}/peach:fuzzer . # always add the fuzzer tag
	echo "================================BUILD COMPLETED============================================"
	echo "Image name: ${FUZZEVAL_TAG}/peach:fuzzer"
	echo "==========================================================================================="
else
    echo "Please set FUZZEVAL_TAG  environment variables before running this script."
	exit 1
fi