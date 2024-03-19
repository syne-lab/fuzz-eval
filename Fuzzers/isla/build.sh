#!/bin/bash
if [[ -v FUZZEVAL_TAG  ]]; then
	docker build --build-arg="baseimage=${FUZZEVAL_TAG}/platform-20.04:platform" -t ${FUZZEVAL_TAG}/isla:fuzzer . # always add the fuzzer tag
	echo "================================BUILD COMPLETED============================================"
	echo "Image name: ${FUZZEVAL_TAG}/isla:fuzzer"
	echo "==========================================================================================="
else
    echo "Please set FUZZEVAL_TAG  environment variables before running this script."
	exit 1
fi