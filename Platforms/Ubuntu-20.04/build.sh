#!/bin/bash
if [[ -v FUZZEVAL_TAG]]; then
	docker build  -t ${FUZZEVAL_TAG}/platform-20.04:platform .  # always add the platform tag
	echo "================================BUILD COMPLETED============================================"
	echo "Image name: ${FUZZEVAL_TAG}/platform-20.04"
	echo "==========================================================================================="
else
    echo "Please set FUZZEVAL_TAG environment variables before running this script."
	exit 1
fi
