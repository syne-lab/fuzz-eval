#!/bin/bash

# written by Cyiu

function confirm
{
    read -p "[?] OK to continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        exit 1
    fi
}

function getCpuThreadCnts
{
    # read cpuinfo to figure out how many
    # logical CPUs are available
    # what a hack
    cat /proc/cpuinfo | grep "model name" | wc -l
}

export ScriptDir="$(dirname "$(realpath "${BASH_SOURCE:-$0}")")"
export IMPL_NAME='axTLS-2.1.5'

