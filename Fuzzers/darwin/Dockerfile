# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
ARG baseimage
FROM $baseimage
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421
RUN apt-get update -y
RUN apt-get upgrade -y


RUN apt-get update && \
    apt-get install -y \
        build-essential \
        clang \
        git \
        libtool \
        libtool-bin \
        python \
        wget \
        zlib1g-dev


RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
# Install AFLSmart dependencies.
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    apt-utils \
    libc6-dev-i386 \
    g++-multilib \
    mono-complete \
    software-properties-common
    
# Add the LLVM APT repository and install Clang-14
RUN apt-get update && apt-get install -y \
    software-properties-common && \
    add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-14 main" && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    apt-get update && apt-get install -y \
    clang-14

# Clean up the package lists and repository information
RUN apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove


RUN  apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 14 and install the distro default if that fails
RUN  apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 ||  apt-get install -y lld llvm llvm-dev clang
RUN  apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
RUN  apt-get install -y ninja-build clang
ENV CXX=clang++-14
ENV CC=clang-14

# Download and compile AFL v2.57b.
# Set AFL_NO_X86 to skip flaky tests.
RUN git clone \
        --depth 1 \
        https://github.com/TUDA-SSL/DARWIN/ /darwin
RUN cd /darwin && CFLAGS= CXXFLAGS= AFL_NO_X86=1 make

# Setting up AFL and varints
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_NO_FORKSRV=1
ENV AFL_NO_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV FUZZERCC=/darwin/afl-clang
ENV FUZZERCXX=/darwin/afl-clang++
ENV FUZZERPATH=/darwin
ENV AFLTYPE=1
WORKDIR /