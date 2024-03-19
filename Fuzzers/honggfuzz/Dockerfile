ARG baseimage
FROM $baseimage
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421
RUN apt-get update -y
RUN apt-get upgrade -y


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


# honggfuzz requires libfd and libunwid.
RUN apt-get update -y && \
    apt-get install -y \
    libbfd-dev \
    libunwind-dev \
    libblocksruntime-dev \
    liblzma-dev

# Download honggfuz version 2.3.1 + 0b4cd5b1c4cf26b7e022dc1deb931d9318c054cb
# Set CFLAGS use honggfuzz's defaults except for -mnative which can build CPU
# dependent code that may not work on the machines we actually fuzz on.
# Create an empty object file which will become the FUZZER_LIB lib (since
# honggfuzz doesn't need this when hfuzz-clang(++) is used).
RUN git clone https://github.com/google/honggfuzz.git /honggfuzz && \
    cd /honggfuzz && \
    git checkout oss-fuzz && \
    CFLAGS="-O3 -funroll-loops" make && \
    touch empty_lib.c && \
    cc -c -o empty_lib.o empty_lib.c

WORKDIR /

ENV FUZZERCC=/honggfuzz/hfuzz_cc/hfuzz-clang
ENV FUZZERCXX=/honggfuzz/hfuzz_cc/hfuzz-clang++
