ARG baseimage
FROM $baseimage

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 40976EAF437D05B5
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421

# Install gcc-4.4 & g++-4.4 required by Peach while running on Ubuntu 16.04.
# Install Python2 and Pip2 required by AFLSmart on Ubuntu:20.04.
RUN echo 'deb http://dk.archive.ubuntu.com/ubuntu/ trusty main' >> \
        /etc/apt/sources.list && \
    echo 'deb http://dk.archive.ubuntu.com/ubuntu/ trusty universe' >> \
        /etc/apt/sources.list 
RUN    apt-get update --allow-unauthenticated

RUN    apt-get install --allow-unauthenticated  -y \
    gcc-4.4 \
    g++-4.4 \
    unzip \
    wget 
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt-get install --allow-unauthenticated -y python2 && \
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && \
    python2 get-pip.py && \
    rm -f /usr/bin/python && \
    ln -s /usr/bin/python2.7 /usr/bin/python

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

# Download and compile AFLSmart.
RUN git clone https://github.com/aflsmart/aflsmart /aflsmart && \
    cd /aflsmart && \
    git checkout 4286ae47e0e5d8c412f91aae94ef9d11fb97dfd8 && \
    AFL_NO_X86=1 make

# Setup Peach.
# Set CFLAGS="" so that we don't use the CFLAGS defined in OSS-Fuzz images.
# Use a copy of
# https://sourceforge.net/projects/peachfuzz/files/Peach/3.0/peach-3.0.202-source.zip
# to avoid network flakiness.
RUN cd /aflsmart && \
    wget https://storage.googleapis.com/fuzzbench-files/peach-3.0.202-source.zip && \
    unzip peach-3.0.202-source.zip && \
    patch -p1 < peach-3.0.202.patch && \
    cd peach-3.0.202-source && \
    CC=gcc-4.4 CXX=g++-4.4 CFLAGS="" CXXFLAGS="-std=c++0x" ./waf configure && \
    CC=gcc-4.4 CXX=g++-4.4 CFLAGS="" CXXFLAGS="-std=c++0x" ./waf install

SHELL ["/bin/bash", "-c"] 

ENV AFLSMART=/aflsmart
ENV PATH=$PATH:$AFLSMART:$AFLSMART/peach-3.0.202-source/output/linux_x86_64_debug/bin
ENV AFL_PATH=$AFLSMART
ENV LD_LIBRARY_PATH=/usr/local/lib
# # Setting up AFL and varints
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_NO_FORKSRV=1
ENV AFL_NO_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV FUZZERCC=/aflsmart/afl-clang
ENV FUZZERCXX=/aflsmart/afl-clang++
ENV FUZZERPATH=/aflsmart
ENV AFLTYPE=1

WORKDIR /