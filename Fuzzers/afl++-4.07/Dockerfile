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

# # Download afl++.
RUN git clone -b dev https://github.com/AFLplusplus/AFLplusplus /aflpp && \
    cd /aflpp && \
    git checkout af8c68a774d0271ae6a2145ac566e1c7024e95d5 || \
    true

# # Build without Python support as we don't need it.
# # Set AFL_NO_X86 to skip flaky tests.
RUN cd /aflpp && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make && \
    cp utils/aflpp_driver/libAFLDriver.a /

# Setting up AFL and varints
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV FUZZERCC=/aflpp/afl-clang-fast
ENV FUZZERCXX=/aflpp/afl-clang-fast++
ENV FUZZERPATH=/aflpp
ENV AFLTYPE=1