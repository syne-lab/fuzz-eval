ARG baseimage
FROM $baseimage

RUN apt-get update -y
RUN apt-get upgrade -y


# Update and install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    wget \
    git \
    python3

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.0/clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz?raw=true -O clang-14.tar.xz
RUN tar -xvf clang-14.tar.xz
RUN mv clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04 clang-14.0.0
RUN rm clang-14.tar.xz
RUN mv clang-14.0.0 /usr/local
RUN ln -s /usr/local/clang-14.0.0/bin/clang /usr/bin/clang-14
RUN ln -s /usr/local/clang-14.0.0/bin/clang++ /usr/bin/clang++-14
# Set the environment variables for Clang
ENV PATH="/usr/local/clang-14.0.0/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/clang-14.0.0/lib:${LD_LIBRARY_PATH}"



RUN  apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
ENV CXX=clang++-14
ENV CC=clang-14

ENV FUZZERCC=clang-14
ENV FUZZERCXX=clang++-14

WORKDIR /