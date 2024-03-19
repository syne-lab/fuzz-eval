FROM  --platform=linux/amd64 ubuntu:20.04
RUN apt-get update -y
RUN apt-get upgrade -y

RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y zip unzip build-essential gdb apt-transport-https curl lsb-release wget software-properties-common tree tmux net-tools iputils-ping git
# Update the package lists and install necessary dependencies

# Set non-interactive mode for package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install initial dependencies
RUN apt-get update -y && apt-get install -y \
    build-essential \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libssl-dev \
    libreadline-dev \
    libffi-dev \
    libsqlite3-dev \
    libbz2-dev \
    liblzma-dev \
    wget \
    curl \
    checkinstall

# Download and extract Python 3.10 source code
RUN wget https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tgz && \
    tar -xzvf Python-3.10.0.tgz && \
    rm Python-3.10.0.tgz

# Build and install Python 3.10
WORKDIR /Python-3.10.0
RUN ./configure && make && make install

# Create the python3.10-dev package
RUN checkinstall --pkgname=python3.10-dev --pkgversion=3.10.0 --provides=python3.10-dev -y

# Install python3.10-dev and ensurepip
RUN apt-get install -y python3.10-dev && \
    python3.10 -m ensurepip

# Clean up
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip3.10 install toml twisted psutil
# Setting up the environment for fuzzing campaign
# we need to mount config to /Config, and Results to /Results
ENV USEDPYTHON=python3.10
ENV CONTROLLER=/Manager/src/controller.py


COPY ./FuzzEvalCommons /FuzzEvalCommons
RUN mv /FuzzEvalCommons/Manager /Manager
RUN mv /FuzzEvalCommons/MorpheusScripts /MorpheusScripts
RUN rm -rf /FuzzEvalCommons

