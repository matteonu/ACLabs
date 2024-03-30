FROM ubuntu:latest

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    autoconf \
    automake \
    libtool \
    zlib1g-dev \
    libbz2-dev \
    wget

# Install C++ compiler (g++)
RUN apt-get install -y g++

# Set working directory
WORKDIR /hashclash

# Clone HashClash repository
RUN git clone https://github.com/cr-marcstevens/hashclash.git .

# Run build script
RUN ./build.sh
