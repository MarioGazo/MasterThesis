FROM ubuntu:18.04

RUN apt update &&  \
    apt install --yes  \
      build-essential  \
      flex  \
      bison  \
      wget  \
      subversion  \
      m4  \
      python3.7  \
      python3.7-dev  \
      python3-pip \
      python3-setuptools  \
      libgmp-dev  \
      libssl-dev  \
      zlib1g-dev \
      libjpeg-dev  \
      libpng-dev \
      git

RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz &&  \
    tar xvf pbc-0.5.14.tar.gz &&  \
    cd /pbc-0.5.14 &&  \
    ./configure LDFLAGS="-lgmp" &&  \
    make &&  \
    make install &&  \
    ldconfig

RUN git clone https://github.com/JHUISI/charm /charm && \
    cd /charm &&  \
    ./configure.sh --python=/usr/bin/python3.7 &&  \
    make &&  \
    make install && \
    ldconfig && \
    export PYTHONPATH="/charm"

COPY . /app

RUN cd app && make install