FROM ixsystems/zfs:latest

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update

RUN apt-get install -y \
      debhelper-compat \
      dh-python \
      cython3 \
      python3-all-dev \
      python3-setuptools \
      git \
      devscripts
