FROM debian:buster

ENV DEBIAN_FRONTEND noninteractive

COPY sources.list /etc/apt/sources.list

RUN apt-get update

RUN apt-get install -y \
      debhelper-compat \
      dh-python \
      cython3 \
      libzfslinux-dev \
      python3-all \
      python3-dev \
      python3-setuptools \
