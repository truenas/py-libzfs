FROM debian:testing

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

# We will build openzfs now to get latest changes
RUN mkdir /zfs-package
RUN git clone --depth=1 https://github.com/truenas/zfs -b truenas/zfs-2.0-release /zfs-package/zfs

WORKDIR /zfs-package/zfs
RUN cp -a /zfs-package/zfs/contrib/truenas /zfs-package/zfs/debian
RUN mk-build-deps --build-dep
RUN apt install -y ./*.deb
RUN dch -b -M --force-distribution --distribution bullseye-truenas-unstable 'Tagged from py-libzfs'
RUN debuild -us -uc -b
RUN apt-get install -y ../*.deb
