PYTHON ?= /usr/local/bin/python2.7
PREFIX ?= /usr/local

build:
	${PYTHON} setup.py build

clean:
	rm -rf build libzfs.c

install:
	${PYTHON} setup.py install --prefix ${PREFIX}
