py-libzfs
======

**Python bindings for libzfs**

py-libzfs is a fairly straight-forward set of Python bindings for libzfs for ZFS on Linux and FreeBSD.


**INSTALLATION**

`./configure && make install`

***MacOS and O3X***

Before runnig configure script, clone O3X repository:

`git clone https://github.com/openzfsonosx/zfs.git ../zfs`

**FEATURES:**
- Access to pools, datasets, snapshots, properties, pool disks
- Many others!

**QUICK HOWTO:**

`import libzfs`

Get a list of pools:

`pools = list(libzfs.ZFS().pools)`

Get help:

`help(libzfs)`


