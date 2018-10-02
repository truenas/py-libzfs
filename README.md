py-libzfs
======

**Python bindings for libzfs**

py-libzfs is a fairly straight-forward set of Python bindings for libzfs for FreeBSD.


**INSTALLATION**

`./configure && make install`

**FEATURES:**
- Access to pools, datasets, snapshots, properties, pool disks
- Many others!

**QUICK HOWTO:**

`import libzfs`

Get a list of pools:

`pools = list(libzfs.ZFS().pools)`

Get help:

`help(libzfs)`


