py-libzfs
======

> [!WARNING]
> **Deprecation Notice:** This repository is deprecated. TrueNAS is transitioning its Python ZFS bindings to
> [github.com/truenas/truenas_pylibzfs](https://github.com/truenas/truenas_pylibzfs). Note that the new
> repository is Linux-only and targets the ZFS version distributed with TrueNAS. This repository will no
> longer receive updates.

**Python bindings for libzfs**

py-libzfs is a fairly straight-forward set of Python bindings for libzfs for ZFS on Linux and FreeBSD.


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


