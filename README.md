# SlabDbg

GDB plug-in that makes it easier to develop Linux kernel exploits targeting the SLUB allocator. It displays the content of slab caches and allows to set breakpoints on allocation/free operations.

## Installation

No installation, simply typing `source slabdbg.py` should be enough to get you started.

## Usage

```
Usage:
  slab list - Display simple information about all slab caches
  slab info <name> - Display extended information about a slab cache
  slab trace <name> - Start/stop tracing allocations for a slab cache
  slab break <name> - Start/stop breaking on allocation for a slab cache
  slab watch <name> - Start/stop watching full-slabs for a slab cache
  slab print <slab> - Print the objects contained in a slab
```

## Examples

### List all slab caches

```
(gdb) slab list
name                    objs inuse slabs size obj_size objs_per_slab pages_per_slab
ext4_groupinfo_4k         28    28     1  144      144            28              1
ip6_dst_cache             10     1     1  384      384            10              1
UDPLITEv6                  0     0     0 1088     1072            -1             -1
UDPv6                     15     0     1 1088     1072            15              4
tw_sock_TCPv6              0     0     0  272      264            -1             -1
request_sock_TCPv6         0     0     0  328      320            -1             -1
TCPv6                      0     0     0 2048     2032            -1             -1
nf_conntrack_1             0     0     0  320      312            -1             -1
ashmem_area_cache         13     3     1  312      312            13              1
---Type <return> to continue, or q <return> to quit---q
```

### Print info about a slab cache

```
(gdb) slab info kmalloc-8192
Slab Cache @ 0xffffffc03a801800:
    Name: kmalloc-8192
    Flags: (none)
    Offset: 0
    Size: 8192
    Object Size: 8192
    Per-CPU Data @ 0xffffffc03ffe0020:
        Freelist: 0xffffffc01b12a000
        Page: Slab @ 0xffffffbdc06c4a00:
            Objects: 4
            In-Use: 4
            Frozen: 1
            Freelist: 0x0
            Page @ 0xffffffc01b128000:
                 - Object (inuse) @ 0xffffffc01b128000
                 - Object (free) @ 0xffffffc01b12a000
                 - Object (inuse) @ 0xffffffc01b12c000
                 - Object (inuse) @ 0xffffffc01b12e000
        Partial List:
            - Slab @ 0xffffffbdc0e18800:
                  Objects: 4
                  In-Use: 0
                  Frozen: 1
                  Freelist: 0xffffffc038622000
                  Page @ 0xffffffc038620000:
                       - Object (inuse) @ 0xffffffc038620000
                       - Object (inuse) @ 0xffffffc038622000
                       - Object (inuse) @ 0xffffffc038624000
                       - Object (inuse) @ 0xffffffc038626000
            - Slab @ 0xffffffbdc0e3a800:
                  Objects: 4
                  In-Use: 2
                  Frozen: 1
                  Freelist: 0xffffffc038ea2000
                  Page @ 0xffffffc038ea0000:
                       - Object (inuse) @ 0xffffffc038ea0000
                       - Object (inuse) @ 0xffffffc038ea2000
                       - Object (inuse) @ 0xffffffc038ea4000
                       - Object (inuse) @ 0xffffffc038ea6000
            - Slab @ 0xffffffbdc0e3ca00:
                  Objects: 4
                  In-Use: 2
                  Frozen: 1
                  Freelist: 0xffffffc038f2e000
                  Page @ 0xffffffc038f28000:
                       - Object (inuse) @ 0xffffffc038f28000
                       - Object (inuse) @ 0xffffffc038f2a000
                       - Object (inuse) @ 0xffffffc038f2c000
                       - Object (inuse) @ 0xffffffc038f2e000
    Per-Node Data @ 0xffffffc03a800c80:
        Partial List: (none)
        Full List: (none)
```

### Trace alloc/free for a slab cache

```
(gdb) slab trace kmalloc-128
Started tracing slab cache
(gdb) c
Continuing.
Object 0xffffffc038503c00 allocated in kmalloc-128
Object 0xffffffc01d5c7d00 allocated in kmalloc-128
Object 0xffffffc01d5c7280 allocated in kmalloc-128
Object 0xffffffc038fee780 freed in kmalloc-128
Object 0xffffffc038fee700 freed in kmalloc-128
Object 0xffffffc038fee000 freed in kmalloc-128
Object 0xffffffc03853f000 allocated in kmalloc-128
Object 0xffffffc01d5c7c80 allocated in kmalloc-128
Object 0xffffffc038117200 allocated in kmalloc-128
```

### Break on alloc/free for a slab cache

```
(gdb) slab break kmalloc-128
Started breaking on slab cache
(gdb) c
Continuing.

Breakpoint -2, kmem_cache_free (s=0xffffffc03a801e00, x=0xffffffc038503c00) at mm/slub.c:2877
2877	{
```

### Print the content of a slab

```
(gdb) slab print 0xffffffbdc0e3ca00
Slab @ 0xffffffbdc0e3ca00:
    Objects: 4
    In-Use: 2
    Frozen: 1
    Freelist: 0xffffffc038f2e000
    Page @ 0xffffffc038f28000:
         - Object (inuse) @ 0xffffffc038f28000
         - Object (inuse) @ 0xffffffc038f2a000
         - Object (free) @ 0xffffffc038f2c000
         - Object (free) @ 0xffffffc038f2e000
```

### Watch the full slabs of a slab cache

```
(gdb) slab watch kmalloc-8192
Started watching slab cache 'kmalloc-8192'
(gdb) c
Continuing.
(gdb) slab info kmalloc-8192
Slab Cache @ 0xffffffc03a801800:
    Name: kmalloc-8192
    Flags: (none)
    Offset: 0
    Size: 8192
    Object Size: 8192
    Per-CPU Data @ 0xffffffc03ffe0020:
        Freelist: 0xffffffc038d0a000
        Page: Slab @ 0xffffffbdc0e34200:
            Objects: 4
            In-Use: 4
            Frozen: 1
            Freelist: 0x0
            Page @ 0xffffffc038d08000:
                 - Object (inuse) @ 0xffffffc038d08000
                 - Object (free) @ 0xffffffc038d0a000
                 - Object (free) @ 0xffffffc038d0c000
                 - Object (free) @ 0xffffffc038d0e000
        Partial List: (none)
    Per-Node Data @ 0xffffffc03a800c80:
        Partial List: (none)
        Full List:
            - Slab @ 0xffffffbdc0e6d000:
                  Objects: 4
                  In-Use: 4
                  Frozen: 0
                  Freelist: 0x0
                  Page @ 0xffffffc039b40000:
                       - Object (inuse) @ 0xffffffc039b40000
                       - Object (inuse) @ 0xffffffc039b42000
                       - Object (inuse) @ 0xffffffc039b44000
                       - Object (inuse) @ 0xffffffc039b46000
---Type <return> to continue, or q <return> to quit---q
```

## Disclaimer

I have only tested it on the official Android emulator running an `arm64` system image and a manually compiled kernel.
