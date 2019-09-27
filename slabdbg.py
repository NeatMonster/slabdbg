import gdb


class KmemCacheAllocFinish(gdb.FinishBreakpoint):
    def __init__(self, command, name):
        super(KmemCacheAllocFinish, self).__init__(internal=True)
        self.command = command
        self.name = name

    def stop(self):
        addr = long(self.return_value) & Slab.UNSIGNED_LONG
        return self.command.notify_alloc(self.name, addr)


class KmemCacheAlloc(gdb.Breakpoint):
    def __init__(self, command):
        super(KmemCacheAlloc, self).__init__("kmem_cache_alloc", internal=True)
        self.command = command

    def stop(self):
        slab_cache = gdb.selected_frame().read_var("s")
        name = slab_cache["name"].string()
        if name in self.command.trace_caches or name in self.command.break_caches:
            KmemCacheAllocFinish(self.command, name)


class KmemCacheFree(gdb.Breakpoint):
    def __init__(self, command):
        super(KmemCacheFree, self).__init__("kmem_cache_free", internal=True)
        self.command = command

    def stop(self):
        slab_cache = gdb.selected_frame().read_var("s")
        name = slab_cache["name"].string()
        x = gdb.selected_frame().read_var("x")
        addr = long(x) & Slab.UNSIGNED_LONG
        return self.command.notify_free(name, addr)


class Slab(gdb.Command):
    UNSIGNED_INT = 0xFFFFFFFF
    UNSIGNED_LONG = 0xFFFFFFFFFFFFFFFF
    TYPE_CODE_HAS_FIELDS = [gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION]

    def __init__(self):
        super(Slab, self).__init__("slab", gdb.COMMAND_USER)
        self.per_cpu_offset = gdb.lookup_global_symbol("__per_cpu_offset").value()
        self.memstart_addr = gdb.lookup_global_symbol("memstart_addr").value()

        self.breakpoints = [KmemCacheAlloc(self), KmemCacheFree(self)]
        self.trace_caches = []
        self.break_caches = []
        self.update_breakpoints()

    def update_breakpoints(self):
        enabled = bool(self.trace_caches) or bool(self.break_caches)
        for breakpoint in self.breakpoints:
            breakpoint.enabled = enabled

    def notify_alloc(self, name, addr):
        if name in self.trace_caches:
            print("Object 0x%x allocated in %s" % (addr, name))
        return name in self.break_caches

    def notify_free(self, name, addr):
        if name in self.trace_caches:
            print("Object 0x%x freed in %s" % (addr, name))
        return name in self.break_caches

    @staticmethod
    def get_field_bitpos(type, member):
        for field in type.fields():
            if field.name == member:
                return field.bitpos
            if field.type.code in Slab.TYPE_CODE_HAS_FIELDS:
                bitpos = Slab.get_field_bitpos(field.type, member)
                if bitpos is not None:
                    return field.bitpos + bitpos
        return None

    @staticmethod
    def for_each_entry(type, head, member):
        void_p = gdb.lookup_type("void").pointer()
        offset = Slab.get_field_bitpos(type, member) // 8

        pos = head["next"].dereference()
        while pos.address != head.address:
            entry = gdb.Value(pos.address.cast(void_p) - offset)
            yield entry.cast(type.pointer()).dereference()
            pos = pos["next"].dereference()

    @staticmethod
    def iter_slab_caches():
        kmem_cache = gdb.lookup_type("struct kmem_cache")
        slab_caches = gdb.lookup_global_symbol("slab_caches").value()
        return Slab.for_each_entry(kmem_cache, slab_caches, "list")

    @staticmethod
    def find_slab_cache(name):
        for slab_cache in Slab.iter_slab_caches():
            if slab_cache["name"].string() == name:
                return slab_cache
        return None

    @staticmethod
    def get_cache_names():
        for slab_cache in Slab.iter_slab_caches():
            yield slab_cache["name"].string()

    @staticmethod
    def get_flags_list(flags):
        flags_list = []
        if flags & 0x00000100:
            flags_list.append("SLAB_DEBUG_FREE")
        if flags & 0x00000400:
            flags_list.append("SLAB_RED_ZONE")
        if flags & 0x00000800:
            flags_list.append("SLAB_POISON")
        if flags & 0x00002000:
            flags_list.append("SLAB_HWCACHE_ALIGN")
        if flags & 0x00004000:
            flags_list.append("SLAB_CACHE_DMA")
        if flags & 0x00010000:
            flags_list.append("SLAB_STORE_USER")
        if flags & 0x00020000:
            flags_list.append("SLAB_RECLAIM_ACCOUNT")
        if flags & 0x00040000:
            flags_list.append("SLAB_PANIC")
        if flags & 0x00080000:
            flags_list.append("SLAB_DESTROY_BY_RCU")
        if flags & 0x00100000:
            flags_list.append("SLAB_MEM_SPREAD")
        if flags & 0x00200000:
            flags_list.append("SLAB_TRACE")
        if flags & 0x00400000:
            flags_list.append("SLAB_DEBUG_OBJECTS")
        if flags & 0x00800000:
            flags_list.append("SLAB_NOLEAKTRACE")
        if flags & 0x01000000:
            flags_list.append("SLAB_NOTRACK")
        if flags & 0x02000000:
            flags_list.append("SLAB_FAILSLAB")
        return flags_list

    def get_slab_cache_cpu(self, slab_cache):
        void = gdb.lookup_type("void").pointer()
        kmem_cache_cpu = gdb.lookup_type("struct kmem_cache_cpu")
        current_cpu = gdb.selected_thread().num - 1
        cpu_offset = self.per_cpu_offset[current_cpu]
        cpu_slab = gdb.Value(slab_cache["cpu_slab"].cast(void) + cpu_offset)
        return cpu_slab.cast(kmem_cache_cpu.pointer()).dereference()

    def page_addr(self, page):
        memstart_addr = long(self.memstart_addr) & Slab.UNSIGNED_LONG
        addr = (memstart_addr >> 6) & Slab.UNSIGNED_LONG
        addr = (addr & 0xFFFFFFFFFF000000) & Slab.UNSIGNED_LONG
        addr = (0xFFFFFFBDC0000000 - addr) & Slab.UNSIGNED_LONG
        addr = (page - addr) & Slab.UNSIGNED_LONG
        addr = (addr >> 6 << 0xC) & Slab.UNSIGNED_LONG
        addr = (addr - memstart_addr) & Slab.UNSIGNED_LONG
        return addr | 0xFFFFFFC000000000

    @staticmethod
    def walk_freelist(slab_cache, freelist):
        void = gdb.lookup_type("void").pointer().pointer()
        offset = int(slab_cache["offset"])
        while freelist:
            address = long(freelist) & Slab.UNSIGNED_LONG
            yield address
            freelist = gdb.Value(address + offset).cast(void).dereference()

    def format_slab(self, slab, indent, freelist=None):
        address = long(slab.address) & Slab.UNSIGNED_LONG
        s = "Slab @ 0x%x:" % address + "\n"
        objects = int(slab["objects"]) & Slab.UNSIGNED_INT
        s += " " * (indent + 4) + ("Objects: %d\n" % objects)
        inuse = int(slab["inuse"]) & Slab.UNSIGNED_INT
        s += " " * (indent + 4) + ("In-Use: %d\n" % inuse)
        frozen = int(slab["frozen"])
        s += " " * (indent + 4) + ("Frozen: %d\n" % frozen)
        fp = long(slab["freelist"]) & Slab.UNSIGNED_LONG
        s += " " * (indent + 4) + ("Freelist: 0x%x\n" % fp)

        page_addr = self.page_addr(address)
        s += " " * (indent + 4) + ("Page @ 0x%x:\n" % page_addr)
        slab_cache = slab["slab_cache"]
        size = int(slab_cache["size"])
        if freelist is None:
            freelist = slab["freelist"]
        freelist = list(Slab.walk_freelist(slab_cache, freelist))
        for address in range(page_addr, page_addr + objects * size, size):
            if address in freelist:
                s += " " * (indent + 8) + (" - Object (free) @ 0x%x\n" % address)
            else:
                s += " " * (indent + 8) + (" - Object (inuse) @ 0x%x\n" % address)
        return s.rstrip("\n")

    def invoke(self, arg, from_tty):
        if arg:
            args = arg.split()
            if args[0] == "help":
                self.invoke_help()
                return
            elif args[0] == "list" and len(args) == 1:
                self.invoke_list()
                return
            elif args[0] == "info" and len(args) == 2:
                self.invoke_info(args[1])
                return
            elif args[0] == "trace" and len(args) == 2:
                self.invoke_trace(args[1])
                return
            elif args[0] == "break" and len(args) == 2:
                self.invoke_break(args[1])
                return
            elif args[0] == "print" and len(args) == 2:
                self.invoke_print(args[1])
                return
        self.invoke_help()

    def complete(self, text, word):
        word, words = "", []
        args = text.split(" ")

        if len(args) < 2:
            word = args[0]
            words = ["list", "info", "trace", "break", "print"]

        elif len(args) == 2:
            if args[0] in ["info", "trace", "break"]:
                word = args[1]
                words = list(Slab.get_cache_names())

        return [s for s in words if s.startswith(word)]

    def invoke_help(self):
        print("Usage:")
        print("  slab list - Display simple information about all slab caches")
        print("  slab info <name> - Display extended information about a slab cache")
        print("  slab trace <name> - Start/stop tracing allocations for a slab cache")
        print("  slab break <name> - Start/stop breaking on allocation for a slab cache")
        print("  slab print <slab> - Print the objects contained in a slab")

    def invoke_list(self):
        print("name                    objs inuse slabs size obj_size objs_per_slab pages_per_slab")
        for slab_cache in self.iter_slab_caches():
            name = slab_cache["name"].string()
            size = int(slab_cache["size"])
            obj_size = int(slab_cache["object_size"])
            objs, inuse, slabs = 0, 0, 0

            cpu_cache = self.get_slab_cache_cpu(slab_cache)
            if cpu_cache["page"]:
                objs = inuse = int(cpu_cache["page"]["objects"]) & Slab.UNSIGNED_INT
                if cpu_cache["freelist"]:
                    inuse -= len(list(Slab.walk_freelist(slab_cache, cpu_cache["freelist"])))
                slabs += 1

            if cpu_cache["partial"]:
                slab = cpu_cache["partial"]
                while slab:
                    objs += int(slab["objects"]) & Slab.UNSIGNED_INT
                    inuse += int(slab["inuse"]) & Slab.UNSIGNED_INT
                    slabs += 1
                    slab = slab.dereference()["next"]

            node_cache = slab_cache["node"].dereference().dereference()
            page = gdb.lookup_type("struct page")
            for slab in Slab.for_each_entry(page, node_cache["partial"], "lru"):
                objs += int(slab["objects"]) & Slab.UNSIGNED_INT
                inuse += int(slab["inuse"]) & Slab.UNSIGNED_INT
                slabs += 1

            if slabs:
                objs_per_slab = objs // slabs
                assert objs_per_slab * slabs == objs
                pages_per_slab = 1 + size * objs_per_slab // 4096
            else:
                objs_per_slab = pages_per_slab = -1

            print(
                "%-23s %4d %5d %5d %4d %8d %13d %14d"
                % (name, objs, inuse, slabs, size, obj_size, objs_per_slab, pages_per_slab)
            )

    def invoke_info(self, name):
        slab_cache = Slab.find_slab_cache(name)
        if slab_cache is None:
            print("Slab cache %s not found" % name)
            return

        address = long(slab_cache.address) & Slab.UNSIGNED_LONG
        print("Slab Cache @ 0x%x:" % address)
        name = slab_cache["name"].string()
        print("    Name: %s" % name)
        flags = long(slab_cache["flags"]) & Slab.UNSIGNED_LONG
        flags_list = Slab.get_flags_list(flags)
        if flags_list:
            print("    Flags: %s" % " | ".join(flags_list))
        else:
            print("    Flags: (none)")
        offset = int(slab_cache["offset"])
        print("    Offset: %d" % offset)
        size = int(slab_cache["size"])
        print("    Size: %d" % size)
        object_size = int(slab_cache["object_size"])
        print("    Object Size: %d" % object_size)

        cpu_cache = self.get_slab_cache_cpu(slab_cache)
        address = long(cpu_cache.address) & Slab.UNSIGNED_LONG
        print("    Per-CPU Data @ 0x%x:" % address)
        freelist = long(cpu_cache["freelist"]) & Slab.UNSIGNED_LONG
        print("        Freelist: 0x%x" % freelist)
        if cpu_cache["page"]:
            slab = cpu_cache["page"].dereference()
            print("        Page: " + self.format_slab(slab, 8, cpu_cache["freelist"]))
        else:
            print("        Page: (none)")
        if cpu_cache["partial"]:
            print("        Partial List:")
            slab = cpu_cache["partial"]
            while slab:
                print("            - " + self.format_slab(slab.dereference(), 14, cpu_cache["freelist"]))
                slab = slab.dereference()["next"]
        else:
            print("        Partial List: (none)")

        node_cache = slab_cache["node"].dereference().dereference()
        address = long(node_cache.address) & Slab.UNSIGNED_LONG
        print("    Per-Node Data @ 0x%x:" % address)
        page = gdb.lookup_type("struct page")
        partials = list(Slab.for_each_entry(page, node_cache["partial"], "lru"))
        if partials:
            print("        Partial List:")
            for slab in partials:
                print("            - " + self.format_slab(slab, 14))
        else:
            print("        Partial List: (none)")
        fulls = list(Slab.for_each_entry(page, node_cache["full"], "lru"))
        if fulls:
            print("        Full List:")
            for slab in fulls:
                print("            - " + self.format_slab(slab, 14))
        else:
            print("        Full List: (none)")

    def invoke_trace(self, name):
        slab_cache = Slab.find_slab_cache(name)
        if slab_cache is None:
            print("Slab cache %s not found" % name)
            return

        if name in self.trace_caches:
            print("Stopped tracing slab cache")
            self.trace_caches.remove(name)
        else:
            print("Started tracing slab cache")
            self.trace_caches.append(name)
        self.update_breakpoints()

    def invoke_break(self, name):
        slab_cache = Slab.find_slab_cache(name)
        if slab_cache is None:
            print("Slab cache %s not found" % name)
            return

        if name in self.break_caches:
            print("Stopped breaking on slab cache")
            self.break_caches.remove(name)
        else:
            print("Started breaking on slab cache")
            self.break_caches.append(name)
        self.update_breakpoints()

    def invoke_print(self, slab):
        try:
            slab = int(slab, 0)
        except Exception:
            print("Failed to parse argument")
            return

        page = gdb.lookup_type("struct page")
        slab = gdb.Value(slab).cast(page.pointer()).dereference()
        print(self.format_slab(slab, 0))


if __name__ == "__main__":
    Slab()
