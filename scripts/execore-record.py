"""Usage:

(gdb) source execore-record.py
(gdb) set pagination off
(gdb) execore-record 20000
Saved execore.tar.gz
"""
import os
import tarfile

import gdb


class S390X:
    PSW_MASK_CC = 0x0000300000000000
    PSW_MASK_PM = 0x00000F0000000000
    PSW_MASK_64 = 0x0000000100000000
    PSW_MASK_32 = 0x0000000080000000
    PSW_MASK_USER = PSW_MASK_CC | PSW_MASK_PM | PSW_MASK_64 | PSW_MASK_32
    REGS = [
        "$pswm",
        "$pswa",
        "$r0",
        "$r1",
        "$r2",
        "$r3",
        "$r4",
        "$r5",
        "$r6",
        "$r7",
        "$r8",
        "$r9",
        "$r10",
        "$r11",
        "$r12",
        "$r13",
        "$r14",
        "$r15",
    ]
    SYSCALL_INSN = "svc\t"

    @classmethod
    def fixup_reg(cls, reg, reg_val):
        if reg == "$pswm":
            reg_val &= cls.PSW_MASK_USER
        return reg_val


ARCHES = {"s390:64-bit": S390X}


def dump_regs(fp, arch, epoch_insns):
    fp.write("[{}]\n".format(epoch_insns))
    for reg in arch.REGS:
        reg_val = arch.fixup_reg(reg, int(gdb.parse_and_eval(reg)))
        fp.write("{}=0x{:x}\n".format(reg, reg_val))


class ExecoreRecord(gdb.Command):
    def __init__(self):
        super(ExecoreRecord, self).__init__("execore-record", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        max_insns = int(arg)
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        total_insns = 0
        epoch = 0
        objfile_names = set()
        try:
            while total_insns < max_insns:
                gdb.execute("generate-core-file core.{}".format(epoch))
                for objfile in gdb.objfiles():
                    objfile_name = objfile.filename
                    if objfile_name is None:
                        continue
                    if objfile_name.startswith("target:"):
                        # Assume we share the filesystem with the target.
                        objfile_name = objfile_name[7:]
                    objfile_names.add(objfile_name)
                with open("trace.{}".format(epoch), "w") as fp:
                    epoch_insns = 0
                    while total_insns < max_insns:
                        dump_regs(fp, arch, epoch_insns)
                        insn = gdb.execute("x/i $pc", to_string=True)
                        gdb.execute("si")
                        if arch.SYSCALL_INSN in insn:
                            break
                        epoch_insns += 1
                        total_insns += 1
                epoch += 1
        finally:
            filename = "execore.tar.gz"
            with tarfile.open(filename, "w:gz") as tf:
                for objfile_name in objfile_names:
                    tf.add(objfile_name)
                for i in range(epoch + 1):
                    tf.add(os.path.join(os.getcwd(), "core.{}".format(i)))
                    tf.add(os.path.join(os.getcwd(), "trace.{}".format(i)))
            print("Saved {}".format(filename))


class ExecoreReplay(gdb.Command):
    def __init__(self):
        super(ExecoreReplay, self).__init__("execore-replay", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        max_insns, epoch = arg.split()
        max_insns = int(max_insns)
        epoch = int(epoch)
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        with open("trace.{}.r".format(epoch), "w") as fp:
            epoch_insns = 0
            while epoch_insns < max_insns:
                dump_regs(fp, arch, epoch_insns)
                gdb.execute("si")
                epoch_insns += 1


ExecoreRecord()
ExecoreReplay()
