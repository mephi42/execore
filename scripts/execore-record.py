"""Usage:

(gdb) source execore-record.py
(gdb) set pagination off
(gdb) execore-record 20000
Saved execore.tar.gz
"""
import inspect
import os
import subprocess
import tarfile
import tempfile

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
    STOP_INSNS = ["stck\t", "stckf\t", "stfle\t", "svc\t"]

    @classmethod
    def fixup_reg(cls, reg, reg_val):
        if reg == "$pswm":
            reg_val &= cls.PSW_MASK_USER
        return reg_val


class X86_64:
    REGS = [
        "$rax",
        "$rbx",
        "$rcx",
        "$rdx",
        "$rsi",
        "$rdi",
        "$rbp",
        "$rsp",
        "$r8",
        "$r9",
        "$r10",
        "$r11",
        "$r12",
        "$r13",
        "$r14",
        "$r15",
        "$rip",
        "$eflags",
        "$cs",
        "$ss",
        "$ds",
        "$es",
        "$fs",
        "$gs",
    ]
    STOP_INSNS = ["syscall ", "rdtsc "]

    @classmethod
    def fixup_reg(cls, reg, reg_val):
        if reg == "$eflags":
            reg_val |= 2
        return reg_val


ARCHES = {
    "s390:64-bit": S390X,
    "i386:x86-64": X86_64,
}


def dump_regs(fp, arch, epoch_insns):
    fp.write("[{}]\n".format(epoch_insns))
    for reg in arch.REGS:
        reg_val = arch.fixup_reg(reg, int(gdb.parse_and_eval(reg)))
        fp.write("{}=0x{:x}\n".format(reg, reg_val))


def record_epoch(trace_path, arch, total_insns, max_insns):
    with open(trace_path, "w") as fp:
        epoch_insns = 0
        while total_insns < max_insns:
            dump_regs(fp, arch, epoch_insns)
            insn = gdb.execute("x/i $pc", to_string=True)
            gdb.execute("si")
            epoch_insns += 1
            total_insns += 1
            if any(stop_insn in insn for stop_insn in arch.STOP_INSNS):
                break
    return total_insns, epoch_insns


class ExecoreRecord(gdb.Command):
    def __init__(self):
        super(ExecoreRecord, self).__init__("execore-record", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        max_insns = int(arg)
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        total_insns = 0
        epoch = 0
        objfile_names = set()
        filename = "execore.tar.gz"
        with tarfile.open(filename, "w:gz", compresslevel=1) as tf:
            while total_insns < max_insns:
                core_path = os.path.join(os.getcwd(), "core.{}".format(epoch))
                gdb.execute("generate-core-file {}".format(core_path))
                tf.add(core_path)
                os.unlink(core_path)
                for objfile in gdb.objfiles():
                    objfile_name = objfile.filename
                    if objfile_name is None or objfile_name.startswith(
                        "system-supplied DSO at 0x"
                    ):
                        continue
                    objfile_names.add(objfile_name)
                trace_path = os.path.join(os.getcwd(), "trace.{}".format(epoch))
                total_insns, _ = record_epoch(trace_path, arch, total_insns, max_insns)
                tf.add(trace_path)
                os.unlink(trace_path)
                epoch += 1
            for objfile_name in objfile_names:
                tf.add(objfile_name)
            print("Saved {}".format(filename))


class ExecoreReplay(gdb.Command):
    def __init__(self):
        super(ExecoreReplay, self).__init__("execore-replay", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        max_insns, epoch = arg.split()
        max_insns = int(max_insns)
        epoch = int(epoch)
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        gdb.execute("set pagination off")
        with open("trace.{}.r".format(epoch), "w") as fp:
            epoch_insns = 0
            while epoch_insns < max_insns:
                dump_regs(fp, arch, epoch_insns)
                gdb.execute("si")
                epoch_insns += 1
        gdb.execute("kill")
        gdb.execute("quit")


class ExecoreRecordReplay(gdb.Command):
    def __init__(self):
        super(ExecoreRecordReplay, self).__init__(
            "execore-record-replay", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        max_insns = int(arg)
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        with tempfile.TemporaryDirectory() as workdir:
            total_insns = 0
            epoch = 0
            while total_insns < max_insns:
                core_path = os.path.join(workdir, "core.{}".format(epoch))
                gdb.execute("generate-core-file {}".format(core_path))
                trace_path = os.path.join(workdir, "trace.{}".format(epoch))
                total_insns, epoch_insns = record_epoch(
                    trace_path, arch, total_insns, max_insns
                )
                subprocess.check_call(
                    [
                        "execore",
                        core_path,
                        "--batch",
                        # https://stackoverflow.com/a/53293924
                        "--eval-command=source {}".format(
                            os.path.realpath(inspect.getfile(lambda: None))
                        ),
                        "--eval-command=execore-replay {} {}".format(
                            epoch_insns, epoch
                        ),
                    ],
                    cwd=workdir,
                )
                replay_path = os.path.join(workdir, "trace.{}.r".format(epoch))
                diff_status = subprocess.call(
                    ["colordiff", "--unified=30", replay_path, trace_path]
                )
                if diff_status != 0:
                    print("\nTraces do not match\n")
                    return
                os.unlink(core_path)
                os.unlink(trace_path)
                os.unlink(replay_path)
                epoch += 1
        print("\nTraces match\n")


ExecoreRecord()
ExecoreReplay()
ExecoreRecordReplay()
