"""Usage:

(gdb) source execore-record.py
(gdb) set pagination off
(gdb) execore-record 20000
Saved execore.tar.gz
"""
import argparse
import contextlib
import inspect
import os
import shlex
import subprocess
import tarfile
import uuid

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
        "$f0",
        "$f1",
        "$f2",
        "$f3",
        "$f4",
        "$f5",
        "$f6",
        "$f7",
        "$f8",
        "$f9",
        "$f10",
        "$f11",
        "$f12",
        "$f13",
        "$f14",
        "$f15",
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
    STOP_INSNS = ["syscall ", "rdtsc ", "cpuid "]

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
    try:
        s = "[{}]\n".format(epoch_insns)
        for reg in arch.REGS:
            reg_val = arch.fixup_reg(reg, int(gdb.parse_and_eval(reg)))
            s += "{}=0x{:x}\n".format(reg, reg_val)
    except gdb.error:
        return False
    fp.write(s)
    return True


def record_epoch(trace_path, arch, total_insns, max_insns):
    proceed = True
    with open(trace_path, "w") as fp:
        epoch_insns = 0
        while total_insns < max_insns:
            if not dump_regs(fp, arch, epoch_insns):
                proceed = False
                break
            insn = gdb.execute("x/i $pc", to_string=True)
            gdb.execute("si")
            epoch_insns += 1
            total_insns += 1
            if any(stop_insn in insn for stop_insn in arch.STOP_INSNS):
                break
    return total_insns, epoch_insns, proceed


def iter_objfile_names():
    for objfile in gdb.objfiles():
        objfile_name = objfile.filename
        if objfile_name is None or objfile_name.startswith("system-supplied DSO at 0x"):
            continue
        yield os.path.realpath(objfile_name)


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
                try:
                    gdb.execute("generate-core-file {}".format(core_path))
                except gdb.error:
                    break
                tf.add(core_path)
                os.unlink(core_path)
                objfile_names.update(iter_objfile_names())
                trace_path = os.path.join(os.getcwd(), "trace.{}".format(epoch))
                total_insns, _, proceed = record_epoch(
                    trace_path, arch, total_insns, max_insns
                )
                tf.add(trace_path)
                os.unlink(trace_path)
                epoch += 1
                if not proceed:
                    break
            for objfile_name in objfile_names:
                tf.add(objfile_name)
            print("Saved {}".format(filename))


class ExecoreReplay(gdb.Command):
    def __init__(self):
        super(ExecoreReplay, self).__init__("execore-replay", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parser = argparse.ArgumentParser()
        parser.add_argument("max_insns", type=int)
        parser.add_argument("epoch", type=int)
        args = parser.parse_args(shlex.split(arg))
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        gdb.execute("set pagination off")
        with open("trace.{}.r".format(args.epoch), "w") as fp:
            epoch_insns = 0
            while epoch_insns < args.max_insns:
                dump_regs(fp, arch, epoch_insns)
                gdb.execute("si")
                epoch_insns += 1
        gdb.execute("kill")
        gdb.execute("quit")


def this_file():
    # https://stackoverflow.com/a/53293924
    return os.path.realpath(inspect.getfile(lambda: None))


def check_call(argv):
    print("$ {}".format(shlex.join(argv)))
    subprocess.check_call(argv)


def ssh(remote, *args):
    check_call(["ssh", remote, *args])


def rsync(*args):
    check_call(["rsync", "-avz", *args])


@contextlib.contextmanager
def temporary_remote_directory(remote):
    if remote is None:
        yield None
        return
    try:
        remote_dir = "/tmp/{}".format(uuid.uuid4())
        ssh(remote, "mkdir", "-p", "{}/sysroot".format(remote_dir))
        rsync(this_file(), "{}:{}/".format(remote, remote_dir))
        yield remote_dir
    finally:
        ssh(remote, "rm", "-r", remote_dir)


class ExecoreRecordReplay(gdb.Command):
    def __init__(self):
        super(ExecoreRecordReplay, self).__init__(
            "execore-record-replay", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        parser = argparse.ArgumentParser()
        parser.add_argument("--remote")
        parser.add_argument("--execore", default="execore")
        parser.add_argument("max_insns", type=int)
        args = parser.parse_args(shlex.split(arg))
        arch = ARCHES[gdb.selected_inferior().architecture().name()]

        with temporary_remote_directory(args.remote) as remote_dir:
            total_insns = 0
            epoch = 0
            while total_insns < args.max_insns:
                core_path = "core.{}".format(epoch)
                try:
                    gdb.execute("generate-core-file {}".format(core_path))
                except gdb.error:
                    break
                trace_path = "trace.{}".format(epoch)
                total_insns, epoch_insns, proceed = record_epoch(
                    trace_path, arch, total_insns, args.max_insns
                )

                replay_path = "trace.{}.r".format(epoch)
                if remote_dir is None:
                    check_call(
                        [
                            args.execore,
                            core_path,
                            "--batch",
                            "--eval-command=source {}".format(this_file()),
                            "--eval-command=execore-replay {} {}".format(
                                epoch_insns, epoch
                            ),
                        ],
                    )
                else:
                    rsync(core_path, "{}:{}/core.0".format(args.remote, remote_dir))
                    rsync(
                        "-R",
                        *iter_objfile_names(),
                        "{}:{}/sysroot".format(args.remote, remote_dir)
                    )
                    ssh(
                        args.remote,
                        " && ".join(
                            (
                                shlex.join(["cd", remote_dir]),
                                shlex.join(
                                    [
                                        args.execore,
                                        "--sysroot=sysroot",
                                        "core.0",
                                        "--batch",
                                        "--eval-command=source {}".format(
                                            os.path.basename(this_file())
                                        ),
                                        "--eval-command=execore-replay {} 0".format(
                                            epoch_insns
                                        ),
                                    ]
                                ),
                            )
                        ),
                    )
                    remote_replay_path = "{}/trace.0.r".format(remote_dir)
                    rsync("{}:{}".format(args.remote, remote_replay_path), replay_path)
                    ssh(args.remote, "rm", remote_replay_path)

                try:
                    check_call(["colordiff", "--unified=50", replay_path, trace_path])
                except subprocess.CalledProcessError:
                    print(
                        "\nTraces do not match, check {}, {} and {}\n".format(
                            core_path, trace_path, replay_path
                        )
                    )
                    return
                os.unlink(core_path)
                os.unlink(trace_path)
                os.unlink(replay_path)
                epoch += 1
                if not proceed:
                    break
            print("\nTraces match\n")


ExecoreRecord()
ExecoreReplay()
ExecoreRecordReplay()
