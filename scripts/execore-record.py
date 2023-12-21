"""Usage:

(gdb) source execore-record.py
(gdb) set pagination off
(gdb) execore-record 20000
Saved execore.tar.gz
"""
import argparse
import contextlib
import hashlib
import inspect
import os
import shlex
import shutil
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
    STOP_INSNS = ["stck", "stckf", "stfle", "svc"]

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
    STOP_INSNS = ["syscall", "rdtsc", "cpuid"]

    @classmethod
    def fixup_reg(cls, reg, reg_val):
        if reg == "$eflags":
            reg_val |= 2
        return reg_val


class PPC64:
    REGS = [
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
        "$r16",
        "$r17",
        "$r18",
        "$r19",
        "$r20",
        "$r21",
        "$r22",
        "$r23",
        "$r24",
        "$r25",
        "$r26",
        "$r27",
        "$r28",
        "$r29",
        "$r30",
        "$r31",
        "$pc",
        "$cr",
        "$lr",
        "$ctr",
    ]
    STOP_INSNS = ["mftb", "mftbu", "mfspr", "sc", "scv"]

    @classmethod
    def fixup_reg(cls, reg, reg_val):
        return reg_val


ARCHES = {
    "s390:64-bit": S390X,
    "i386:x86-64": X86_64,
    "powerpc:common64": PPC64,
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
    fp.flush()
    return True


def iter_objfile_names():
    for objfile in gdb.objfiles():
        objfile_name = objfile.filename
        if objfile_name is None or objfile_name.startswith("system-supplied DSO at 0x"):
            continue
        yield os.path.realpath(objfile_name)


def iter_mappings():
    try:
        execore_start = int(gdb.parse_and_eval("&_execore_start"))
        execore_end = int(gdb.parse_and_eval("&_execore_end"))
    except gdb.error:
        execore_start = None
        execore_end = None
    skip = True
    for line in gdb.execute("info proc mappings", to_string=True).split("\n"):
        if "Start Addr" in line:
            skip = False
            continue
        if skip:
            continue
        if line == "":
            break
        start, end, *_ = line.split()
        start = int(start, 0)
        end = int(end, 0)
        if (
            execore_start is None
            or execore_start >= end
            or execore_end is None
            or execore_end <= start
        ):
            yield start, end


def dump_memory(path):
    with open(path, "w") as fp:
        first_line = True
        for start, end in iter_mappings():
            for page in range(start, end, 0x1000):
                try:
                    data = gdb.selected_inferior().read_memory(page, 0x1000)
                except gdb.MemoryError:
                    continue
                for i in range(0x1000):
                    if i % 0x10 == 0:
                        if first_line:
                            first_line = False
                        else:
                            fp.write("\n")
                        fp.write("{:016x}:".format(page + i))
                    if i % 0x8 == 0:
                        fp.write(" ")
                    fp.write(" {:02x}".format(data[i][0]))


def add_fgmemory(parser):
    parser.add_argument(
        "--fgmemory",
        action="store_true",
        help="Generate a memory diff after each instruction",
    )


def fgmemory_start():
    dump_memory("memory.before")


def fgmemory_step(fp):
    dump_memory("memory.after")
    fp.write(
        subprocess.run(
            [
                "diff",
                "--label=memory.before",
                "--label=memory.after",
                "--unified",
                "memory.before",
                "memory.after",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
        ).stdout.decode()
    )
    fp.flush()
    os.rename("memory.after", "memory.before")


def record_epoch(trace_path, arch, total_insns, max_insns, max_epoch_insns, fgmemory):
    proceed = True
    with open(trace_path, "w") as fp:
        epoch_insns = 0
        while total_insns < max_insns and (
            max_epoch_insns is None or epoch_insns < max_epoch_insns
        ):
            if not dump_regs(fp, arch, epoch_insns):
                proceed = False
                break
            insn = gdb.execute("x/i $pc", to_string=True)
            gdb.execute("si")
            epoch_insns += 1
            total_insns += 1
            if fgmemory:
                fgmemory_step(fp)
            if any(stop_insn in insn.split() for stop_insn in arch.STOP_INSNS):
                break
    return total_insns, epoch_insns, proceed


class ExecoreRecord(gdb.Command):
    NAME = "execore-record"

    def __init__(self):
        super(ExecoreRecord, self).__init__(self.NAME, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parser = argparse.ArgumentParser(
            prog=self.NAME, description="Record instruction trace"
        )
        parser.add_argument(
            "max_insns", type=int, help="The number of instructions to record"
        )
        parser.add_argument(
            "--max-epoch-insns",
            type=int,
            help="The maximum number of instructions to record and replay per epoch",
        )
        add_fgmemory(parser)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        total_insns = 0
        epoch = 0
        objfile_names = set()
        filename = "execore.tar.gz"
        if args.fgmemory:
            fgmemory_start()
        with tarfile.open(filename, "w:gz", compresslevel=1) as tf:
            while total_insns < args.max_insns:
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
                    trace_path,
                    arch,
                    total_insns,
                    args.max_insns,
                    args.max_epoch_insns,
                    args.fgmemory,
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
    NAME = "execore-replay"

    def __init__(self):
        super(ExecoreReplay, self).__init__(self.NAME, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parser = argparse.ArgumentParser(
            prog=self.NAME, description="Replay instruction trace"
        )
        parser.add_argument(
            "--memory", action="store_true", help="Generate a memory dump at the end"
        )
        parser.add_argument(
            "max_insns", type=int, help="The number of instructions to replay"
        )
        parser.add_argument("epoch", type=int, help="Epoch number")
        add_fgmemory(parser)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        gdb.execute("set pagination off")
        if args.fgmemory:
            fgmemory_start()
        with open("trace.{}.r".format(args.epoch), "w") as fp:
            epoch_insns = 0
            while epoch_insns < args.max_insns:
                if not dump_regs(fp, arch, epoch_insns):
                    if args.memory:
                        with open("memory.{}.r".format(args.epoch), "w"):
                            pass
                    gdb.execute("quit")
                    return
                gdb.execute("si")
                epoch_insns += 1
                if args.fgmemory:
                    fgmemory_step(fp)
        if args.memory:
            dump_memory("memory.{}.r".format(args.epoch))
        gdb.execute("kill")
        gdb.execute("quit")


def this_file():
    # https://stackoverflow.com/a/53293924
    return os.path.realpath(inspect.getfile(lambda: None))


def shlex_join(xs):
    return " ".join(shlex.quote(x) for x in xs)


def check_call(argv, **kwargs):
    print("$ {}".format(shlex_join(argv)))
    subprocess.check_call(argv, **kwargs)


def ssh(remote, *args):
    check_call(["ssh", remote, *args])


def rsync(*args):
    check_call(
        ["rsync", "--archive", "--compress", "--ignore-times", "--verbose", *args]
    )


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
        ssh(
            remote,
            "find",
            remote_dir,
            "-type",
            "d",
            "-exec",
            "chmod",
            "u+w",
            "{}",
            "\\;",
        )
        ssh(remote, "rm", "-r", remote_dir)


def get_diff_command():
    diff = shutil.which("colordiff")
    if diff is None:
        diff = shutil.which("diff")
    if diff is None:
        raise RuntimeError("Neither colordiff nor diff found in $PATH")
    return diff


class ExecoreRecordReplay(gdb.Command):
    NAME = "execore-record-replay"

    def __init__(self):
        super(ExecoreRecordReplay, self).__init__(self.NAME, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parser = argparse.ArgumentParser(
            prog=self.NAME, description="Record, replay and compare instruction traces"
        )
        parser.add_argument(
            "--execore",
            default="execore",
            help="Replay using the specified execore binary",
        )
        parser.add_argument(
            "--memory",
            action="store_true",
            help="Compare memory at the end of each epoch",
        )
        parser.add_argument("--remote", help="Replay on the specified remote machine")
        parser.add_argument(
            "max_insns",
            type=int,
            help="The number of instructions to record and replay",
        )
        parser.add_argument(
            "--symlink",
            action="append",
            default=[],
            help="Symlink to create before replaying, in SRC:DST format",
        )
        parser.add_argument(
            "--max-epoch-insns",
            type=int,
            help="The maximum number of instructions to record and replay per epoch",
        )
        add_fgmemory(parser)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        diff = get_diff_command()
        arch = ARCHES[gdb.selected_inferior().architecture().name()]
        if args.fgmemory:
            fgmemory_start()
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
                    trace_path,
                    arch,
                    total_insns,
                    args.max_insns,
                    args.max_epoch_insns,
                    args.fgmemory,
                )
                memory_path = "memory.{}".format(epoch)
                if args.memory:
                    dump_memory(memory_path)
                trace_replay_path = "trace.{}.r".format(epoch)
                memory_replay_path = "memory.{}.r".format(epoch)
                outputs = [core_path, trace_path, trace_replay_path]
                if args.memory:
                    outputs.extend((memory_path, memory_replay_path))
                if remote_dir is None:
                    check_call(
                        [
                            args.execore,
                            core_path,
                            "--batch",
                            "--eval-command=source {}".format(this_file()),
                            "--eval-command=execore-replay {}{}{} {}".format(
                                "--memory " if args.memory else "",
                                "--fgmemory " if args.fgmemory else "",
                                epoch_insns,
                                epoch,
                            ),
                        ],
                    )
                else:
                    core_hash = hashlib.sha256()
                    with open(core_path, "rb") as fp:
                        while True:
                            buf = fp.read(0x2000)
                            if len(buf) == 0:
                                break
                            core_hash.update(buf)
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
                                shlex_join(["cd", remote_dir]),
                                "(echo "
                                + core_hash.hexdigest()
                                + " core.0 | sha256sum --check)",
                                *(
                                    shlex_join(
                                        [
                                            "ln",
                                            "-fsT",
                                            "{}/sysroot/{}".format(remote_dir, src),
                                            "{}/sysroot/{}".format(remote_dir, dst),
                                        ]
                                    )
                                    for symlink in args.symlink
                                    for src, dst in (symlink.split(":"),)
                                ),
                                shlex_join(
                                    [
                                        args.execore,
                                        "--sysroot=sysroot",
                                        "core.0",
                                        "--batch",
                                        "--eval-command=source {}".format(
                                            os.path.basename(this_file())
                                        ),
                                        "--eval-command=execore-replay {}{}{} 0".format(
                                            "--memory " if args.memory else "",
                                            "--fgmemory " if args.fgmemory else "",
                                            epoch_insns,
                                        ),
                                    ]
                                ),
                            )
                        ),
                    )
                    remote_trace_replay_path = "{}/trace.0.r".format(remote_dir)
                    rsync(
                        "{}:{}".format(args.remote, remote_trace_replay_path),
                        trace_replay_path,
                    )
                    ssh(args.remote, "rm", remote_trace_replay_path)
                    if args.memory:
                        remote_memory_replay_path = "{}/memory.0.r".format(remote_dir)
                        shutil.copy(memory_path, memory_replay_path)
                        rsync(
                            "{}:{}".format(args.remote, remote_memory_replay_path),
                            memory_replay_path,
                        )
                        ssh(args.remote, "rm", remote_memory_replay_path)
                try:
                    trace_diff = "trace.diff"
                    outputs.append(trace_diff)
                    with open(trace_diff, "wb") as fp:
                        check_call(
                            [diff, "--unified=50", trace_replay_path, trace_path],
                            stdout=fp,
                        )
                    if args.memory:
                        memory_diff = "memory.diff"
                        outputs.append(memory_diff)
                        with open(memory_diff, "wb") as fp:
                            check_call(
                                [
                                    diff,
                                    "--unified=50",
                                    memory_replay_path,
                                    memory_path,
                                ],
                                stdout=fp,
                            )
                except subprocess.CalledProcessError:
                    print("\nInstructions replayed: {}".format(total_insns))
                    print("Traces do not match, see: {}\n".format(", ".join(outputs)))
                    return
                for output in outputs:
                    os.unlink(output)
                epoch += 1
                if not proceed:
                    break
            print("\nInstructions replayed: {}".format(total_insns))
            print("Traces match\n")


ExecoreRecord()
ExecoreReplay()
ExecoreRecordReplay()
