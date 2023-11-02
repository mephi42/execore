# execore

The whole point of this tool is if you wanna take a core dump, load it into
memory and let it run and segfault once more, you can! You are free to do so!
To me, that's beautiful.

## No, really...

This is useful for calling functions from GDB when only a core file is
available. Suppose we have one from the following small program:

```
$ cat 42.c
int win(void) { return 42; }
int main(void) { __builtin_trap(); }

$ gcc -o 42 -g 42.c
$ ./42
Illegal instruction (core dumped)
```

and we need to call `win()` from GDB without running `./42` again.

```
$ sudo execore core.31025
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1

main () at 42.c:2
2	int main(void) { __builtin_trap(); }

(gdb) p win()
$1 = 42
```

The original use case is finding discrepancies between  QEMU TCG and real
hardware. Attach with GDB to qemu-user's gdbstub, do `generate-core-file`,
and resume on a real CPU.

## Caveats

* The original executable file and shared libraries must be available at the
  original locations. Core files do not contain data from these.

* `sudo` is required for restoring auxv (see `PR_SET_MM_AUXV` in
  [`man 2 prctl`](https://man7.org/linux/man-pages/man2/prctl.2.html)).

* Core files contain information about threads, but only one thread is
  restored at the moment. The thread to restore can be specified using the
  `--tid=` argument.

* Core files do not contain information about file descriptors and many other
  pieces of process state. This is not CRIU, sorry.
