# execore

The whole point of this tool is if you wanna take a core dump, load it into
memory and let it run and segfault once more, you can! You are free to do so!
To me, that's beautiful.

## No, really...

This is useful for finding discrepancies between QEMU TCG and real hardware.
Attach with GDB to qemu-user's gdbstub, do `generate-core-file`, and resume on
a real CPU.

## But...

This is not CRIU and is meant only for specific debugging scenarios, so
nothing except registers and memory is restored. In particular, there is no
information about file descriptors in a core file. There is information about
threads, but only one thread is restored at the moment.
