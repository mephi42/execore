ENTRY(_start);

PHDRS {
        text   PT_LOAD FLAGS(5);  /* PF_R | PF_X */
        rodata PT_LOAD FLAGS(4);  /* PF_R */
        bss    PT_LOAD FLAGS(6);  /* PF_R | PF_W */
}

SECTIONS {
        . = 0x70000000;
        _execore_start = .;
        .text : { *(.text*) } :text
        . = ALIGN(0x1000);
        .rodata : { *(.rodata*) } :rodata
        . = ALIGN(0x1000);
        .bss : { *(.bss) } :bss
        . = ALIGN(0x1000);
        _execore_end = .;
        /DISCARD/ : { *(.note.*) }
}
