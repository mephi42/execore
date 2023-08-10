#include "execore_page.h"

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
        . = ALIGN(PAGE_SIZE);
        .rodata : { *(.rodata*) } :rodata
        . = ALIGN(PAGE_SIZE);
        .bss : { *(.bss) } :bss
        . = ALIGN(PAGE_SIZE);
        _execore_end = .;
        /DISCARD/ : { *(.note.*) }
}
