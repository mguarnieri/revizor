/* 
    Linker script inspired by nanobench layout
*/

OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64",
	      "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
SEARCH_DIR("=/usr/local/lib/x86_64-linux-gnu"); SEARCH_DIR("=/lib/x86_64-linux-gnu"); SEARCH_DIR("=/usr/lib/x86_64-linux-gnu"); SEARCH_DIR("=/usr/lib/x86_64-linux-gnu64"); SEARCH_DIR("=/usr/local/lib64"); SEARCH_DIR("=/lib64"); SEARCH_DIR("=/usr/lib64"); SEARCH_DIR("=/usr/local/lib"); SEARCH_DIR("=/lib"); SEARCH_DIR("=/usr/lib"); SEARCH_DIR("=/usr/x86_64-linux-gnu/lib64"); SEARCH_DIR("=/usr/x86_64-linux-gnu/lib");

STACK_SIZE = 0x0FFFFF; /* 1M */


MEMORY{
    code    :   ORIGIN = 0x401000, LENGTH = 1M 
    sandbox :   ORIGIN = 0x502000, LENGTH = 1M 
    stack   :   ORIGIN = 0x700000, LENGTH = 1M
}

SECTIONS{
    /* PROVIDE (__executable_start = SEGMENT_START("text-segment", 0x0000)); . = SEGMENT_START("text-segment", 0x0000) + SIZEOF_HEADERS; */
    __stacktop = ORIGIN(stack) + LENGTH(stack);
    .text   :
    {
        /* . = ALIGN(4096); */
        *(.text)
        /* . = ALIGN(4096); */
    } > code

    .data  : 
    {
         _sdata = .;
        *(.data)
        _edata = .;
    } > sandbox 
   

    .stack  :
    {
        /* . = ALIGN(8);
        . = . + STACK_SIZE;
        . = ALIGN(8); */
        *(.stack)
    } > stack
    
    /DISCARD/ :
    {
        *(.note.gnu.property)
    }

}
