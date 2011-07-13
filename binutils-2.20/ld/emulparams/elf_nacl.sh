. ${srcdir}/emulparams/elf_i386.sh
SCRIPT_NAME=naclelf
OUTPUT_FORMAT="elf32-nacl"
TEXT_START_ADDR=0x00020000
SEGMENT_SIZE=0x10000
# Compile in the built-in version to simplify the PNaCl translator.
COMPILE_IN=yes
