#name: C6X arch attribute merging, c67x+ c62x
#as: -mlittle-endian
#ld: -r -melf32_tic6x_le
#source: attr-arch-c67x+.s
#source: attr-arch-c62x.s
#readelf: -A

Attribute Section: c6xabi
File Attributes
  Tag_C6XABI_Tag_CPU_arch: C67x\+
