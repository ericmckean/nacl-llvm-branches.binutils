#objdump: -dr
#name: video2
.*: +file format .*

Disassembly of section .text:

00000000 <.text>:
[ 0-9a-f]+:	0d c6 00 00 	R0 = ALIGN8 \(R0, R0\);
[ 0-9a-f]+:	0d c6 08 00 	R0 = ALIGN8 \(R0, R1\);
[ 0-9a-f]+:	0d c6 01 00 	R0 = ALIGN8 \(R1, R0\);
[ 0-9a-f]+:	0d c6 09 00 	R0 = ALIGN8 \(R1, R1\);
[ 0-9a-f]+:	0d c6 11 00 	R0 = ALIGN8 \(R1, R2\);
[ 0-9a-f]+:	0d c6 2c 06 	R3 = ALIGN8 \(R4, R5\);
[ 0-9a-f]+:	0d c6 07 0c 	R6 = ALIGN8 \(R7, R0\);
[ 0-9a-f]+:	0d c6 1a 02 	R1 = ALIGN8 \(R2, R3\);
[ 0-9a-f]+:	0d c6 35 08 	R4 = ALIGN8 \(R5, R6\);
[ 0-9a-f]+:	0d c6 08 0e 	R7 = ALIGN8 \(R0, R1\);
[ 0-9a-f]+:	0d c6 23 04 	R2 = ALIGN8 \(R3, R4\);
[ 0-9a-f]+:	0d c6 3e 0a 	R5 = ALIGN8 \(R6, R7\);
[ 0-9a-f]+:	0d c6 00 40 	R0 = ALIGN16 \(R0, R0\);
[ 0-9a-f]+:	0d c6 08 40 	R0 = ALIGN16 \(R0, R1\);
[ 0-9a-f]+:	0d c6 01 40 	R0 = ALIGN16 \(R1, R0\);
[ 0-9a-f]+:	0d c6 09 40 	R0 = ALIGN16 \(R1, R1\);
[ 0-9a-f]+:	0d c6 11 40 	R0 = ALIGN16 \(R1, R2\);
[ 0-9a-f]+:	0d c6 2c 46 	R3 = ALIGN16 \(R4, R5\);
[ 0-9a-f]+:	0d c6 07 4c 	R6 = ALIGN16 \(R7, R0\);
[ 0-9a-f]+:	0d c6 1a 42 	R1 = ALIGN16 \(R2, R3\);
[ 0-9a-f]+:	0d c6 35 48 	R4 = ALIGN16 \(R5, R6\);
[ 0-9a-f]+:	0d c6 08 4e 	R7 = ALIGN16 \(R0, R1\);
[ 0-9a-f]+:	0d c6 23 44 	R2 = ALIGN16 \(R3, R4\);
[ 0-9a-f]+:	0d c6 3e 4a 	R5 = ALIGN16 \(R6, R7\);
[ 0-9a-f]+:	0d c6 00 80 	R0 = ALIGN24 \(R0, R0\);
[ 0-9a-f]+:	0d c6 08 80 	R0 = ALIGN24 \(R0, R1\);
[ 0-9a-f]+:	0d c6 01 80 	R0 = ALIGN24 \(R1, R0\);
[ 0-9a-f]+:	0d c6 09 80 	R0 = ALIGN24 \(R1, R1\);
[ 0-9a-f]+:	0d c6 11 80 	R0 = ALIGN24 \(R1, R2\);
[ 0-9a-f]+:	0d c6 2c 86 	R3 = ALIGN24 \(R4, R5\);
[ 0-9a-f]+:	0d c6 07 8c 	R6 = ALIGN24 \(R7, R0\);
[ 0-9a-f]+:	0d c6 1a 82 	R1 = ALIGN24 \(R2, R3\);
[ 0-9a-f]+:	0d c6 35 88 	R4 = ALIGN24 \(R5, R6\);
[ 0-9a-f]+:	0d c6 08 8e 	R7 = ALIGN24 \(R0, R1\);
[ 0-9a-f]+:	0d c6 23 84 	R2 = ALIGN24 \(R3, R4\);
[ 0-9a-f]+:	0d c6 3e 8a 	R5 = ALIGN24 \(R6, R7\);
[ 0-9a-f]+:	12 c4 00 c0 	DISALGNEXCPT;
[ 0-9a-f]+:	17 c4 02 00 	R0 = BYTEOP3P \(R1:0, R3:2\) \(LO\);
[ 0-9a-f]+:	37 c4 02 02 	R1 = BYTEOP3P \(R1:0, R3:2\) \(HI\);
[ 0-9a-f]+:	17 c4 02 24 	R2 = BYTEOP3P \(R1:0, R3:2\) \(LO, R\);
[ 0-9a-f]+:	37 c4 02 26 	R3 = BYTEOP3P \(R1:0, R3:2\) \(HI, R\);
[ 0-9a-f]+:	17 c4 10 08 	R4 = BYTEOP3P \(R3:2, R1:0\) \(LO\);
[ 0-9a-f]+:	37 c4 10 0a 	R5 = BYTEOP3P \(R3:2, R1:0\) \(HI\);
[ 0-9a-f]+:	17 c4 10 2c 	R6 = BYTEOP3P \(R3:2, R1:0\) \(LO, R\);
[ 0-9a-f]+:	37 c4 10 2e 	R7 = BYTEOP3P \(R3:2, R1:0\) \(HI, R\);
[ 0-9a-f]+:	0c c4 00 40 	R0 = A1.L \+ A1.H, R0 = A0.L \+ A0.H;
[ 0-9a-f]+:	0c c4 00 42 	R0 = A1.L \+ A1.H, R1 = A0.L \+ A0.H;
[ 0-9a-f]+:	0c c4 80 46 	R2 = A1.L \+ A1.H, R3 = A0.L \+ A0.H;
[ 0-9a-f]+:	0c c4 00 4b 	R4 = A1.L \+ A1.H, R5 = A0.L \+ A0.H;
[ 0-9a-f]+:	0c c4 80 4f 	R6 = A1.L \+ A1.H, R7 = A0.L \+ A0.H;
[ 0-9a-f]+:	15 c4 d0 01 	\(R7, R0\) = BYTEOP16P \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 50 04 	\(R1, R2\) = BYTEOP16P \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 10 02 	\(R0, R1\) = BYTEOP16P \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 90 06 	\(R2, R3\) = BYTEOP16P \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 c2 01 	\(R7, R0\) = BYTEOP16P \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 42 04 	\(R1, R2\) = BYTEOP16P \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 02 02 	\(R0, R1\) = BYTEOP16P \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 82 06 	\(R2, R3\) = BYTEOP16P \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 d0 21 	\(R7, R0\) = BYTEOP16P \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 50 24 	\(R1, R2\) = BYTEOP16P \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 10 22 	\(R0, R1\) = BYTEOP16P \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 90 26 	\(R2, R3\) = BYTEOP16P \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 c2 21 	\(R7, R0\) = BYTEOP16P \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 42 24 	\(R1, R2\) = BYTEOP16P \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 02 22 	\(R0, R1\) = BYTEOP16P \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 82 26 	\(R2, R3\) = BYTEOP16P \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	14 c4 02 06 	R3 = BYTEOP1P \(R1:0, R3:2\);
[ 0-9a-f]+:	14 c4 02 26 	R3 = BYTEOP1P \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	14 c4 02 46 	R3 = BYTEOP1P \(R1:0, R3:2\) \(T\);
[ 0-9a-f]+:	14 c4 02 66 	R3 = BYTEOP1P \(R1:0, R3:2\) \(T, R\);
[ 0-9a-f]+:	14 c4 10 00 	R0 = BYTEOP1P \(R3:2, R1:0\);
[ 0-9a-f]+:	14 c4 10 22 	R1 = BYTEOP1P \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	14 c4 10 44 	R2 = BYTEOP1P \(R3:2, R1:0\) \(T\);
[ 0-9a-f]+:	14 c4 10 66 	R3 = BYTEOP1P \(R3:2, R1:0\) \(T, R\);
[ 0-9a-f]+:	16 c4 02 06 	R3 = BYTEOP2P \(R1:0, R3:2\) \(RNDL\);
[ 0-9a-f]+:	36 c4 02 06 	R3 = BYTEOP2P \(R1:0, R3:2\) \(RNDH\);
[ 0-9a-f]+:	16 c4 02 46 	R3 = BYTEOP2P \(R1:0, R3:2\) \(TL\);
[ 0-9a-f]+:	36 c4 02 46 	R3 = BYTEOP2P \(R1:0, R3:2\) \(TH\);
[ 0-9a-f]+:	16 c4 02 26 	R3 = BYTEOP2P \(R1:0, R3:2\) \(RNDL, R\);
[ 0-9a-f]+:	36 c4 02 26 	R3 = BYTEOP2P \(R1:0, R3:2\) \(RNDH, R\);
[ 0-9a-f]+:	16 c4 02 66 	R3 = BYTEOP2P \(R1:0, R3:2\) \(TL, R\);
[ 0-9a-f]+:	36 c4 02 66 	R3 = BYTEOP2P \(R1:0, R3:2\) \(TH, R\);
[ 0-9a-f]+:	16 c4 02 00 	R0 = BYTEOP2P \(R1:0, R3:2\) \(RNDL\);
[ 0-9a-f]+:	36 c4 02 02 	R1 = BYTEOP2P \(R1:0, R3:2\) \(RNDH\);
[ 0-9a-f]+:	16 c4 02 44 	R2 = BYTEOP2P \(R1:0, R3:2\) \(TL\);
[ 0-9a-f]+:	36 c4 02 46 	R3 = BYTEOP2P \(R1:0, R3:2\) \(TH\);
[ 0-9a-f]+:	16 c4 02 28 	R4 = BYTEOP2P \(R1:0, R3:2\) \(RNDL, R\);
[ 0-9a-f]+:	36 c4 02 2a 	R5 = BYTEOP2P \(R1:0, R3:2\) \(RNDH, R\);
[ 0-9a-f]+:	16 c4 02 6c 	R6 = BYTEOP2P \(R1:0, R3:2\) \(TL, R\);
[ 0-9a-f]+:	36 c4 02 6e 	R7 = BYTEOP2P \(R1:0, R3:2\) \(TH, R\);
[ 0-9a-f]+:	16 c4 12 00 	R0 = BYTEOP2P \(R3:2, R3:2\) \(RNDL\);
[ 0-9a-f]+:	36 c4 12 02 	R1 = BYTEOP2P \(R3:2, R3:2\) \(RNDH\);
[ 0-9a-f]+:	16 c4 12 44 	R2 = BYTEOP2P \(R3:2, R3:2\) \(TL\);
[ 0-9a-f]+:	36 c4 12 46 	R3 = BYTEOP2P \(R3:2, R3:2\) \(TH\);
[ 0-9a-f]+:	16 c4 12 28 	R4 = BYTEOP2P \(R3:2, R3:2\) \(RNDL, R\);
[ 0-9a-f]+:	36 c4 12 2a 	R5 = BYTEOP2P \(R3:2, R3:2\) \(RNDH, R\);
[ 0-9a-f]+:	16 c4 12 6c 	R6 = BYTEOP2P \(R3:2, R3:2\) \(TL, R\);
[ 0-9a-f]+:	36 c4 12 6e 	R7 = BYTEOP2P \(R3:2, R3:2\) \(TH, R\);
[ 0-9a-f]+:	18 c4 00 00 	R0 = BYTEPACK \(R0, R0\);
[ 0-9a-f]+:	18 c4 13 02 	R1 = BYTEPACK \(R2, R3\);
[ 0-9a-f]+:	18 c4 2e 08 	R4 = BYTEPACK \(R5, R6\);
[ 0-9a-f]+:	18 c4 01 0e 	R7 = BYTEPACK \(R0, R1\);
[ 0-9a-f]+:	18 c4 1c 04 	R2 = BYTEPACK \(R3, R4\);
[ 0-9a-f]+:	18 c4 37 0a 	R5 = BYTEPACK \(R6, R7\);
[ 0-9a-f]+:	15 c4 50 44 	\(R1, R2\) = BYTEOP16M \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 50 64 	\(R1, R2\) = BYTEOP16M \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 10 42 	\(R0, R1\) = BYTEOP16M \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 90 66 	\(R2, R3\) = BYTEOP16M \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 d0 4a 	\(R3, R5\) = BYTEOP16M \(R3:2, R1:0\);
[ 0-9a-f]+:	15 c4 90 6f 	\(R6, R7\) = BYTEOP16M \(R3:2, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 40 44 	\(R1, R2\) = BYTEOP16M \(R1:0, R1:0\);
[ 0-9a-f]+:	15 c4 40 64 	\(R1, R2\) = BYTEOP16M \(R1:0, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 00 42 	\(R0, R1\) = BYTEOP16M \(R1:0, R1:0\);
[ 0-9a-f]+:	15 c4 80 66 	\(R2, R3\) = BYTEOP16M \(R1:0, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 c0 4a 	\(R3, R5\) = BYTEOP16M \(R1:0, R1:0\);
[ 0-9a-f]+:	15 c4 80 6f 	\(R6, R7\) = BYTEOP16M \(R1:0, R1:0\) \(R\);
[ 0-9a-f]+:	15 c4 42 44 	\(R1, R2\) = BYTEOP16M \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 42 64 	\(R1, R2\) = BYTEOP16M \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 02 42 	\(R0, R1\) = BYTEOP16M \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 82 66 	\(R2, R3\) = BYTEOP16M \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 c2 4a 	\(R3, R5\) = BYTEOP16M \(R1:0, R3:2\);
[ 0-9a-f]+:	15 c4 82 6f 	\(R6, R7\) = BYTEOP16M \(R1:0, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 52 44 	\(R1, R2\) = BYTEOP16M \(R3:2, R3:2\);
[ 0-9a-f]+:	15 c4 52 64 	\(R1, R2\) = BYTEOP16M \(R3:2, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 12 42 	\(R0, R1\) = BYTEOP16M \(R3:2, R3:2\);
[ 0-9a-f]+:	15 c4 92 66 	\(R2, R3\) = BYTEOP16M \(R3:2, R3:2\) \(R\);
[ 0-9a-f]+:	15 c4 d2 4a 	\(R3, R5\) = BYTEOP16M \(R3:2, R3:2\);
[ 0-9a-f]+:	15 c4 92 6f 	\(R6, R7\) = BYTEOP16M \(R3:2, R3:2\) \(R\);
[ 0-9a-f]+:	12 cc 02 00 	SAA \(R1:0, R3:2\) \|\| R0 = \[I0\+\+\] \|\| R2 = \[I1\+\+\];
[ 0-9a-f]+:	00 9c 0a 9c 
[ 0-9a-f]+:	12 cc 02 20 	SAA \(R1:0, R3:2\) \(R\) \|\| R1 = \[I0\+\+\] \|\| R3 = \[I1\+\+\];
[ 0-9a-f]+:	01 9c 0b 9c 
[ 0-9a-f]+:	12 c4 02 00 	SAA \(R1:0, R3:2\);
[ 0-9a-f]+:	18 c4 80 4b 	\(R6, R5\) = BYTEUNPACK R1:0;
[ 0-9a-f]+:	18 c4 80 6b 	\(R6, R5\) = BYTEUNPACK R1:0 \(R\);
[ 0-9a-f]+:	18 c4 90 4b 	\(R6, R5\) = BYTEUNPACK R3:2;
[ 0-9a-f]+:	18 c4 90 6b 	\(R6, R5\) = BYTEUNPACK R3:2 \(R\);
[ 0-9a-f]+:	18 c4 00 42 	\(R0, R1\) = BYTEUNPACK R1:0;
[ 0-9a-f]+:	18 c4 80 66 	\(R2, R3\) = BYTEUNPACK R1:0 \(R\);
[ 0-9a-f]+:	18 c4 10 4b 	\(R4, R5\) = BYTEUNPACK R3:2;
[ 0-9a-f]+:	18 c4 90 6f 	\(R6, R7\) = BYTEUNPACK R3:2 \(R\);
