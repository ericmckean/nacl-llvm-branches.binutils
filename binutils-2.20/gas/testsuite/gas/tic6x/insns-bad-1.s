# Test bad instructions and operands.
.text
.globl f
f:
	nonesuch foo bar
	nop nonconst
	nop 2,
	nop 2,3
	nop 2 , 4
	nop 2 4
	nop 0
	nop -1
	nop 10000
	nop 10
	nop 15
	abs .L1 a1,
	abs .L1 a1
	abs .S1 a1,a2
	abs .L1 foo,bar
	abs .L1X foo,bar
	abs .L1 A0,A00
	abs .L1 A32,A1
	abs .L1 B1,A1
	abs .L1 A1,B1
	abs .L1X A1,A1
	abs .L1X B1,B1
	abs .L2 A3,B4
	abs .L2 B4,A3
	abs .L2X A7,A8
	abs .L2X b9,b10
	abs .L1 A2:A1,A3:A2
	abs .L2 B5:B4,B2:B3
	abs .L1 A3:B2,A5:A4
	abs .L2 B1:B0,A5:A4
	abs .L1X B1:B0,A1:A0
	abs .L1 A1:A0,A11
	abs2 .L1 a1
	abs2 .S1 a1,a2
	abs2 .L1 foo,a3:a2
	abs2 .L2X b1,b2
	absdp .L1 a3:a2,a1:a0
	absdp .S2 b1:b0
	absdp .S2 b1,b0
	absdp .S2X a1:a0,b1:b0
	abssp .L1 a0,a0
	abssp .S1 a1:a0
	abssp .S1X a0,a1
	abssp .S2 a1,b0
	add .M1 a0,a0,a0
	add .L1 a0,b0,a0
	add .L1X a0,a0,a0
	add .L1 a1:a0,a3:a2,a5:a4
	add .L1X 16,b2,a3
	add .L1X -17,b2,a3
	add .L1X 5,a3:a2,a7:a6
	add .L2 100,b5:b4,b9:b8
	add .L1 a0,a0
	add .S1 a0,a0,a1:a0
	add .S2 b1,b2
	add .S1X 4,a5,a7
	add .S2X -17,a9,b11
	add .S1 16,a14,a13
	add .D1T1 a1,a1,a1
	add .D1 a1,a1
	add .D2 b1,-17,b2
	add .D2 b1,32,b4
	add .D1X b1,b1,a1
	add .D2X a5,-17,b1
	add .D2X a20,16,b4
	addab .L1 a4,a5,a6
	addab .D1X a7,a8,a9
	addab .D1 a2,a3
	addab .D2 a1,b2,b3
	addab .D1 a1,-1,a2
	addab .D2 b1,32,b2
	addab .D1X b14,-1,a2
	addab .D2 b15,32768,b20
	addab .D1 a14,32,a20
	addad .D1X a4,a5,a6
	addad .S1 a10,a9,a8
	addad .D1 a1,a2,a3,a4
	addad .D2 b4,-1,b4
	addad .D2 b4,32,b3
	addad .D1 a1,b2,a3
	addad .D2 b14,foo,b4
	addah .L1 a4,a5,a6
	addah .D1X a7,a8,a9
	addah .D1 a2,a3
	addah .D2 a1,b2,b3
	addah .D1 a1,-1,a2
	addah .D2 b1,32,b2
	addah .D1X b14,-1,a2
	addah .D2 b15,32768,b20
	addah .D1 a14,32,a20
	addaw .L1 a4,a5,a6
	addaw .D1X a7,a8,a9
	addaw .D1 a2,a3
	addaw .D2 a1,b2,b3
	addaw .D1 a1,-1,a2
	addaw .D2 b1,32,b2
	addaw .D1X b14,-1,a2
	addaw .D2 b15,32768,b20
	addaw .D1 a14,32,a20
	adddp .D1 a1:a0,a1:a0,a1:a0
	adddp .L1 a1:a0,a1:a0
	adddp .L2 b1,b1,b1
	adddp .L1 a1:a0,b1:b0,a1:a0
	adddp .L2X b1:b0,b3:b2,b5:b4
	addk .L1 0,a1
	addk .S2 32768,b1
	addk .S1 -32769,a1
	addk .S2 0
	addk .S2X 0,a1
	mvk .M1 0,a1
	mvk .S2 32768,b1
	mvk .S1 -32769,a1
	mvk .S2 0,b1,0
	mvk .S1X 0,b1
	mvkh .L1 0,a1
	mvkh .S2 0,b1,0
	mvkh .S1X 0,b1
	mvklh .L1 0,a1
	mvklh .S2 0,b1,0
	mvklh .S1X 0,b1
	mvkl .L1 0,a1
	mvkl .S2 0,b1,0
	mvkl .S1X 0,b1
	addkpc .S1 f,a1,0
	addkpc .S2X f,a1,0
	addkpc .S2 0,b2,0
	addkpc .S2 f,b2
	addkpc .S2 f,b2,-1
	addkpc .S2 f,b2,8
	b .L1 f
	b .S1X f
	b .S1 f,0
	b .S1 0
	call .L1 f
	call .S1X f
	call .S1 f,0
	call .S1 0
	bdec .L1 f,a1
	bdec .S1X f,b1
	bdec .S1 f,b1
	bdec .S2 0,b2
	bdec .S2 f,b1,0
	bpos .L1 f,a1
	bpos .S1X f,b1
	bpos .S1 f,b1
	bpos .S2 0,b2
	bpos .S2 f,b1,0
	bnop .L1 f,0
	bnop .S1X f,0
	bnop f,-1
	bnop 0,0
	bnop f,8
	callnop .L1 f,0
	callnop .S1X f,0
	callnop f,-1
	callnop 0,0
	callnop f,8
	callp .L1 f,a3
	callp .S1X f,b3
	callp .S1 f,a4
	callp .S1 0,a3
	callp .S1 f,b3
	callp .S2 f,a3
	addsp .D1 a1,a2,a3
	addsp .L1 a1
	addsp .L2 a2,0
	addsp .L1 b1,a1,a3
	addsp .S2X b1,b2,b3
	addsub .M1 a2,a3,a5:a4
	addsub .L1 a1
	addsub .L1 a1,a2,a3
	addsub .L2 a1,b1,b3:b2
	addsub2 .M1 a2,a3,a5:a4
	addsub2 .L1 a1
	addsub2 .L1 a1,a2,a3
	addsub2 .L2 a1,b1,b3:b2
	addu .D2 b4,b5,b7:b6
	addu .L2 b1,b2
	addu .L1 b1,a1,a3:a2
	addu .L2X a4,b7:b6,b5
	add2 .M1 a1,a2,a3
	add2 .S1 a1,a2,a3,a4
	add2 .L1 b1,a1,a2
	add2 .D2X b1,b2,b3
	add4 .S1 a1,a2,a3
	add4 .L1 a1,a2,a3,a4
	add4 .L1 b1,a1,a2
	add4 .L2X b1,b2,b3
	and .M2 b1,b2,b3
	and .L1 -17,a4,a5
	and .L2 16,b3,b4
	and .S1X -17,b4,a5
	and .S2X 16,a3,b4
	and .D1 -17,a4,a5
	and .D2 16,b3,b4
	and .D1 b1,a2,a3
	andn .M1 a1,a2,a3
	andn .S1 a1
	andn .D1X b2,b2,a3
	andn .S2 0,b2,b3
	avg2 .S1 a1,a2,a3
	avg2 .M1 a1,a2
	avg2 .M1 b1,a2,a2
	avg2 .M2X a1,a2,b3
	avgu4 .S1 a1,a2,a3
	avgu4 .M1 a1,a2
	avgu4 .M1 b1,a2,a2
	avgu4 .M2X a1,a2,b3
	b .L2 b1
	b .S2 b1,0
	call .M2 b1
	call .S2 b1,0
	callret .D2 b1
	callret .S2 b1,0
	ret .L2 b1
	ret .S2 b1,0
	b .S2X irp
	b .L2 irp
	b .S2X nrp
	b .M2 nrp
	bitc4 .M1 a1,a2,a3
	bitc4 .L1 a1,a2
	bitc4 .M2 b2,a1
	bitc4 .M2X b3,b4
	bitr .M1 a1
	bitr .S1 a1,a2
	bitr .M2 b2,a1
	bitr .M2X b3,b4
	bnop .M1 a5,0
	bnop .S1X b5,0
	bnop .S2 b3,-1
	bnop .S2 b3,8
	bnop .S2 b3
	callnop .M1 a5,0
	callnop .S1X b5,0
	callnop .S2 b3,-1
	callnop .S2 b3,8
	callnop .S2 b3
	clr .L1 a1,0,1,a2
	clr .M2 b1,b2,b3
	clr .S1 a1,a1
	clr .S1X a1,0,0,a1
	clr .S2 b1,a1,b1
	cmpeq .S1 a1,a2,a3
	cmpeq .L1 a1,a2,a3,a4
	cmpeq .L1 a1:a0,a3:a2,a5
	cmpeq .L2 -17,b4,b5
	cmpeq .L2 16,b4,b5
	cmpeq .L1 -17,a5:a4,a3
	cmpeq .L1 16,a5:a4,a3
	cmpeq .L1X -16,a5:a4,a3
	cmpeq2 .L1 a1,a2,a3
	cmpeq2 .S1 a1,a2
	cmpeq2 .S1 a1,b2,a3
	cmpeq2 .S2X b1,b2,b3
	cmpeq4 .D1 a1,a2,a3
	cmpeq4 .S1 a1
	cmpeq4 .S2 a1,b2,b3
	cmpeq4 .S1X a4,a5,a6
	cmpeqdp .M1 a3:a2,a1:a0,a5
	cmpeqdp .S1 a3:a2
	cmpeqdp .S1 a3,a2,a1
	cmpeqdp .S2 a3:a2,b1:b0,b5
	cmpeqdp .S2X b3:b2,b1:b0,b31
	cmpeqsp .S1 a1
	cmpeqsp .M2 b1,b2,b3
	cmpeqsp .S2X b1,b2,b3
	cmpeqsp .S1 b1,a2,a3
	cmpgt .S1 a1,a2,a3
	cmpgt .L1 a1,a2,a3,a4
	cmpgt .L1 a1:a0,a3:a2,a5
	cmpgt .L2 -17,b4,b5
	cmpgt .L2 16,b4,b5
	cmpgt .L1 -17,a5:a4,a3
	cmpgt .L1 16,a5:a4,a3
	cmpgt .L1X -16,a5:a4,a3
	cmpgt2 .L1 a1,a2,a3
	cmpgt2 .S1 a1,a2
	cmpgt2 .S1 b1,a2,a3
	cmpgt2 .S2X b1,b3,b3
	cmpgtdp .L1 a1:a0,a1:a0,a0
	cmpgtdp .S1 a1:a0
	cmpgtdp .S1 b1:b0,a1:a0,a2
	cmpgtdp .S2X b5:b4,b3:b2,b1
	cmpgtsp .L1 a1,a1,a0
	cmpgtsp .S1 a1
	cmpgtsp .S1 b1,a1,a2
	cmpgtsp .S2X b5,b3,b1
	cmpgtu .S1 a1,a2,a3
	cmpgtu .L1 a1,a2,a3,a4
	cmpgtu .L1 a1:a0,a3:a2,a5
	cmpgtu .L2 -1,b4,b5
	cmpgtu .L2 32,b4,b5
	cmpgtu .L1 -1,a5:a4,a3
	cmpgtu .L1 32,a5:a4,a3
	cmpgtu .L1X 0,a5:a4,a3
	cmpgtu4 .D1 a1,a2,a3
	cmpgtu4 .S1 a1,a2
	cmpgtu4 .S1 a1,a2,b3
	cmpgtu4 .S2X b1,b2,b3
	cmplt .S1 a1,a2,a3
	cmplt .L1 a1,a2,a3,a4
	cmplt .L1 a1:a0,a3:a2,a5
	cmplt .L2 -17,b4,b5
	cmplt .L2 16,b4,b5
	cmplt .L1 -17,a5:a4,a3
	cmplt .L1 16,a5:a4,a3
	cmplt .L1X -16,a5:a4,a3
	cmplt2 .L1 a1,a2,a3
	cmplt2 .S1 a1,a2
	cmplt2 .S1 a2,b1,a3
	cmplt2 .S2X b1,b3,b3
	cmpltdp .L1 a1:a0,a1:a0,a0
	cmpltdp .S1 a1:a0
	cmpltdp .S1 b1:b0,a1:a0,a2
	cmpltdp .S2X b5:b4,b3:b2,b1
	cmpltsp .L1 a1,a1,a0
	cmpltsp .S1 a1
	cmpltsp .S1 b1,a1,a2
	cmpltsp .S2X b5,b3,b1
	cmpltu .S1 a1,a2,a3
	cmpltu .L1 a1,a2,a3,a4
	cmpltu .L1 a1:a0,a3:a2,a5
	cmpltu .L2 -1,b4,b5
	cmpltu .L2 32,b4,b5
	cmpltu .L1 -1,a5:a4,a3
	cmpltu .L1 32,a5:a4,a3
	cmpltu .L1X 0,a5:a4,a3
	cmpltu4 .D1 a1,a2,a3
	cmpltu4 .S1 a1,a2
	cmpltu4 .S1 a1,a2,b3
	cmpltu4 .S2X b1,b2,b3
	cmpy .S1 a1,a2,a5:a4
	cmpy .M1 a1,a2
	cmpy .M1 b1,a1,a3:a2
	cmpy .M2X b3,b4,b7:b6
	cmpyr .S1 a1,a2,a5
	cmpyr .M1 a1,a2
	cmpyr .M1 b1,a1,a3
	cmpyr .M2X b3,b4,b7
	cmpyr1 .L1 a1,a2,a5
	cmpyr1 .M1 a1,a2
	cmpyr1 .M1 b1,a1,a3
	cmpyr1 .M2X b3,b4,b7
	ddotp4 .D1 a1,a3,a5:a4
	ddotp4 .M1 a1,a3
	ddotp4 .M1X a1,a2,a5:a4
	ddotp4 .M2 a1,b1,b3:b2
	ddotph2 .L1 a1:a0,a3,a5:a4
	ddotph2 .M1 a1:a0,a3
	ddotph2 .M1X a1:a0,a2,a5:a4
	ddotph2 .M2 a1:a0,b1,b3:b2
	ddotph2r .S1 a1:a0,a3,a5
	ddotph2r .M1 a1:a0,a3
	ddotph2r .M1X a1:a0,a2,a5
	ddotph2r .M2 a1:a0,b1,b3
	ddotpl2 .L1 a1:a0,a3,a5:a4
	ddotpl2 .M1 a1:a0,a3
	ddotpl2 .M1X a1:a0,a2,a5:a4
	ddotpl2 .M2 a1:a0,b1,b3:b2
	ddotpl2r .L1 a1:a0,a3,a5
	ddotpl2r .M1 a1:a0,a3
	ddotpl2r .M1X a1:a0,a2,a5
	ddotpl2r .M2 a1:a0,b1,b3
	deal .D1 a1,a2
	deal .M1 a1,a2,a3
	deal .M2 b1,a1
	deal .M2X b1,b2
	dint .S1
	dint a1
	dmv .M1 a1,a2,a5:a4
	dmv .S1 a1,a2
	dmv .S2 a1,b2,b5:b4
	dmv .S2X b1,b2,b5:b4
	dotp2 .L1 a1,a2,a3
	dotp2 .M1 a1,a2
	dotp2 .M1 b1,a2,a3
	dotp2 .M1X a1,a2,a3
	dotp2 .M2 a1,b2,b5:b4
	dotp2 .M2X b3,b4,b7:b6
	dotpn2 .L1 a1,a2,a3
	dotpn2 .M1 a1,a2
	dotpn2 .M1 b1,a2,a3
	dotpn2 .M1X a1,a2,a3
	dotpnrsu2 .L1 a1,a2,a3
	dotpnrsu2 .M1 a1,a2
	dotpnrsu2 .M1 b1,a2,a3
	dotpnrsu2 .M1X a1,a2,a3
	dotpnrus2 .L1 a1,a2,a3
	dotpnrus2 .M1 a1,a2
	dotpnrus2 .M1 a2,b1,a3
	dotpnrus2 .M1X a1,a2,a3
	dotprsu2 .L1 a1,a2,a3
	dotprsu2 .M1 a1,a2
	dotprsu2 .M1 b1,a2,a3
	dotprsu2 .M1X a1,a2,a3
	dotprus2 .L1 a1,a2,a3
	dotprus2 .M1 a1,a2
	dotprus2 .M1 a2,b1,a3
	dotprus2 .M1X a1,a2,a3
	dotpsu4 .L1 a1,a2,a3
	dotpsu4 .M1 a1,a2
	dotpsu4 .M1 b1,a2,a3
	dotpsu4 .M1X a1,a2,a3
	dotpus4 .L1 a1,a2,a3
	dotpus4 .M1 a1,a2
	dotpus4 .M1 a2,b1,a3
	dotpus4 .M1X a1,a2,a3
	dotpu4 .L1 a1,a2,a3
	dotpu4 .M1 a1,a2
	dotpu4 .M1 b1,a2,a3
	dotpu4 .M1X a1,a2,a3
	dpack2 .M1 a0,a1,a3:a2
	dpack2 .L1 a0,a1
	dpack2 .L1 a1,a2,b3:b2
	dpack2 .L2X b3,b4,b7:b6
	dpackx2 .M1 a0,a1,a3:a2
	dpackx2 .L1 a0,a1
	dpackx2 .L1 a1,a2,b3:b2
	dpackx2 .L2X b3,b4,b7:b6
	dpint .S1 a5:a4,a3
	dpint .L1X b5:b4,a3
	dpint .L2 a5:a4,b3
	dpsp .S1 a5:a4,a3
	dpsp .L1X b5:b4,a3
	dpsp .L2 a5:a4,b3
	dptrunc .S1 a5:a4,a3
	dptrunc .L1X b5:b4,a3
	dptrunc .L2 a5:a4,b3
	ext .L1 a1,0,1,a2
	ext .M2 b1,b2,b3
	ext .S1 a1,a1
	ext .S1X a1,0,0,a1
	ext .S2 b1,a1,b1
	clr .S1 a0,-1,0,a1
	clr .S1 a0,32,0,a1
	clr .S1 a0,0,-1,a1
	clr .S1 a0,0,32,a1
	ext .S1 a0,-1,0,a1
	ext .S1 a0,32,0,a1
	ext .S1 a0,0,-1,a1
	ext .S1 a0,0,32,a1
	extu .L1 a1,0,1,a2
	extu .M2 b1,b2,b3
	extu .S1 a1,a1
	extu .S1X a1,0,0,a1
	extu .S2 b1,a1,b1
	extu .S1 a0,-1,0,a1
	extu .S1 a0,32,0,a1
	extu .S1 a0,0,-1,a1
	extu .S1 a0,0,32,a1
	gmpy .L1 a1,a2,a3
	gmpy .M1 a1,a2
	gmpy .M1X a1,a2,a3
	gmpy .M2 a1,b2,b3
	gmpy4 .S1 a1,a2,a3
	gmpy4 .M1 a1,a2,a3,a4
	gmpy4 .M1 b1,a1,a2
	gmpy4 .M2X b1,b2,b3
	idle .S1
	idle a0
	intdp .S1 a5,a3:a2
	intdp .L1 a5
	intdp .L2 b0,a1:a0
	intdp .L1X b5,b3:b2
	intdpu .D1 a5,a3:a2
	intdpu .L1 a5
	intdpu .L2 b0,a1:a0
	intdpu .L1X b5,b3:b2
	intsp .S1 a5,a3
	intsp .L1 a5
	intsp .L2 b0,a1
	intsp .L1X b5,b3
	intspu .D1 a5,a3
	intspu .L1 a5
	intspu .L2 b0,a1
	intspu .L1X b5,b3
	cmtl .D2T1 *b0,a0
	cmtl .D1T1 *a0,a1
	cmtl .L1 *a0,a1
	cmtl .D2T2 *+b0(0),b1
	cmtl .D2T2 *-b0[0],b1
	cmtl .D2T2 *++b0,b1
	cmtl .D2T2 *--b0,b1
	cmtl .D2T2 *b0++,b1
	cmtl .D2T2 *b0--,b1
	cmtl .D2T2 *+b0[b1],b2
	cmtl .D2T2 *a0,b1
	cmtl .D2T2 *b0,a1
	ll .D2T1 *b0,a0
	ll .D1T1 *a0,a1
	ll .S1 *a0,a1
	ll .D2T2 *+b0(0),b1
	ll .D2T2 *-b0[0],b1
	ll .D2T2 *++b0,b1
	ll .D2T2 *--b0,b1
	ll .D2T2 *b0++,b1
	ll .D2T2 *b0--,b1
	ll .D2T2 *+b0[b1],b2
	ll .D2T2 *a0,b1
	ll .D2T2 *b0,a1
	sl .D2T1 a0,*b0
	sl .D1T1 a1,*a0
	sl .L1 a1,*a0
	sl .D2T2 b1,*+b0(0)
	sl .D2T2 b1,*-b0[0]
	sl .D2T2 b1,*++b0
	sl .D2T2 b1,*--b0
	sl .D2T2 b1,*b0++
	sl .D2T2 b1,*b0--
	sl .D2T2 b2,*+b0[b1]
	sl .D2T2 b1,*a0
	sl .D2T2 a1,*b0
	ldb .L1 *a1,a0
	ldb .D1T1 *a1,b1
	ldb .D1T1 *b1,a1
	ldb .D2T2 *a1,b1
	ldb .D2T2 *b1,a1
	ldb .D1T1 *a1
	ldb .D1T1 *+a1[b1],a2
	ldb .D1T1 *+a1,a2
	ldb .D1T1 *-a1,a2
	ldb .D1T1 *a1++[32],a2
	ldb .D1T1 *a1++(32),a2
	ldb .D1T1 *--a1[-1],a2
	ldb .D1T1 *--a1(-1),a2
	ldb .D1T1 *+a1(a2),a3
	ldb .D2T2 *+b14[foo],b16
	ldbu .S1 *a1,a0
	ldbu .D1T1 *a1,b1
	ldbu .D1T1 *b1,a1
	ldbu .D2T2 *a1,b1
	ldbu .D2T2 *b1,a1
	ldbu .D1T1 *a1
	ldbu .D1T1 *+a1[b1],a2
	ldbu .D1T1 *+a1,a2
	ldbu .D1T1 *-a1,a2
	ldbu .D1T1 *a1++[32],a2
	ldbu .D1T1 *a1++(32),a2
	ldbu .D1T1 *--a1[-1],a2
	ldbu .D1T1 *--a1(-1),a2
	ldbu .D1T1 *+a1(a2),a3
	ldbu .D2T2 *+b14[foo],b16
	lddw .L1 *a1,a1:a0
	lddw .D1T1 *a1,b1:b0
	lddw .D1T1 *b1,a1:a0
	lddw .D2T2 *a1,b1:b0
	lddw .D2T2 *b1,a1:a0
	lddw .D1T1 *a1
	lddw .D1T1 *+a1[b1],a3:a2
	lddw .D1T1 *+a1,a3:a2
	lddw .D1T1 *-a1,a3:a2
	lddw .D1T1 *a1++[32],a3:a2
	lddw .D1T1 *a1++(256),a3:a2
	lddw .D1T1 *--a1[-1],a3:a2
	lddw .D1T1 *--a1(-8),a3:a2
	lddw .D1T1 *+a1(a2),a3:a2
	lddw .D2T2 *+b14[foo],b17:b16
	lddw .D1T1 *+a1(1),a3:a2
	lddw .D2T2 *+b14(b15),b17:b16
	ldh .M1 *a1,a0
	ldh .D1T1 *a1,b1
	ldh .D1T1 *b1,a1
	ldh .D2T2 *a1,b1
	ldh .D2T2 *b1,a1
	ldh .D1T1 *a1
	ldh .D1T1 *+a1[b1],a2
	ldh .D1T1 *+a1,a2
	ldh .D1T1 *-a1,a2
	ldh .D1T1 *a1++[32],a2
	ldh .D1T1 *a1++(64),a2
	ldh .D1T1 *--a1[-1],a2
	ldh .D1T1 *--a1(-2),a2
	ldh .D1T1 *+a1(a2),a3
	ldh .D2T2 *+b14[foo],b16
	ldh .D2T2 *+b1(1),b2
	ldhu .S1 *a1,a0
	ldhu .D1T1 *a1,b1
	ldhu .D1T1 *b1,a1
	ldhu .D2T2 *a1,b1
	ldhu .D2T2 *b1,a1
	ldhu .D1T1 *a1
	ldhu .D1T1 *+a1[b1],a2
	ldhu .D1T1 *+a1,a2
	ldhu .D1T1 *-a1,a2
	ldhu .D1T1 *a1++[32],a2
	ldhu .D1T1 *a1++(64),a2
	ldhu .D1T1 *--a1[-1],a2
	ldhu .D1T1 *--a1(-2),a2
	ldhu .D1T1 *+a1(a2),a3
	ldhu .D2T2 *+b14[foo],b16
	ldhu .D2T2 *+b1(1),b2
	ldndw .L1 *a1,a1:a0
	ldndw .D1T1 *a1,b1:b0
	ldndw .D1T1 *b1,a1:a0
	ldndw .D2T2 *a1,b1:b0
	ldndw .D2T2 *b1,a1:a0
	ldndw .D1T1 *a1
	ldndw .D1T1 *+a1[b1],a3:a2
	ldndw .D1T1 *+a1,a3:a2
	ldndw .D1T1 *-a1,a3:a2
	ldndw .D1T1 *a1++[32],a3:a2
	ldndw .D1T1 *a1++(32),a3:a2
	ldndw .D1T1 *--a1[-1],a3:a2
	ldndw .D1T1 *--a1(-1),a3:a2
	ldndw .D2T2 *+b14[foo],b17:b16
	ldnw .S1 *a1,a0
	ldnw .D1T1 *a1,b1
	ldnw .D1T1 *b1,a1
	ldnw .D2T2 *a1,b1
	ldnw .D2T2 *b1,a1
	ldnw .D1T1 *a1
	ldnw .D1T1 *+a1[b1],a2
	ldnw .D1T1 *+a1,a2
	ldnw .D1T1 *-a1,a2
	ldnw .D1T1 *a1++[32],a2
	ldnw .D1T1 *a1++(128),a2
	ldnw .D1T1 *--a1[-1],a2
	ldnw .D1T1 *--a1(-4),a2
	ldnw .D1T1 *+a1(a2),a3
	ldnw .D2T2 *+b14[foo],b16
	ldnw .D2T2 *+b1(2),b2
	ldw .S1 *a1,a0
	ldw .D1T1 *a1,b1
	ldw .D1T1 *b1,a1
	ldw .D2T2 *a1,b1
	ldw .D2T2 *b1,a1
	ldw .D1T1 *a1
	ldw .D1T1 *+a1[b1],a2
	ldw .D1T1 *+a1,a2
	ldw .D1T1 *-a1,a2
	ldw .D1T1 *a1++[32],a2
	ldw .D1T1 *a1++(128),a2
	ldw .D1T1 *--a1[-1],a2
	ldw .D1T1 *--a1(-4),a2
	ldw .D1T1 *+a1(a2),a3
	ldw .D2T2 *+b14[foo],b16
	ldw .D2T2 *+b1(2),b2
	ldb .D2T2 *+b14[-1],b1
	ldb .D2T2 *+b14[32768],b1
	ldbu .D2T2 *+b14[-1],b1
	ldbu .D2T2 *+b14[32768],b1
	ldh .D2T2 *+b14[-1],b1
	ldh .D2T2 *+b14[32768],b1
	ldhu .D2T2 *+b14[-1],b1
	ldhu .D2T2 *+b14[32768],b1
	ldw .D2T2 *+b14[-1],b1
	ldw .D2T2 *+b14[32768],b1
	lmbd .S1 a1,a2,a3
	lmbd .L1 a1,a2
	lmbd .L1 b1,a2,a3
	lmbd .L2X b1,b2,b3
	lmbd .L1 -17,a1,a2
	lmbd .L1 16,a1,a2
	max2 .M1 a1,a2,a3
	max2 .L1 a1,a2
	max2 .L1 b1,a2,a3
	max2 .L2X b1,b2,b3
	max2 .S2X b1,b2,b3
	max2 .S2 a1,b2,b3
	maxu4 .S1 a1,a2,a3
	maxu4 .L1 a1,a2
	maxu4 .L1 b1,a2,a3
	maxu4 .L2X b1,b2,b3
	min2 .M1 a1,a2,a3
	min2 .L1 a1,a2
	min2 .L1 b1,a2,a3
	min2 .L2X b1,b2,b3
	min2 .S2X b1,b2,b3
	min2 .S2 a1,b2,b3
	minu4 .S1 a1,a2,a3
	minu4 .L1 a1,a2
	minu4 .L1 b1,a2,a3
	minu4 .L2X b1,b2,b3
	mpy .L1 a1,a2,a3
	mpy .M1 a1,a2
	mpy .M1 b1,a2,a3
	mpy .M2X b1,b2,b3
	mpy .M2 -17,b1,b2
	mpy .M1 16,a1,a2
	mpy .M2X 0,b2,b3
	mpydp .D1 a1:a0,a1:a0,a1:a0
	mpydp .M1 a1:a0,a1:a0
	mpydp .M1 b1:b0,a1:a0,a3:a2
	mpydp .M2X b1:b0,a1:a0,b1:b0
	mpyh .S1 a1,a2,a3
	mpyh .M1 a1,a2
	mpyh .M1 b1,a2,a3
	mpyh .M2X b1,b2,b3
	mpyhi .D1 a1,a2,a5:a4
	mpyhi .M1 a1,a2
	mpyhi .M1 b1,a2,a5:a4
	mpyhi .M2X b1,b2,b5:b4
	mpyhir .D1 a1,a2,a3
	mpyhir .M1 a1,a2
	mpyhir .M1 b1,a2,a3
	mpyhir .M2X b1,b2,b3
	mpyhl .L1 a1,a2,a3
	mpyhl .M1 a1,a2
	mpyhl .M1 b1,a2,a3
	mpyhl .M2X b1,b2,b3
	mpyhlu .S1 a1,a2,a3
	mpyhlu .M1 a1,a2
	mpyhlu .M1 b1,a2,a3
	mpyhlu .M2X b1,b2,b3
	mpyhslu .S1 a1,a2,a3
	mpyhslu .M1 a1,a2
	mpyhslu .M1 b1,a2,a3
	mpyhslu .M2X b1,b2,b3
	mpyhsu .S1 a1,a2,a3
	mpyhsu .M1 a1,a2
	mpyhsu .M1 b1,a2,a3
	mpyhsu .M2X b1,b2,b3
	mpyhu .D1 a1,a2,a3
	mpyhu .M1 a1,a2
	mpyhu .M1 b1,a2,a3
	mpyhu .M2X b1,b2,b3
	mpyhuls .S1 a1,a2,a3
	mpyhuls .M1 a1,a2
	mpyhuls .M1 b1,a2,a3
	mpyhuls .M2X b1,b2,b3
	mpyhus .S1 a1,a2,a3
	mpyhus .M1 a1,a2
	mpyhus .M1 b1,a2,a3
	mpyhus .M2X b1,b2,b3
	mpyi .L1 a1,a2,a3
	mpyi .M1 a1,a2
	mpyi .M1 b1,a2,a3
	mpyi .M2X b1,b2,b3
	mpyi .M1 -17,a2,a3
	mpyi .M2 16,b2,b3
	mpyid .D1 a1,a2,a3:a2
	mpyid .M1 a1,a2
	mpyid .M1 b1,a2,a3:a2
	mpyid .M2X b1,b2,b3:b2
	mpyid .M1 -17,a2,a3:a2
	mpyid .M2 16,b2,b3:b2
	mpyih .D1 a1,a2,a5:a4
	mpyih .M1 a1,a2
	mpyih .M1 b1,a2,a5:a4
	mpyih .M2X b1,b2,b5:b4
	mpyihr .D1 a1,a2,a3
	mpyihr .M1 a1,a2
	mpyihr .M1 b1,a2,a3
	mpyihr .M2X b1,b2,b3
	mpyil .S1 a1,a2,a5:a4
	mpyil .M1 a1,a2
	mpyil .M1 b1,a2,a5:a4
	mpyil .M2X b1,b2,b5:b4
	mpyilr .L1 a1,a2,a3
	mpyilr .M1 a1,a2
	mpyilr .M1 b1,a2,a3
	mpyilr .M2X b1,b2,b3
	mpylh .S1 a1,a2,a3
	mpylh .M1 a1,a2
	mpylh .M1 b1,a2,a3
	mpylh .M2X b1,b2,b3
	mpylhu .D1 a1,a2,a3
	mpylhu .M1 a1,a2
	mpylhu .M1 b1,a2,a3
	mpylhu .M2X b1,b2,b3
	mpyli .S1 a1,a2,a3:a2
	mpyli .M1 a1,a2
	mpyli .M1 b1,a2,a3:a2
	mpyli .M2X b1,b2,b3:b2
	mpylir .D1 a1,a2,a3
	mpylir .M1 a1,a2
	mpylir .M1 b1,a2,a3
	mpylir .M2X b1,b2,b3
	mpylshu .L1 a1,a2,a3
	mpylshu .M1 a1,a2
	mpylshu .M1 b1,a2,a3
	mpylshu .M2X b1,b2,b3
	mpyluhs .S1 a1,a2,a3
	mpyluhs .M1 a1,a2
	mpyluhs .M1 b1,a2,a3
	mpyluhs .M2X b1,b2,b3
	mpysp .D1 a1,a2,a3
	mpysp .M1 a1,a2
	mpysp .M1 b1,a2,a3
	mpysp .M2X b1,b2,b3
	mpyspdp .L1 a1,a1:a0,a1:a0
	mpyspdp .M1 a1,a1:a0,a1:a0,a1:a0
	mpyspdp .M1 b1,a1:a0,a1:a0
	mpyspdp .M2X b1,b1:b0,b1:b0
	mpysp2dp .S1 a1,a2,a3:a2
	mpysp2dp .M1 a1,a2
	mpysp2dp .M1 b1,a2,a3:a2
	mpysp2dp .M2X b1,b2,b3:b2
	mpysu .D1 a1,a2,a3
	mpysu .M1 a1,a2
	mpysu .M1 b1,a2,a3
	mpysu .M2X b1,b2,b3
	mpysu .M1 -17,a2,a3
	mpysu .M2 16,b2,b3
	mpysu4 .S1 a1,a2,a3:a2
	mpysu4 .M1 a1,a2
	mpysu4 .M1 b1,a2,a3:a2
	mpysu4 .M2X b1,b2,b3:b2
	mpyu .L1 a1,a2,a3
	mpyu .M1 a1,a2
	mpyu .M1 b1,a2,a3
	mpyu .M2X b1,b2,b3
	mpyu4 .D1 a1,a2,a3:a2
	mpyu4 .M1 a1,a2
	mpyu4 .M1 b1,a2,a3:a2
	mpyu4 .M2X b1,b2,b3:b2
	mpyus .S1 a1,a2,a3
	mpyus .M1 a1,a2
	mpyus .M1 b1,a2,a3
	mpyus .M2X b1,b2,b3
	mpyus4 .L1 a1,a2,a3:a2
	mpyus4 .M1 a1,a2
	mpyus4 .M1 b1,a2,a3:a2
	mpyus4 .M2X b1,b2,b3:b2
	mpy2 .D1 a1,a2,a3:a2
	mpy2 .M1 a1,a2
	mpy2 .M1 b1,a2,a3:a2
	mpy2 .M2X b1,b2,b3:b2
	mpy2ir .L1 a1,a2,a3:a2
	mpy2ir .M1 a1,a2
	mpy2ir .M1 b1,a2,a3:a2
	mpy2ir .M2X b1,b2,b3:b2
	mpy32 .L1 a1,a2,a3
	mpy32 .M1 a1,a2
	mpy32 .M1 b1,a2,a3
	mpy32 .M2X b1,b2,b3
	mpy32 .M1 b1,a2,a3:a2
	mpy32 .M1X a1,a2,a5:a4
	mpy32su .L1 a1,a2,a3:a2
	mpy32su .M1 a1,a2
	mpy32su .M2X b1,b2,b3:b2
	mpy32su .M1 b1,a2,a3:a2
	mpy32u .L1 a1,a2,a3:a2
	mpy32u .M1 a1,a2
	mpy32u .M2X b1,b2,b3:b2
	mpy32u .M1 b1,a2,a3:a2
	mpy32us .L1 a1,a2,a3:a2
	mpy32us .M1 a1,a2
	mpy32us .M2X b1,b2,b3:b2
	mpy32us .M1 b1,a2,a3:a2
	mvc .L2 b2,amr
	mvc .S2X amr,a1
	mvc .S2 b2,nonesuch
	mvc .S2 b0,dnum
	mvc .S2 ecr,b0
	mvc .S2 b0,efr
	mvc .S2 icr,b0
	mvc .S2 b0,ifr
	mvc .S2 isr,b0
	mvc .S2 b0,pce1
	mvc .S2 b0,tsch
	mvc .S2 b0,tscl
	mv .M1 a1,a2
	mv .L1 a1,a2,a3
	mv .L1 a1,b2
	mv .L2X b1,b2
	mv .S1 a1,b2
	mv .S2X b1,b2
	mv .D1 a1,b2
	mv .D2X b1,b2
	mvd .L1 a1,a2
	mvd .M1 a3,a4,a5
	mvd .M1 a1,b2
	mvd .M2X b3,b4
	mvk .L1 -17,a0
	mvk .L1 16,a0
	mvk .L1X 0,a0
	mvk .D2 -17,b0
	mvk .D2 16,b0
	mvk .D2X 0,b0
	norm .S1 a1,a0
	norm .L1 a1:a0,a0,a0
	norm .L1X b1:b0,a1
	norm .L2 b1,a1
	norm .L2X b1,b1
	or .M1 a1,a2,a3
	or .L1 a1,a2
	or .D1 -17,a0,a0
	or .D1X 16,b0,a0
	or .L1 -17,a0,a0
	or .L1X 16,b0,a0
	or .S2 -17,b0,b0
	or .S2X 16,a0,b0
	or .D1 a0,a0,b0
	or .D2X b0,b0,b0
	or .L1X a0,a0,a0
	or .S2 b0,b0,a0
	pack2 .D1 a0,a0,a0
	pack2 .L1 a0,a0
	pack2 .S1 a0,a1,b2
	pack2 .L2X b0,b0,b0
	packh2 .M1 a0,a0,a0
	packh2 .L1 a0,a0
	packh2 .S1 a0,a1,b2
	packh2 .L2X b0,b0,b0
	packh4 .S1 a0,a0,a0
	packh4 .L1 a0,a0
	packh4 .L1 a0,a1,b2
	packh4 .L2X b0,b0,b0
	packhl2 .M1 a0,a0,a0
	packhl2 .L1 a0,a0
	packhl2 .S1 a0,a1,b2
	packhl2 .L2X b0,b0,b0
	packlh2 .D1 a0,a0,a0
	packlh2 .L1 a0,a0
	packlh2 .S1 a0,a1,b2
	packlh2 .L2X b0,b0,b0
	packl4 .S1 a0,a0,a0
	packl4 .L1 a0,a0
	packl4 .L1 a0,a1,b2
	packl4 .L2X b0,b0,b0
	rcpdp .L1 a1:a0,a1:a0
	rcpdp .S1 a1:a0
	rcpdp .S1 b1:b0,a1:a0
	rcpdp .S2X a1:a0,b1:b0
	rcpsp .L1 a0,a0
	rcpsp .S1 a0,a0,a0
	rcpsp .S2 b0,a0
	rcpsp .S1X a0,a0
	rint .S2
	rint a0
	rotl .S1 a0,a0,a0
	rotl .M1 a0,a0
	rotl .M1 a0,b0,a0
	rotl .M2X b0,b0,b0
	rotl .M1 a0,-1,a0
	rotl .M2 b0,32,b0
	rotl .M2X b0,0,b0
	rpack2 .L1 a0,a0,a0
	rpack2 .S1 a0,a0
	rpack2 .S2 a0,b0,b0
	rpack2 .S1X a0,a0,a0
	rsqrdp .L1 a1:a0,a1:a0
	rsqrdp .S1 a1:a0
	rsqrdp .S1 b1:b0,a1:a0
	rsqrdp .S2X a1:a0,b1:b0
	rsqrsp .L1 a0,a0
	rsqrsp .S1 a0,a0,a0
	rsqrsp .S2 b0,a0
	rsqrsp .S1X a0,a0
	sadd .D1 a1,a2,a3
	sadd .L1 a1,a2
	sadd .S1 0,a1,a2
	sadd .L1X 0,a1:a0,a1:a0
	sadd .L1 b0,a0,a0
	sadd .L1X a0,a0,a0
	sadd .L2 -17,b0,b0
	sadd .L2 16,b0,b0
	sadd .L1 -17,a1:a0,a1:a0
	sadd .L1 16,a1:a0,a1:a0
	sadd2 .L1 a0,a0,a0
	sadd2 .S1 a0,a0
	sadd2 .S2 a0,b0,b0
	sadd2 .S2X b0,b0,b0
	saddsub .S1 a0,a0,a1:a0
	saddsub .L1 a0,a0
	saddsub .L1 a0,a0,a0
	saddsub .L2 a0,b0,b1:b0
	saddsub .L2X b0,b0,b1:b0
	saddsub2 .S1 a0,a0,a1:a0
	saddsub2 .L1 a0,a0
	saddsub2 .L1 a0,a0,a0
	saddsub2 .L2 a0,b0,b1:b0
	saddsub2 .L2X b0,b0,b1:b0
	saddsu2 .L1 a0,a0,a0
	saddsu2 .S1 a0
	saddsu2 .S2 b0,a0,b0
	saddsu2 .S2X b0,b0,b0
	saddus2 .M1 a0,a0,a0
	saddus2 .S1 a0,a0
	saddus2 .S1 b0,a0,a0
	saddus2 .S1X a0,a0,a0
	saddu4 .D1 a0,a0,a0
	saddu4 .S1 a0,a0
	saddu4 .S1 b0,a0,a0
	saddu4 .S1X a0,a0,a0
	sat .S1 a1:a0,a0
	sat .L1X b1:b0,a0
	sat .L1 a1:a0
	sat .L1 b1:b0,a0
	set .L1 a0,0,0,a0
	set .S1 a0
	set .S1 a0,-1,0,a0
	set .S1 a0,32,0,a0
	set .S1 a0,0,-1,a0
	set .S1 a0,0,32,a0
	set .S1X b0,0,0,a0
	set .S1X a0,a0,a0
	set .S2 b0,a0,b0
	shfl .S1 a0,a0
	shfl .M1 a0,a0,a0
	shfl .M1 a0,b0
	shfl .M2X b0,b0
	shfl3 .M1 a0,a0,a1:a0
	shfl3 .L1 a0,a0
	shfl3 .L1 b0,a0,a1:a0
	shfl3 .L2X b0,b0,b1:b0
	shl .L1 a0,a0,a0
	shl .S1 a0,a0
	shl .S1X a1:a0,a0,a1:a0
	shl .S1 a0,b0,a0
	shl .S2X b0,b0,b1:b0
	shl .S1 a0,-1,a0
	shl .S1 a0,32,a0
	shl .S2 b1:b0,-1,b1:b0
	shl .S2 b1:b0,32,b1:b0
	shl .S1X b0,-1,a1:a0
	shl .S1X b0,32,a1:a0
	shlmb .D1 a0,a0,a0
	shlmb .L1 a0,a0
	shlmb .L1 b0,a0,a0
	shlmb .L2X b0,b0,b0
	shlmb .S1 b0,a0,a0
	shlmb .S2X b0,b0,b0
	shr .L1 a0,a0,a0
	shr .S1 a0,a0
	shr .S1X a1:a0,a0,a1:a0
	shr .S1 a0,b0,a0
	shr .S1 a0,-1,a0
	shr .S1 a0,32,a0
	shr .S2 b1:b0,-1,b1:b0
	shr .S2 b1:b0,32,b1:b0
	shr2 .L1 a0,a0,a0
	shr2 .L1 a0,0,a0
	shr2 .S1 a0,a0
	shr2 .S1 a1,b0,a0
	shr2 .S2X b0,b0,b0
	shr2 .S1 a0,-1,a0
	shr2 .S1 a0,32,a0
	shrmb .M1 a0,a0,a0
	shrmb .L1 a0,a0
	shrmb .L1 b0,a0,a0
	shrmb .L2X b0,b0,b0
	shrmb .S1 b0,a0,a0
	shrmb .S2X b0,b0,b0
	shru .D1 a0,a0,a0
	shru .S1 a0,a0
	shru .S1X a1:a0,a0,a1:a0
	shru .S1 a0,b0,a0
	shru .S1 a0,-1,a0
	shru .S1 a0,32,a0
	shru .S2 b1:b0,-1,b1:b0
	shru .S2 b1:b0,32,b1:b0
	shru2 .L1 a0,a0,a0
	shru2 .L1 a0,0,a0
	shru2 .S1 a0,a0
	shru2 .S1 a1,b0,a0
	shru2 .S2X b0,b0,b0
	shru2 .S1 a0,-1,a0
	shru2 .S1 a0,32,a0
	smpy .L1 a0,a0,a0
	smpy .M1 a0,a0
	smpy .M2 a0,b0,b0
	smpy .M1X a0,a0,a0
	smpyh .S1 a0,a0,a0
	smpyh .M1 a0,a0
	smpyh .M2 a0,b0,b0
	smpyh .M1X a0,a0,a0
	smpyhl .D1 a0,a0,a0
	smpyhl .M1 a0,a0
	smpyhl .M2 a0,b0,b0
	smpyhl .M1X a0,a0,a0
	smpylh .L1 a0,a0,a0
	smpylh .M1 a0,a0
	smpylh .M2 a0,b0,b0
	smpylh .M1X a0,a0,a0
	smpy2 .S1 a0,a0,a1:a0
	smpy2 .M1 a0,a0
	smpy2 .M2 a0,b0,b1:b0
	smpy2 .M2X b0,b0,b1:b0
	smpy32 .L1 a0,a0,a0
	smpy32 .M1 a0,a0
	smpy32 .M2 a0,b0,b0
	smpy32 .M1X a0,a0,a0
	spack2 .L1 a0,a0,a0
	spack2 .S1 a0,a0
	spack2 .S1 b0,a0,a0
	spack2 .S2X b0,b0,b0
	spacku4 .L1 a0,a0,a0
	spacku4 .S1 a0,a0
	spacku4 .S1 b0,a0,a0
	spacku4 .S2X b0,b0,b0
	spdp .M1 a0,a1:a0
	spdp .S1 a0
	spdp .S1 a0,b1:b0
	spdp .S2X b0,b1:b0
	spint .S1 a0,a0
	spint .L1 a0,a0,a0
	spint .L2 b0,a0
	spint .L1X a0,a0
	sptrunc .D1 a0,a0
	sptrunc .L1 a0,a0,a0
	sptrunc .L2 b0,a0
	sptrunc .L1X a0,a0
	sshl .L1 a0,a0,a0
	sshl .S1 a0,a0
	sshl .S1 a0,b0,a0
	sshl .S1X a0,a0,a0
	sshl .S2 b0,-1,b0
	sshl .S2 b0,32,b0
	sshvl .S1 a0,a0,a0
	sshvl .M1 a0,a0
	sshvl .M1 a0,b0,a0
	sshvl .M1X a0,a0,a0
	sshvr .L1 a0,a0,a0
	sshvr .M1 a0,a0
	sshvr .M1 a0,b0,a0
	sshvr .M1X a0,a0,a0
	ssub .S1 a0,a0,a0
	ssub .L1 a0,a0
	ssub .L1 a0,a0,b0
	ssub .L1X a0,a0,a0
	ssub .L2 -17,b0,b0
	ssub .L2 16,b0,b0
	ssub .L1X 0,a1:a0,a1:a0
	ssub .L1 -17,a1:a0,a1:a0
	ssub .L1 16,a1:a0,a1:a0
	ssub2 .S1 a0,a0,a0
	ssub2 .L1 a0,a0
	ssub2 .L1 a0,b0,a0
	ssub2 .L1X a0,a0,a0
	stb .L1 a0,*a1
	stb .D1T1 b1,*a1
	stb .D1T1 a1,*b1
	stb .D2T2 b1,*a1
	stb .D2T2 a1,*b1
	stb .D1T1 *a1
	stb .D1T1 a2,*+a1[b1]
	stb .D1T1 a2,*+a1
	stb .D1T1 a2,*-a1
	stb .D1T1 a2,*a1++[32]
	stb .D1T1 a2,*a1++(32)
	stb .D1T1 a2,*--a1[-1]
	stb .D1T1 a2,*--a1(-1)
	stb .D1T1 a3,*+a1(a2)
	stb .D2T2 b16,*+b14[foo]
	stb .D2T2 b1,*+b14[-1]
	stb .D2T2 b1,*+b14[32768]
	stdw .L1 a1:a0,*a1
	stdw .D1T1 b1:b0,*a1
	stdw .D1T1 a1:a0,*b1
	stdw .D2T2 b1:b0,*a1
	stdw .D2T2 a1:a0,*b1
	stdw .D1T1 *a1
	stdw .D1T1 a3:a2,*+a1[b1]
	stdw .D1T1 a3:a2,*+a1
	stdw .D1T1 a3:a2,*-a1
	stdw .D1T1 a3:a2,*a1++[32]
	stdw .D1T1 a3:a2,*a1++(256)
	stdw .D1T1 a3:a2,*--a1[-1]
	stdw .D1T1 a3:a2,*--a1(-8)
	stdw .D1T1 a3:a2,*+a1(a2)
	stdw .D2T2 b17:b16,*+b14[foo]
	stdw .D1T1 a3:a2,*+a1(1)
	stdw .D2T2 b17:b16,*+b14(b15)
	sth .M1 a0,*a1
	sth .D1T1 b1,*a1
	sth .D1T1 a1,*b1
	sth .D2T2 b1,*a1
	sth .D2T2 a1,*b1
	sth .D1T1 *a1
	sth .D1T1 a2,*+a1[b1]
	sth .D1T1 a2,*+a1
	sth .D1T1 a2,*-a1
	sth .D1T1 a2,*a1++[32]
	sth .D1T1 a2,*a1++(64)
	sth .D1T1 a2,*--a1[-1]
	sth .D1T1 a2,*--a1(-2)
	sth .D1T1 a3,*+a1(a2)
	sth .D2T2 b16,*+b14[foo]
	sth .D2T2 b2,*+b1(1)
	sth .D2T2 b1,*+b14[-1]
	sth .D2T2 b1,*+b14[32768]
	stndw .L1 a1:a0,*a1
	stndw .D1T1 b1:b0,*a1
	stndw .D1T1 a1:a0,*b1
	stndw .D2T2 b1:b0,*a1
	stndw .D2T2 a1:a0,*b1
	stndw .D1T1 *a1
	stndw .D1T1 a3:a2,*+a1[b1]
	stndw .D1T1 a3:a2,*+a1
	stndw .D1T1 a3:a2,*-a1
	stndw .D1T1 a3:a2,*a1++[32]
	stndw .D1T1 a3:a2,*a1++(32)
	stndw .D1T1 a3:a2,*--a1[-1]
	stndw .D1T1 a3:a2,*--a1(-1)
	stndw .D2T2 b17:b16,*+b14[foo]
	stnw .S1 a0,*a1
	stnw .D1T1 b1,*a1
	stnw .D1T1 a1,*b1
	stnw .D2T2 b1,*a1
	stnw .D2T2 a1,*b1
	stnw .D1T1 *a1
	stnw .D1T1 a2,*+a1[b1]
	stnw .D1T1 a2,*+a1
	stnw .D1T1 a2,*-a1
	stnw .D1T1 a2,*a1++[32]
	stnw .D1T1 a2,*a1++(128)
	stnw .D1T1 a2,*--a1[-1]
	stnw .D1T1 a2,*--a1(-4)
	stnw .D1T1 a3,*+a1(a2)
	stnw .D2T2 b16,*+b14[foo]
	stnw .D2T2 b2,*+b1(2)
	stw .S1 a0,*a1
	stw .D1T1 b1,*a1
	stw .D1T1 a1,*b1
	stw .D2T2 b1,*a1
	stw .D2T2 a1,*b1
	stw .D1T1 *a1
	stw .D1T1 a2,*+a1[b1]
	stw .D1T1 a2,*+a1
	stw .D1T1 a2,*-a1
	stw .D1T1 a2,*a1++[32]
	stw .D1T1 a2,*a1++(128)
	stw .D1T1 a2,*--a1[-1]
	stw .D1T1 a2,*--a1(-4)
	stw .D1T1 a3,*+a1(a2)
	stw .D2T2 b16,*+b14[foo]
	stw .D2T2 b2,*+b1(2)
	stw .D2T2 b1,*+b14[-1]
	stw .D2T2 b1,*+b14[32768]
	neg .D1 a1,a2
	neg .S1 a1:a0,a1:a0
	neg .S1 a1,a1,a1
	neg .S1 a1,b1
	neg .S1X a1,a1
	neg .L2X b1:b0,b1:b0
	neg .L2 b0,a0
	neg .L2X b0,b0
	sub .M1 a0,a0,a0
	sub .L1 a0,a0
	sub .L1 b0,b0,a0
	sub .L2X b0,b0,b0
	sub .L1X 0,a1:a0,a1:a0
	sub .L2 -17,b0,b0
	sub .L2 16,b0,b0
	sub .L1 -17,a1:a0,a1:a0
	sub .L1 16,a1:a0,a1:a0
	sub .S1 a0,a0
	sub .S1 a0,a0,b0
	sub .S1X a0,a0,a0
	sub .S1 -17,a0,a0
	sub .S1 16,a0,a0
	sub .S1 0,a1:a0,a1:a0
	sub .D1 a0
	sub .D1 b0,a0,a0
	sub .D1X a0,a0,a0
	sub .D1X b0,0,a0
	sub .D1 a0,-1,a0
	sub .D1 a0,32,a0
	subab .S1 a0,a0,a0
	subab .D1 a0,a0
	subab .D1 a0,b0,a0
	subab .D1X a0,b0,a0
	subab .D1X b0,0,a0
	subab .D2 b0,-1,b0
	subab .D2 b14,32,b14
	subabs4 .S1 a0,a0,a0
	subabs4 .L1 a0,a0
	subabs4 .L1 a0,a0,b0
	subabs4 .L2X b0,b0,b0
	subah .M1 a0,a0,a0
	subah .D1 a0,a0
	subah .D1 a0,b0,a0
	subah .D1X a0,b0,a0
	subah .D1X b0,0,a0
	subah .D2 b0,-1,b0
	subah .D2 b14,32,b14
	subaw .L1 a0,a0,a0
	subaw .D1 a0,a0
	subaw .D1 a0,b0,a0
	subaw .D1X a0,b0,a0
	subaw .D1X b0,0,a0
	subaw .D2 b0,-1,b0
	subaw .D2 b14,32,b14
	subc .S1 a0,a0,a0
	subc .L1 a0,a0
	subc .L1 b0,a0,a0
	subc .L2X b0,b0,b0
	subdp .D1 a1:a0,a1:a0,a1:a0
	subdp .L1 a1:a0
	subdp .L1 b1:b0,a1:a0,a1:a0
	subdp .L1X a1:a0,a1:a0,a1:a0
	subdp .S1 b1:b0,a1:a0,a1:a0
	subdp .S1X a1:a0,a1:a0,a1:a0
	subsp .M1 a0,a0,a0
	subsp .L1 a0,a0
	subsp .L1 a0,a0,b0
	subsp .L2X b0,b0,b0
	subsp .S1 a0,a0
	subsp .S1 a0,a0,b0
	subsp .S2X b0,b0,b0
	subu .S1 a0,a0,a1:a0
	subu .L1 a0,a0
	subu .L1 a0,a0,a0
	subu .L2 b0,b0,a1:a0
	subu .L1X a0,a0,a1:a0
	sub2 .M1 a0,a0,a0
	sub2 .L1 a0,a0
	sub2 .L1 a0,a0,b0
	sub2 .L2X b0,b0,b0
	sub2 .S1 a0,a0
	sub2 .S1 a0,a0,b0
	sub2 .S2X b0,b0,b0
	sub2 .D1 a0,a0
	sub2 .D1 a0,a0,b0
	sub2 .D2X b0,b0,b0
	sub4 .S1 a0,a0,a0
	sub4 .L1 a0,a0
	sub4 .L1 a0,a0,b0
	sub4 .L2X b0,b0,b0
	swap2 .D1 a0,a0
	swap2 .L1 a0,a0,a0
	swap2 .L1X b0,a0
	swap2 .L2 a0,b0
	swap2 .S1 a0,a0,a0
	swap2 .S1X b0,a0
	swap2 .S2 a0,b0
	swap4 .S1 a0,a0
	swap4 .L1 a0
	swap4 .L1 a0,b0
	swap4 .L1X a0,a0
	swe .S1
	swe a0
	swenr .L1
	swenr b0
	unpkhu4 .D1 a0,a0
	unpkhu4 .L1 a0,a0,a0
	unpkhu4 .L1 a0,b0
	unpkhu4 .L2X b0,b0
	unpkhu4 .S1 a0,a0,a0
	unpkhu4 .S1 a0,b0
	unpkhu4 .S2X b0,b0
	unpklu4 .M1 a0,a0
	unpklu4 .L1 a0,a0,a0
	unpklu4 .L1 a0,b0
	unpklu4 .L2X b0,b0
	unpklu4 .S1 a0,a0,a0
	unpklu4 .S1 a0,b0
	unpklu4 .S2X b0,b0
	not .M1 a0,a0
	not .L1 a0,a0,a0
	not .L1 a0,b0
	not .L1X a0,a0
	not .S1 a0,a0,a0
	not .S1 a0,b0
	not .S1X a0,a0
	not .D1 a0,a0,a0
	not .D1 a0,b0
	not .D1X a0,a0
	xor .M1 a0,a0,a0
	xor .L1 a0,a0
	xor .L2 b0,b0,a0
	xor .L2X b0,b0,b0
	xor .L1 -17,a0,a0
	xor .L1 16,a0,a0
	xor .S1 a0,a0
	xor .S2 b0,b0,a0
	xor .S2X b0,b0,b0
	xor .S1 -17,a0,a0
	xor .S1 16,a0,a0
	xor .D1 a0,a0
	xor .D2 b0,b0,a0
	xor .D2X b0,b0,b0
	xor .D1 -17,a0,a0
	xor .D1 16,a0,a0
	xormpy .L1 a0,a0,a0
	xormpy .M1 a0,a0
	xormpy .M1 b0,a0,a0
	xormpy .M1X a0,a0,a0
	xpnd2 .S1 a0,a0
	xpnd2 .M1 a0,a0,a0
	xpnd2 .M1 a0,b0
	xpnd2 .M1X a0,a0
	xpnd4 .L1 a0,a0
	xpnd4 .M1 a0,a0,a0
	xpnd4 .M1 a0,b0
	xpnd4 .M1X a0,a0
	zero .M1 a0
	zero .L1 a0,a0
	zero .L2 a0
	zero .D1 a0,a0
	zero .D2 a0
	zero .S1 a0,a0
	zero .S2 a0
	sub .L1 a0,17,a0
	sub .L1 a0,-16,a0
	sub .L1 a1:a0,17,a1:a0
	sub .L1 a1:a0,-16,a1:a0
	sub .S1 a0,17,a0
	sub .S1 a0,-16,a0
	addab .D1X b13,0,a5
	addah .D1X b13,0,a5
	addaw .D1X b13,0,a5
