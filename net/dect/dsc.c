/*
 * DECT Standard Cipher
 *
 * Copyright (c) 2010 Erik Tews <e_tews@cdc.informatik.tu-darmstadt.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <net/dect/dsc.h>

#define R1_LEN			17
#define R2_LEN			19
#define R3_LEN			21
#define R4_LEN			23

#define MASK_R1			(65536 | 32)
#define MASK_R2			(262144 | 4096 | 8 | 4)
#define MASK_R3			(1048576 | 2)
#define MASK_R4			(256 | 4194304)

#define R1_CLOCKMASK		(1 << 8)
#define R2_CLOCKMASK		(1 << 9)
#define R3_CLOCKMASK		(1 << 10)

#define R1_R4_CLOCKMASK		(1 << 0)
#define R2_R4_CLOCKMASK		(1 << 1)
#define R3_R4_CLOCKMASK		(1 << 2)

static uint32_t clock(uint32_t lfsr, int length, uint32_t mask)
{
	return (lfsr >> 1) ^ (-(lfsr & 1) & mask);
}

static uint32_t combine(uint32_t comb, uint32_t r1, uint32_t r2, uint32_t r3)
{
	uint32_t c, x10, x11, x20, x21, x30, x31;

	c = comb;
	x10 = r1 & 1;
	x11 = (r1 >> 1) & 1;
	x20 = r2 & 1;
	x21 = (r2 >> 1) & 1;
	x30 = r3 & 1;
	x31 = (r3 >> 1) & 1;

	return (x11 & x10 & c) ^
	       (x20 & x11 & x10) ^
	       (x21 & x10 & c) ^
	       (x21 & x20 & x10) ^
	       (x30 & x10 & c) ^
	       (x30 & x20 & x10) ^
	       (x11 & c) ^
	       (x11 & x10) ^
	       (x20 & x11) ^
	       (x30 & c) ^
	       (x31 & c) ^
	       (x31 & x10) ^
	       (x21) ^
	       (x31);
}

void dect_dsc_keystream(uint64_t iv, const uint8_t *key,
			uint8_t *output, unsigned int len)
{
	uint8_t input[16];
	uint32_t R1, R2, R3, R4, N1, N2, N3, COMB;
	unsigned int i, keybit;

	memset(output, 0, len);
	input[0] = iv & 0xff;
	input[1] = (iv >> 8) & 0xff;
	input[2] = (iv >> 16) & 0xff;
	input[3] = (iv >> 24) & 0xff;
	input[4] = (iv >> 32) & 0xff;
	for (i = 5; i < 8; i++)
		input[i] = 0;
	for (i = 0; i < 8; i++)
		input[i + 8] = key[i];

	R1 = R2 = R3 = R4 = COMB = 0;

	/* load IV and KEY */
	for (i = 0; i < 128; i++) {
		keybit = (input[i / 8] >> ((i) & 7)) & 1;
		R1 = clock(R1, R1_LEN, MASK_R1) ^ (keybit << (R1_LEN - 1));
		R2 = clock(R2, R2_LEN, MASK_R2) ^ (keybit << (R2_LEN - 1));
		R3 = clock(R3, R3_LEN, MASK_R3) ^ (keybit << (R3_LEN - 1));
		R4 = clock(R4, R4_LEN, MASK_R4) ^ (keybit << (R4_LEN - 1));
	}

	for (i = 0; i < 40 + (len * 8); i++) {
		N1 = R1;
		N2 = R2;
		N3 = R3;
		COMB = combine(COMB, R1, R2, R3);
		if (((R2 & R2_CLOCKMASK) != 0) ^
		    ((R3 & R3_CLOCKMASK) != 0) ^
		    ((R4 & R1_R4_CLOCKMASK) != 0))
			N1 = clock(R1, R1_LEN, MASK_R1);
		if (((R1 & R1_CLOCKMASK) != 0) ^
		    ((R3 & R3_CLOCKMASK) != 0) ^
		    ((R4 & R2_R4_CLOCKMASK) != 0))
			N2 = clock(R2, R2_LEN, MASK_R2);
		if (((R1 & R1_CLOCKMASK) != 0) ^
		    ((R2 & R2_CLOCKMASK) != 0) ^
		    ((R4 & R3_R4_CLOCKMASK) != 0))
			N3 = clock(R3, R3_LEN, MASK_R3);

		/* Check whether any registers are zero after 11 pre-ciphering
		 * steps. If a register is all-zero after 11 steps, set input
		 * bit to one (see U.S. patent 5608802)
		 */
		if (i == 11) {
			if (!R1)
				N1 ^= (1 << (R1_LEN - 1));
			if (!R2)
				N2 ^= (1 << (R2_LEN - 1));
			if (!R3)
				N3 ^= (1 << (R3_LEN - 1));
			if (!R4)
				R4 ^= (1 << (R4_LEN - 1));
		}

		N1 = clock(N1, R1_LEN, MASK_R1);
		R1 = clock(N1, R1_LEN, MASK_R1);
		N2 = clock(N2, R2_LEN, MASK_R2);
		R2 = clock(N2, R2_LEN, MASK_R2);
		N3 = clock(N3, R3_LEN, MASK_R3);
		R3 = clock(N3, R3_LEN, MASK_R3);
		R4 = clock(R4, R4_LEN, MASK_R4);
		R4 = clock(R4, R4_LEN, MASK_R4);
		R4 = clock(R4, R4_LEN, MASK_R4);

		if (i >= 40)
			output[(i - 40) / 8] |= ((COMB) << (7 - ((i - 40) & 7)));
	}
}
