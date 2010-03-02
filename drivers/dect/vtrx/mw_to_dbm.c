/*
 * DECT virtual transceiver
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <net/dect/transceiver.h>
#include "vtrx.h"

static const struct {
	u64		mw;
	int		dbm;
} mw_to_dbm_tbl[] = {
	{ 5ULL,			-93 },
	{ 6ULL,			-92 },
	{ 7ULL,			-91 },
	{ 10ULL,		-90 },
	{ 12ULL,		-89 },
	{ 15ULL,		-88 },
	{ 19ULL,		-87 },
	{ 25ULL,		-86 },
	{ 31ULL,		-85 },
	{ 39ULL,		-84 },
	{ 50ULL,		-83 },
	{ 63ULL,		-82 },
	{ 79ULL,		-81 },
	{ 100ULL,		-80 },
	{ 125ULL,		-79 },
	{ 158ULL,		-78 },
	{ 199ULL,		-77 },
	{ 251ULL,		-76 },
	{ 316ULL,		-75 },
	{ 398ULL,		-74 },
	{ 501ULL,		-73 },
	{ 630ULL,		-72 },
	{ 794ULL,		-71 },
	{ 1000ULL,		-70 },
	{ 1258ULL,		-69 },
	{ 1584ULL,		-68 },
	{ 1995ULL,		-67 },
	{ 2511ULL,		-66 },
	{ 3162ULL,		-65 },
	{ 3981ULL,		-64 },
	{ 5011ULL,		-63 },
	{ 6309ULL,		-62 },
	{ 7943ULL,		-61 },
	{ 10000ULL,		-60 },
	{ 12589ULL,		-59 },
	{ 15848ULL,		-58 },
	{ 19952ULL,		-57 },
	{ 25118ULL,		-56 },
	{ 31622ULL,		-55 },
	{ 39810ULL,		-54 },
	{ 50118ULL,		-53 },
	{ 63095ULL,		-52 },
	{ 79432ULL,		-51 },
	{ 100000ULL,		-50 },
	{ 125892ULL,		-49 },
	{ 158489ULL,		-48 },
	{ 199526ULL,		-47 },
	{ 251188ULL,		-46 },
	{ 316227ULL,		-45 },
	{ 398107ULL,		-44 },
	{ 501187ULL,		-43 },
	{ 630957ULL,		-42 },
	{ 794328ULL,		-41 },
	{ 1000000ULL,		-40 },
	{ 1258925ULL,		-39 },
	{ 1584893ULL,		-38 },
	{ 1995262ULL,		-37 },
	{ 2511886ULL,		-36 },
	{ 3162277ULL,		-35 },
	{ 3981071ULL,		-34 },
	{ 5011872ULL,		-33 },
	{ 6309573ULL,		-32 },
	{ 7943282ULL,		-31 },
	{ 10000000ULL,		-30 },
	{ 12589254ULL,		-29 },
	{ 15848931ULL,		-28 },
	{ 19952623ULL,		-27 },
	{ 25118864ULL,		-26 },
	{ 31622776ULL,		-25 },
	{ 39810717ULL,		-24 },
	{ 50118723ULL,		-23 },
	{ 63095734ULL,		-22 },
	{ 79432823ULL,		-21 },
	{ 100000000ULL,		-20 },
	{ 125892541ULL,		-19 },
	{ 158489319ULL,		-18 },
	{ 199526231ULL,		-17 },
	{ 251188643ULL,		-16 },
	{ 316227766ULL,		-15 },
	{ 398107170ULL,		-14 },
	{ 501187233ULL,		-13 },
	{ 630957344ULL,		-12 },
	{ 794328234ULL,		-11 },
	{ 1000000000ULL,	-10 },
	{ 1258925411ULL,	-9 },
	{ 1584893192ULL,	-8 },
	{ 1995262314ULL,	-7 },
	{ 2511886431ULL,	-6 },
	{ 3162277660ULL,	-5 },
	{ 3981071705ULL,	-4 },
	{ 5011872336ULL,	-3 },
	{ 6309573444ULL,	-2 },
	{ 7943282347ULL,	-1 },
	{ 10000000000ULL,	0 },
	{ 12589254117ULL,	1 },
	{ 15848931924ULL,	2 },
	{ 19952623149ULL,	3 },
	{ 25118864315ULL,	4 },
	{ 31622776601ULL,	5 },
	{ 39810717055ULL,	6 },
	{ 50118723362ULL,	7 },
	{ 63095734448ULL,	8 },
	{ 79432823472ULL,	9 },
	{ 100000000000ULL,	10 },
	{ 125892541179ULL,	11 },
	{ 158489319246ULL,	12 },
	{ 199526231496ULL,	13 },
	{ 251188643150ULL,	14 },
	{ 316227766016ULL,	15 },
	{ 398107170553ULL,	16 },
	{ 501187233627ULL,	17 },
	{ 630957344480ULL,	18 },
	{ 794328234724ULL,	19 },
	{ 1000000000000ULL,	20 },
	{ 1258925411794ULL,	21 },
	{ 1584893192461ULL,	22 },
	{ 1995262314968ULL,	23 },
	{ 2511886431509ULL,	24 },
};

int dect_mw_to_dbm(u64 mw)
{
	unsigned int min, max, mid;
	u64 val;

	min = 0;
	max = ARRAY_SIZE(mw_to_dbm_tbl) - 1;

	while (min < max) {
		mid = min + (max - min) / 2;

		val = mw_to_dbm_tbl[mid].mw;
		if (val < mw)
			min = mid + 1;
		else
			max = mid;
	}

	if (val > mw) {
		if (mid == 0)
			return 0;
		mid--;
	}

	return mw_to_dbm_tbl[mid].dbm;
}
