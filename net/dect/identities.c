/*
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/dect.h>
#include <net/dect/dect.h>

bool dect_ari_masked_cmp(const struct dect_ari *a1, const struct dect_ari *a2,
			 const struct dect_ari *m)
{
	/* An empty class mask implies a wildcard for everything */
	if (!m->arc)
		return false;
	if (a1->arc != a2->arc)
		return true;

	if ((a1->fpn ^ a2->fpn) & m->fpn)
		return true;

	switch (a1->arc) {
	case DECT_ARC_A:
		return  ((a1->emc ^ a2->emc) & m->emc);
	case DECT_ARC_B:
		return (((a1->eic ^ a2->eic) & m->eic) |
		        ((a1->fps ^ a2->fps) & m->fps));
	case DECT_ARC_C:
		return (((a1->poc ^ a2->poc) & m->poc) |
		        ((a1->fps ^ a2->fps) & m->fps));
	case DECT_ARC_D:
		return  ((a1->gop ^ a2->gop) & m->gop);
	case DECT_ARC_E:
		return  ((a1->fil ^ a2->fil) & m->fil);
	default:
		return true;
	}
}

bool dect_ari_cmp(const struct dect_ari *a1, const struct dect_ari *a2)
{
	static const struct dect_ari mask = {
		.arc = ~0,
		.fpn = ~0,
		.fps = ~0,
		{ ~0 }
	};
	return dect_ari_masked_cmp(a1, a2, &mask);
}

u8 dect_parse_ari(struct dect_ari *ari, u64 a)
{
	ari->arc = (a & DECT_ARI_ARC_MASK) >> DECT_ARI_ARC_SHIFT;
	switch (ari->arc) {
	case DECT_ARC_A:
		ari->emc = (a & DECT_ARI_A_EMC_MASK) >> DECT_ARI_A_EMC_SHIFT;
		ari->fpn = (a & DECT_ARI_A_FPN_MASK) >> DECT_ARI_A_FPN_SHIFT;
		return DECT_ARC_A_LEN;
	case DECT_ARC_B:
		ari->eic = (a & DECT_ARI_B_EIC_MASK) >> DECT_ARI_B_EIC_SHIFT;
		ari->fpn = (a & DECT_ARI_B_FPN_MASK) >> DECT_ARI_B_FPN_SHIFT;
		ari->fps = (a & DECT_ARI_B_FPS_MASK) >> DECT_ARI_B_FPS_SHIFT;
		return DECT_ARC_B_LEN;
	case DECT_ARC_C:
		ari->poc = (a & DECT_ARI_C_POC_MASK) >> DECT_ARI_C_POC_SHIFT;
		ari->fpn = (a & DECT_ARI_C_FPN_MASK) >> DECT_ARI_C_FPN_SHIFT;
		ari->fps = (a & DECT_ARI_C_FPS_MASK) >> DECT_ARI_C_FPS_SHIFT;
		return DECT_ARC_C_LEN;
	case DECT_ARC_D:
		ari->gop = (a & DECT_ARI_D_GOP_MASK) >> DECT_ARI_D_GOP_SHIFT;
		ari->fpn = (a & DECT_ARI_D_FPN_MASK) >> DECT_ARI_D_FPN_SHIFT;
		return DECT_ARC_D_LEN;
	case DECT_ARC_E:
		ari->fil = (a & DECT_ARI_E_FIL_MASK) >> DECT_ARI_E_FIL_SHIFT;
		ari->fpn = (a & DECT_ARI_E_FPN_MASK) >> DECT_ARI_E_FPN_SHIFT;
		return DECT_ARC_E_LEN;
	default:
		return 0;
	}
}
EXPORT_SYMBOL_GPL(dect_parse_ari);

u64 dect_build_ari(const struct dect_ari *ari)
{
	u64 a = 0;

	a |= (u64)ari->arc << DECT_ARI_ARC_SHIFT;
	switch (ari->arc) {
	case DECT_ARC_A:
		a |= (u64)ari->emc << DECT_ARI_A_EMC_SHIFT;
		a |= (u64)ari->fpn << DECT_ARI_A_FPN_SHIFT;
		break;
	case DECT_ARC_B:
		a |= (u64)ari->eic << DECT_ARI_B_EIC_SHIFT;
		a |= (u64)ari->fpn << DECT_ARI_B_FPN_SHIFT;
		a |= (u64)ari->fps << DECT_ARI_B_FPS_SHIFT;
		break;
	case DECT_ARC_C:
		a |= (u64)ari->poc << DECT_ARI_C_POC_SHIFT;
		a |= (u64)ari->fpn << DECT_ARI_C_FPN_SHIFT;
		a |= (u64)ari->fps << DECT_ARI_C_FPS_SHIFT;
		break;
	case DECT_ARC_D:
		a |= (u64)ari->gop << DECT_ARI_D_GOP_SHIFT;
		a |= (u64)ari->fpn << DECT_ARI_D_FPN_SHIFT;
		break;
	case DECT_ARC_E:
		a |= (u64)ari->fil << DECT_ARI_E_FIL_SHIFT;
		a |= (u64)ari->fpn << DECT_ARI_E_FPN_SHIFT;
		break;
	}
	return a;
}

u64 dect_build_rfpi(const struct dect_idi *idi)
{
	u64 t = 0;

	t |= idi->e ? DECT_RFPI_E_FLAG : 0;
	t |= dect_build_ari(&idi->pari) >> DECT_RFPI_ARI_SHIFT;
	t |= idi->rpn << DECT_RFPI_RPN_SHIFT;
	return t;
}

bool dect_rfpi_cmp(const struct dect_idi *i1, const struct dect_idi *i2)
{
	return dect_ari_cmp(&i1->pari, &i2->pari) ||
	       i1->rpn != i2->rpn ||
	       i1->e   != i2->e;
}

u16 dect_build_fmid(const struct dect_idi *idi)
{
	u64 rfpi;

	rfpi = dect_build_rfpi(idi);
	rfpi >>= (sizeof(rfpi) - DECT_NT_ID_RFPI_LEN) * BITS_PER_BYTE;
	return rfpi & DECT_FMID_MASK;
}

/*
 * PMID (Portable MAC Identity)
 */

void dect_parse_pmid(struct dect_pmid *pmid, u32 p)
{
	if ((p & DECT_PMID_DEFAULT_ID_MASK) == DECT_PMID_DEFAULT_ID) {
		pmid->type = DECT_PMID_DEFAULT;
		pmid->num  = p & DECT_PMID_DEFAULT_NUM_MASK;
	} else if ((p & DECT_PMID_EMERGENCY_ID_MASK) == DECT_PMID_EMERGENCY_ID) {
		pmid->type = DECT_PMID_EMERGENCY;
		pmid->tpui = p & DECT_PMID_EMERGENCY_TPUI_MASK;
	} else {
		pmid->type = DECT_PMID_ASSIGNED;
		pmid->tpui = p & DECT_PMID_ASSIGNED_TPUI_MASK;
	}
}
EXPORT_SYMBOL_GPL(dect_parse_pmid);

u32 dect_build_pmid(const struct dect_pmid *pmid)
{
	u32 p = 0;

	switch (pmid->type) {
	case DECT_PMID_DEFAULT:
		p |= DECT_PMID_DEFAULT_ID;
		p |= pmid->tpui;
		break;
	case DECT_PMID_EMERGENCY:
		p |= DECT_PMID_EMERGENCY_ID;
		p |= pmid->tpui;
		break;
	case DECT_PMID_ASSIGNED:
		p |= pmid->tpui;
		break;
	}
	return p;
}
EXPORT_SYMBOL_GPL(dect_build_pmid);

bool dect_pmid_cmp(const struct dect_pmid *p1, const struct dect_pmid *p2)
{
	return memcmp(p1, p2, sizeof(*p1));
}

/**
 * dect_parse_mci - Extract the MCI elements from a packed MCI in a
 * 		    struct sockaddr_dect_lu
 *
 * The packed MCI is build from ARI + PMID + LCN
 */
int dect_parse_mci(struct dect_mci *mci, u64 m)
{
	u32 p;
	u8 len;

	len = dect_parse_ari(&mci->ari, m);

	len += DECT_PMID_SIZE;
	p = (m >> (sizeof(m) * BITS_PER_BYTE - len)) & DECT_PMID_MASK;
	dect_parse_pmid(&mci->pmid, p);

	len += DECT_ECN_SIZE;
	mci->lcn = (m >> (sizeof(m) * BITS_PER_BYTE - len)) & DECT_LCN_MASK;
	return 0;
}

u64 dect_build_mci(const struct dect_mci *mci)
{
	return 0;
}
