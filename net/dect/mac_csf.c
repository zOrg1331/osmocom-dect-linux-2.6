/*
 * DECT MAC Cell Site Functions
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_DECT_DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <net/dect/dect.h>
#include <net/dect/mac_csf.h>
#include <net/dect/ccp.h>
#include <asm/unaligned.h>

/* avoid <KERN_DEBUG> for continuation lines */
#undef KERN_DEBUG
#define KERN_DEBUG

static const u8 dect_fp_preamble[]	= { 0x55, 0x55, 0xe9, 0x8a};
static const u8 dect_pp_preamble[]	= { 0xaa, 0xaa, 0x16, 0x75};

/*
 * MAC layer timers
 */

#define timer_debug(cell, base, fmt, args...) \
	pr_debug("%s %u.%.2u.%.2u: " fmt, \
		 (base) == DECT_TIMER_TX ? "TX" : "RX", \
		 cell->timer_base[(base)].mfn, cell->timer_base[(base)].framenum, \
		 cell->timer_base[(base)].slot, ## args)

#define rx_debug(cell, fmt, args...)	timer_debug(cell, DECT_TIMER_RX, fmt, ## args)
#define tx_debug(cell, fmt, args...)	timer_debug(cell, DECT_TIMER_TX, fmt, ## args)

static u8 dect_slotnum(const struct dect_cell *cell, enum dect_timer_bases b)
{
	return cell->timer_base[b].slot;
}

static u8 dect_framenum(const struct dect_cell *cell, enum dect_timer_bases b)
{
	return cell->timer_base[b].framenum;
}

static u32 dect_mfn(const struct dect_cell *cell, enum dect_timer_bases b)
{
	return cell->timer_base[b].mfn;
}

/* Return whether the TX time is in the next frame relative to the RX time */
static bool dect_tx_time_wrapped(const struct dect_cell *cell)
{
	return dect_slotnum(cell, DECT_TIMER_TX) <
	       dect_slotnum(cell, DECT_TIMER_RX);
}

/**
 * dect_timer_synchronize_framenum
 *
 * Synchronize the current frame number based on Q-channel reception.
 *
 * Q-channel information is transmitted only in frame 8 and serves as an
 * indirect indication. The TX frame number update needs to take the clock
 * difference into account.
 */
static void dect_timer_synchronize_framenum(struct dect_cell *cell, u8 framenum)
{
	cell->timer_base[DECT_TIMER_RX].framenum = framenum;
	if (dect_tx_time_wrapped(cell))
		framenum++;
	cell->timer_base[DECT_TIMER_TX].framenum = framenum;
}

static void dect_timer_synchronize_mfn(struct dect_cell *cell, u32 mfn)
{
	cell->timer_base[DECT_TIMER_RX].mfn = mfn;
	cell->timer_base[DECT_TIMER_TX].mfn = mfn;
}

static void dect_run_timers(struct dect_cell *cell, enum dect_timer_bases b)
{
	struct dect_timer_base *base = &cell->timer_base[b];
	struct dect_timer *t;

	while (!list_empty(&base->timers)) {
		t = list_first_entry(&base->timers, struct dect_timer, list);

		if (dect_mfn_after(t->mfn, base->mfn) ||
		    (t->mfn == base->mfn && t->frame > base->framenum) ||
		    (t->mfn == base->mfn && t->frame == base->framenum &&
		     t->slot > base->slot))
			break;

		timer_debug(cell, b, "timer %p: %u.%u.%u\n",
			    t, t->mfn, t->frame, t->slot);
		list_del_init(&t->list);
		t->func(cell, t->data);
	}
}

static void dect_timer_base_update(struct dect_cell *cell,
				   enum dect_timer_bases b, u8 slot)
{
	struct dect_timer_base *base = &cell->timer_base[b];

	base->slot = slot;
	if (base->slot == 0) {
		base->framenum = dect_next_framenum(base->framenum);
		if (base->framenum == 0)
			base->mfn = dect_next_mfn(base->mfn);
	}
}

/**
 * dect_timer_add - (re)schedule a timer
 *
 * Frame numbers are relative to the current time, slot positions are absolute.
 * A timer scheduled for (1, 2) will expire in slot 2 in the next frame.
 *
 * A frame number of zero will expire at the next occurence of the slot, which
 * can be within the same frame in case the slot is not already in the past, or
 * in the next frame in case it is.
 */
static void dect_timer_add(struct dect_cell *cell, struct dect_timer *timer,
			   enum dect_timer_bases base, u32 frame, u8 slot)
{
	struct dect_timer_base *b = &cell->timer_base[base];
	struct dect_timer *t;
	u32 mfn;

	if (frame == 0 && slot < b->slot)
		frame++;
	frame += b->framenum;
	mfn = dect_mfn_add(b->mfn, frame / DECT_FRAMES_PER_MULTIFRAME);
	frame %= DECT_FRAMES_PER_MULTIFRAME;

	timer_debug(cell, base, "timer %p: schedule for %u.%u.%u\n",
		    timer, mfn, frame, slot);
	if (!list_empty(&timer->list))
		list_del(&timer->list);
	list_for_each_entry(t, &b->timers, list) {
		if (dect_mfn_after(t->mfn, mfn) ||
		    (t->mfn == mfn && t->frame > frame) ||
		    (t->mfn == mfn && t->frame == frame && t->slot > slot))
			break;
	}

	timer->mfn   = mfn;
	timer->frame = frame;
	timer->slot  = slot;
	list_add_tail(&timer->list, &t->list);
}

static void dect_timer_del(struct dect_timer *timer)
{
	list_del_init(&timer->list);
}

static void dect_timer_init(struct dect_timer *t)
{
	INIT_LIST_HEAD(&t->list);
}

static void dect_timer_setup(struct dect_timer *t,
			     void (*func)(struct dect_cell *, void *),
			     void *data)
{
	dect_timer_init(t);
	t->func = func;
	t->data = data;
}

/*
 * Basic Channel lists
 *
 * A channel list contains channel descriptions of all physical channels
 * able to carry the packet type, sorted into multiple bins based on the
 * maximum RSSI value of the TDD slot pair.
 *
 * At any time, only a single incomplete channel list exists that is updated
 * based on the RSSI measurements gathered by the individual IRC instances.
 * Once a list is complete, it is added to the list of active channel lists,
 * replacing the previous one for the same packet type, if any.
 */

#if 1
#define chl_debug(cell, chl, fmt, args...) \
	rx_debug(cell, "channel-list %s (%u): " fmt, \
		 (chl)->pkt == DECT_PACKET_P00 ? "P00" : \
		 (chl)->pkt == DECT_PACKET_P08 ? "P08" : \
		 (chl)->pkt == DECT_PACKET_P32 ? "P32" : "?", \
		 (chl)->available, ## args)
#else
#define chl_debug(cell, chl, fmt, args...)
#endif

static int dect_chl_schedule_update(struct dect_cell *cell,
				    enum dect_packet_types pkt);

static struct dect_channel_list *dect_chl_lookup(const struct dect_cell *cell,
						 enum dect_packet_types pkt)
{
	struct dect_channel_list *chl;

	list_for_each_entry(chl, &cell->chanlists, list) {
		if (chl->pkt == pkt)
			return chl;
	}
	return NULL;
}

static void dect_chl_timer(struct dect_cell *cell, void *data)
{
	struct dect_channel_list *chl = data;

	if (dect_chl_schedule_update(cell, chl->pkt) < 0)
		dect_timer_add(cell, &chl->timer, DECT_TIMER_RX, 1, 0);
}

static void dect_chl_release(struct dect_channel_list *chl)
{
	dect_timer_del(&chl->timer);
	kfree(chl);
}

static struct dect_channel_list *dect_chl_init(struct dect_cell *cell,
					       enum dect_packet_types pkt)
{
	struct dect_channel_list *chl;
	unsigned int entries, i;

	entries = DECT_CARRIER_NUM * DECT_HALF_FRAME_SIZE;
	chl = kzalloc(sizeof(*chl) + entries * sizeof(chl->entries[0]), GFP_ATOMIC);
	if (chl == NULL)
		return NULL;
	chl->pkt = pkt;
	dect_timer_setup(&chl->timer, dect_chl_timer, chl);
	for (i = 0; i < ARRAY_SIZE(chl->bins); i++)
		INIT_LIST_HEAD(&chl->bins[i]);
	for (i = 0; i < entries; i++)
		INIT_LIST_HEAD(&chl->entries[i].list);
	return chl;
}

static int dect_chl_schedule_update(struct dect_cell *cell,
				    enum dect_packet_types pkt)
{
	struct dect_channel_list *chl;

	list_for_each_entry(chl, &cell->chl_pending, list) {
		if (chl->pkt == pkt)
			return 0;
	}

	chl = dect_chl_init(cell, pkt);
	if (chl == NULL)
		return -ENOMEM;
	chl_debug(cell, chl, "schedule update\n");
	list_add_tail(&chl->list, &cell->chl_pending);
	return 0;
}

static struct dect_channel_list *dect_chl_get_pending(struct dect_cell *cell)
{
	struct dect_channel_list *chl;

	if (list_empty(&cell->chl_pending))
		return NULL;
	chl = list_first_entry(&cell->chl_pending,
			       struct dect_channel_list,
			       list);
	list_del(&chl->list);
	return chl;
}

static void dect_chl_update(struct dect_cell *cell,
			    struct dect_channel_list *chl,
			    const struct dect_channel_desc *chd, u8 rssi)
{
	struct dect_channel_list_entry *e;
	u8 slot, bin;

	if (rssi > dect_dbm_to_rssi(DECT_CHANNEL_LIST_MAX_DBM))
		return;

	slot = chd->slot < 12 ? chd->slot : chd->slot - 12;
	chl_debug(cell, chl, "update carrier %u slot %u pos %u RSSI %u\n",
		  chd->carrier, chd->slot, slot, rssi);

	e = &chl->entries[chd->carrier * DECT_HALF_FRAME_SIZE + slot];
	if (!list_empty(&e->list))
		return;

	if (chd->slot < DECT_HALF_FRAME_SIZE) {
		e->slot    = slot;
		e->carrier = chd->carrier;
		e->rssi    = rssi;
	} else if (e->rssi != 0) {
		e->rssi = max(e->rssi, rssi);
		bin = rssi * ARRAY_SIZE(chl->bins) / (DECT_RSSI_RANGE + 1);

		list_add_tail(&e->list, &chl->bins[bin]);
		chl->available++;
	}
}

static void dect_chl_update_carrier(struct dect_cell *cell, u8 carrier)
{
	struct dect_channel_list *chl, *old;

	chl = cell->chl;
	chl_debug(cell, chl, "update status %llx rfcars %x carrier %u\n",
		  (unsigned long long)chl->status, cell->si.ssi.rfcars, carrier);

	chl->status |= 1ULL << carrier;
	if (chl->status != cell->si.ssi.rfcars)
		return;
	cell->chl = NULL;

	chl_debug(cell, chl, "complete %u entries\n", chl->available);
	old = dect_chl_lookup(cell, chl->pkt);
	if (old != NULL) {
		list_del(&old->list);
		dect_chl_release(old);
	}

	dect_timer_add(cell, &chl->timer, DECT_TIMER_RX,
		       DECT_CHANNEL_LIST_MAX_AGE * 2 / 3 *
		       DECT_FRAMES_PER_SECOND, 0);
	list_add_tail(&chl->list, &cell->chanlists);
}

/**
 * dect_channel_delay - calculate delay in frames until a channel is accessible
 *
 * Calculate the delay in frames until one of the remote sides' scans is on the
 * specified carrier.
 *
 * A FP maintains one to three scans, which lag behind each other by three
 * carriers, a PP maintains zero or one (fast-setup) scan. The PP fast-
 * setup scan leads the FP primary scan by one carrier.
 *
 * Setup needs at least one full frame, therefore a scan reaching a carrier
 * earlier than that must be treated as reachable one cycle later.
 */
static u8 dect_channel_delay(const struct dect_cell *cell,
			     const struct dect_channel_desc *chd)
{
	u64 rfcars = cell->si.ssi.rfcars;
	u8 i, txs, scn, frames;
	s8 d;

	if (cell->mode == DECT_MODE_FP) {
		/* PP fast-setup scan */
		scn = dect_next_carrier(rfcars, cell->si.ssi.pscn);
		txs = 1;
	} else {
		/* FP primary scan */
		scn = dect_prev_carrier(rfcars, cell->si.ssi.pscn);
		txs = min(cell->si.ssi.txs + 1, 3);
	}

	frames = ~0;
	for (i = 0; i < txs; i++) {
		d = dect_carrier_distance(rfcars, scn, chd->carrier);
#if 0
		if (dect_slotnum(cell, DECT_TIMER_TX) >= chd->slot)
			d--;
#endif
		/* More than two frames in the future? */
		if (d <= DECT_CHANNEL_MIN_DELAY)
			d += hweight64(rfcars);

		frames = min_t(u8, frames, d);
		pr_debug("rfcars %llx distance %u->%u slot %u: %u frames %u\n",
			 (unsigned long long)rfcars, scn, chd->carrier,
			 chd->slot, d, frames);

		scn = dect_carrier_sub(rfcars, scn, 3);
	}

	return frames;
}

/**
 * dect_select_transceiver - select a transceiver for placing a bearer
 *
 * Select the lowest order transceiver that is able to operate on a physical
 * channel.
 */
static struct dect_transceiver *
dect_select_transceiver(const struct dect_cell *cell,
			const struct dect_channel_desc *chd)
{
	struct dect_transceiver *trx;

	dect_foreach_transceiver_reverse(trx, &cell->trg) {
		if (trx->state != DECT_TRANSCEIVER_LOCKED)
			continue;
		if (!dect_transceiver_channel_available(trx, chd))
			continue;
		return trx;
	}
	return NULL;
}

/**
 * dect_select_channel - select a physical channel for bearer setup
 *
 * @cell:	DECT cell
 * @trx:	selected transceiver
 * @chd:	channel description
 * @rssi:	last measure RSSI value of selected channel
 * @quick:	prefer quickly accessible channel
 *
 * This performs the common steps of channel selection based on channel lists.
 * In "quick" mode, the selected channel is the first channel accessible within
 * three TDMA frames from the lowest three available bands. When not in quick
 * mode or when no channel is accessible within three frames, the first
 * available channel from the lowest available band is selected.
 *
 * "quick" mode is used for setting up pilot bearers and for bearer handover.
 *
 * The returned channel description is within the normal transmit half
 * of the cell's mode.
 */
static int dect_select_channel(struct dect_cell *cell,
			       struct dect_transceiver **trxp,
			       struct dect_channel_desc *chd, u8 *rssi,
			       bool quick)
{
	struct dect_channel_list_entry *e, *sel;
	struct dect_channel_list *chl;
	struct dect_transceiver *trx, *uninitialized_var(tsel);
	u8 bin, first, last;

	chl = dect_chl_lookup(cell, chd->pkt);
	if (chl == NULL)
		return -ENOENT;

	/* Find first non-empty bin */
	for (first = 0; first < ARRAY_SIZE(chl->bins); first++) {
		if (!list_empty(&chl->bins[first]))
			break;
	}
	if (first == ARRAY_SIZE(chl->bins))
		return -ENOSPC;

	sel = NULL;
retry:
	last = max_t(u8, first + quick ? 3 : 1, ARRAY_SIZE(chl->bins));
	for (bin = first; sel == NULL && bin < last; bin++) {
		list_for_each_entry(e, &chl->bins[bin], list) {
			if (cell->trg.blind_full_slots & (1 << e->slot))
				continue;
			if (cell->mode == DECT_MODE_PP &&
			    !(cell->blind_full_slots & (1 << (11 - e->slot))))
				continue;

			chd->carrier = e->carrier;
			chd->slot = dect_normal_transmit_base(cell) + e->slot;
			if (quick && dect_channel_delay(cell, chd) > 3)
				continue;

			trx = dect_select_transceiver(cell, chd);
			if (trx == NULL)
				continue;
			if (sel != NULL) {
				if (trx->index < tsel->index)
					continue;
				if (sel->rssi < e->rssi)
					continue;
			}

			sel  = e;
			tsel = trx;

			/* Stop searching if this is the best possible choice */
			if (tsel->index == hweight16(cell->trg.trxmask))
				break;
		}
	}

	if (sel == NULL) {
		/* Check the first band again without considering delay when
		 * no quickly accessible channel is available within the first
		 * three bands. */
		if (quick) {
			quick = false;
			goto retry;
		}
		return -ENOSPC;
	}

	list_del_init(&sel->list);
	chl->available--;
	if (chl->available < DECT_CHANNEL_LIST_LOW_WATERMARK)
		dect_chl_schedule_update(cell, chl->pkt);

	chd->carrier = sel->carrier;
	chd->slot = dect_normal_transmit_base(cell) + sel->slot;
	chl_debug(cell, chl, "select channel: carrier %u slot %u RSSI %u\n",
		  chd->carrier,	chd->slot, sel->rssi);

	*rssi = sel->rssi;
	*trxp = tsel;
	return 0;
}

/*
 * Tail message parsing/construction
 */

static enum dect_tail_identifications dect_parse_tail(const struct sk_buff *skb)
{
	return skb->data[DECT_HDR_TA_OFF] & DECT_HDR_TA_MASK;
}

static int dect_parse_identities_information(struct dect_tail_msg *tm, u64 t)
{
	struct dect_idi *idi = &tm->idi;
	u8 ari_len, rpn_len;

	ari_len = dect_parse_ari(&idi->pari, t << DECT_RFPI_ARI_SHIFT);
	if (ari_len == 0)
		return -1;
	rpn_len = BITS_PER_BYTE * DECT_NT_ID_RFPI_LEN - 1 - ari_len;

	idi->e   = (t & DECT_RFPI_E_FLAG);
	idi->rpn = (t >> DECT_RFPI_RPN_SHIFT) & ((1 << rpn_len) - 1);
	tm->type = DECT_TM_TYPE_ID;

	pr_debug("identities information: e: %u class: %u emc: %.4x "
		 "fpn: %.5x rpn: %x\n", idi->e, idi->pari.arc,
		 idi->pari.emc, idi->pari.fpn, idi->rpn);
	return 0;
}

static u64 dect_build_identities_information(const struct dect_idi *idi)
{
	return dect_build_rfpi(idi);
}

static int dect_parse_static_system_information(struct dect_tail_msg *tm, u64 t)
{
	struct dect_ssi *ssi = &tm->ssi;

	ssi->nr	    = (t & DECT_QT_SSI_NR_FLAG);
	ssi->sn     = (t & DECT_QT_SSI_SN_MASK) >> DECT_QT_SSI_SN_SHIFT;
	ssi->sp     = (t & DECT_QT_SSI_SP_MASK) >> DECT_QT_SSI_SP_SHIFT;
	ssi->txs    = (t & DECT_QT_SSI_TXS_MASK) >> DECT_QT_SSI_TXS_SHIFT;
	ssi->mc     = (t & DECT_QT_SSI_MC_FLAG);
	ssi->rfcars = (t & DECT_QT_SSI_RFCARS_MASK) >> DECT_QT_SSI_RFCARS_SHIFT;
	ssi->cn     = (t & DECT_QT_SSI_CN_MASK) >> DECT_QT_SSI_CN_SHIFT;
	ssi->pscn   = (t & DECT_QT_SSI_PSCN_MASK) >> DECT_QT_SSI_PSCN_SHIFT;

	if (ssi->sn > 11 || ssi->cn > 9 || ssi->pscn > 9)
		return -1;
	tm->type = DECT_TM_TYPE_SSI;

	pr_debug("static system information: nr: %u sn: %u cn: %u pscn: %u\n",
		 ssi->nr, ssi->sn, ssi->cn, ssi->pscn);
	return 0;
}

static u64 dect_build_static_system_information(const struct dect_ssi *ssi)
{
	u64 t = 0;

	t |= ssi->nr ? DECT_QT_SSI_NR_FLAG : 0;
	t |= (u64)ssi->sn << DECT_QT_SSI_SN_SHIFT;
	t |= (u64)ssi->sp << DECT_QT_SSI_SP_SHIFT;
	t |= (u64)ssi->txs << DECT_QT_SSI_TXS_SHIFT;
	t |= (u64)ssi->cn << DECT_QT_SSI_CN_SHIFT;
	t |= ssi->mc ? DECT_QT_SSI_MC_FLAG : 0;
	t |= (u64)ssi->rfcars << DECT_QT_SSI_RFCARS_SHIFT;
	t |= (u64)ssi->pscn << DECT_QT_SSI_PSCN_SHIFT;
	t |= DECT_QT_SI_SSI;
	return t;
}

static int dect_parse_extended_rf_carrier_information(struct dect_tail_msg *tm, u64 t)
{
	struct dect_erfc *erfc = &tm->erfc;

	erfc->rfcars	 = (t & DECT_QT_ERFC_RFCARS_MASK) >>
			   DECT_QT_ERFC_RFCARS_SHIFT;
	erfc->band	 = (t & DECT_QT_ERFC_RFBAND_MASK) >>
			   DECT_QT_ERFC_RFBAND_SHIFT;
	erfc->num_rfcars = (t & DECT_QT_ERFC_NUM_RFCARS_MASK) >
			   DECT_QT_ERFC_NUM_RFCARS_SHIFT;
	tm->type = DECT_TM_TYPE_ERFC;

	pr_debug("extended rf carrier information: rfcars %.6x band %u num %u\n",
		 erfc->rfcars, erfc->band, erfc->num_rfcars);
	return 0;
}

static u64 dect_build_extended_rf_carrier_information(const struct dect_erfc *erfc)
{
	u64 t = 0;

	t |= (u64)erfc->rfcars << DECT_QT_ERFC_RFCARS_SHIFT;
	t |= (u64)erfc->band << DECT_QT_ERFC_RFBAND_SHIFT;
	t |= (u64)erfc->num_rfcars << DECT_QT_ERFC_NUM_RFCARS_SHIFT;
	t |= DECT_QT_SI_ERFC;
	return t;
}

static int dect_parse_fixed_part_capabilities(struct dect_tail_msg *tm, u64 t)
{
	struct dect_fpc *fpc = &tm->fpc;

	fpc->fpc = (t & DECT_QT_FPC_CAPABILITY_MASK) >>
		   DECT_QT_FPC_CAPABILITY_SHIFT;
	fpc->hlc = (t & DECT_QT_FPC_HLC_MASK) >> DECT_QT_FPC_HLC_SHIFT;
	tm->type = DECT_TM_TYPE_FPC;

	pr_debug("fixed part capabilities: fpc: %.5x hlc: %.4x\n",
		 fpc->fpc, fpc->hlc);
	return 0;
}

static u64 dect_build_fixed_part_capabilities(const struct dect_fpc *fpc)
{
	u64 t = 0;

	t |= (u64)fpc->fpc << DECT_QT_FPC_CAPABILITY_SHIFT;
	t |= (u64)fpc->hlc << DECT_QT_FPC_HLC_SHIFT;
	t |= DECT_QT_SI_FPC;
	return t;
}

static int dect_parse_extended_fixed_part_capabilities(struct dect_tail_msg *tm, u64 t)
{
	struct dect_efpc *efpc = &tm->efpc;

	efpc->fpc = (t & DECT_QT_EFPC_EFPC_MASK) >> DECT_QT_EFPC_EFPC_SHIFT;
	efpc->hlc = (t & DECT_QT_EFPC_EHLC_MASK) >> DECT_QT_EFPC_EHLC_SHIFT;
	tm->type  = DECT_TM_TYPE_EFPC;

	pr_debug("extended fixed part capabilities: fpc: %.5x hlc: %.6x\n",
		 efpc->fpc, efpc->hlc);
	return 0;
}

static u64 dect_build_extended_fixed_part_capabilities(const struct dect_efpc *efpc)
{
	u64 t = 0;

	t |= (u64)efpc->fpc << DECT_QT_EFPC_EFPC_SHIFT;
	t |= (u64)efpc->hlc << DECT_QT_EFPC_EHLC_SHIFT;
	t |= DECT_QT_SI_EFPC;
	return t;
}

static int dect_parse_extended_fixed_part_capabilities2(struct dect_tail_msg *tm, u64 t)
{
	struct dect_efpc2 *efpc2 = &tm->efpc2;

	efpc2->fpc = (t & DECT_QT_EFPC2_FPC_MASK) >> DECT_QT_EFPC2_FPC_SHIFT;
	efpc2->hlc = (t & DECT_QT_EFPC2_HLC_MASK) >> DECT_QT_EFPC2_HLC_SHIFT;
	tm->type   = DECT_TM_TYPE_EFPC2;

	pr_debug("extended fixed part capabilities2: fpc: %x hlc: %x\n",
		 efpc2->fpc, efpc2->hlc);
	return 0;
}

static u64 dect_build_extended_fixed_part_capabilities2(const struct dect_efpc2 *efpc2)
{
	u64 t = 0;

	t |= (u64)efpc2->fpc << DECT_QT_EFPC2_FPC_SHIFT;
	t |= (u64)efpc2->hlc << DECT_QT_EFPC2_HLC_SHIFT;
	t |= DECT_QT_SI_EFPC2;
	return t;
}

static int dect_parse_sari(struct dect_tail_msg *tm, u64 t)
{
	struct dect_sari *sari = &tm->sari;

	sari->list_cycle = (((t & DECT_QT_SARI_LIST_CYCLE_MASK) >>
			     DECT_QT_SARI_LIST_CYCLE_SHIFT) + 1) * 2;
	sari->tari  = (t & DECT_QT_SARI_TARI_FLAG);
	sari->black = (t & DECT_QT_SARI_BLACK_FLAG);
	dect_parse_ari(&sari->ari, t << DECT_QT_SARI_ARI_SHIFT);
	tm->type = DECT_TM_TYPE_SARI;

	pr_debug("sari: cycle %u tari: %u black: %u\n",
		 sari->list_cycle, sari->tari, sari->black);
	return 0;
}

static u64 dect_build_sari(const struct dect_sari *sari)
{
	u64 t = 0;

	t |= sari->tari ? DECT_QT_SARI_TARI_FLAG : 0;
	t |= sari->black ? DECT_QT_SARI_BLACK_FLAG : 0;
	t |= dect_build_ari(&sari->ari) >> DECT_QT_SARI_ARI_SHIFT;
	t |= DECT_QT_SI_SARI;
	return t;
}

static int dect_parse_multiframe_number(struct dect_tail_msg *tm, u64 t)
{
	tm->mfn.num = (t & DECT_QT_MFN_MASK) >> DECT_QT_MFN_SHIFT;
	tm->type = DECT_TM_TYPE_MFN;

	pr_debug("multi-frame number: %u\n", tm->mfn.num);
	return 0;
}

static u64 dect_build_multiframe_number(const struct dect_mfn *mfn)
{
	u64 t = 0;

	t |= (u64)mfn->num << DECT_QT_MFN_SHIFT;
	t |= DECT_QT_SI_MFN;
	return t;
}

static int dect_parse_system_information(struct dect_tail_msg *tm, u64 t)
{
	/* clear of memcmp */
	memset(((void *)tm) + offsetof(struct dect_tail_msg, ssi), 0, 
	       sizeof(*tm) - offsetof(struct dect_tail_msg, ssi));

	switch (t & DECT_QT_H_MASK) {
	case DECT_QT_SI_SSI:
	case DECT_QT_SI_SSI2:
		return dect_parse_static_system_information(tm, t);
	case DECT_QT_SI_ERFC:
		return dect_parse_extended_rf_carrier_information(tm, t);
	case DECT_QT_SI_FPC:
		return dect_parse_fixed_part_capabilities(tm, t);
	case DECT_QT_SI_EFPC:
		return dect_parse_extended_fixed_part_capabilities(tm, t);
	case DECT_QT_SI_EFPC2:
		return dect_parse_extended_fixed_part_capabilities2(tm, t);
	case DECT_QT_SI_SARI:
		return dect_parse_sari(tm, t);
	case DECT_QT_SI_MFN:
		return dect_parse_multiframe_number(tm, t);
	default:
		pr_debug("unknown system information type %llx\n",
			 (unsigned long long)t & DECT_QT_H_MASK);
		return -1;
	}
}

static int dect_parse_blind_full_slots(struct dect_tail_msg *tm, u64 t)
{
	struct dect_bfs *bfs = &tm->bfs;

	bfs->mask = (t & DECT_PT_BFS_MASK) >> DECT_PT_BFS_SHIFT;
	tm->type = DECT_TM_TYPE_BFS;

	pr_debug("page: RFPI: %.3x blind full slots: %.3x\n",
		 tm->page.rfpi, bfs->mask);
	return 0;
}

static u64 dect_build_blind_full_slots(const struct dect_bfs *bfs)
{
	u64 t = 0;

	t |= (u64)bfs->mask << DECT_PT_BFS_SHIFT;
	t |= DECT_PT_IT_BLIND_FULL_SLOT;
	return t;
}

static int dect_parse_bearer_description(struct dect_tail_msg *tm, u64 t)
{
	struct dect_bearer_desc *bd = &tm->bd;

	bd->bt = (t & DECT_PT_INFO_TYPE_MASK);
	bd->sn = (t & DECT_PT_BEARER_SN_MASK) >> DECT_PT_BEARER_SN_SHIFT;
	bd->sp = (t & DECT_PT_BEARER_SP_MASK) >> DECT_PT_BEARER_SP_SHIFT;
	bd->cn = (t & DECT_PT_BEARER_CN_MASK) >> DECT_PT_BEARER_CN_SHIFT;
	if (bd->sn >= DECT_HALF_FRAME_SIZE)
		return -1;
	tm->type = DECT_TM_TYPE_BD;

	pr_debug("page: RFPI: %.3x bearer description: bt: %llx sn: %u sp: %u cn: %u\n",
		 tm->page.rfpi, (unsigned long long)bd->bt, bd->sn, bd->sp, bd->cn);
	return 0;
}

static u64 dect_build_bearer_description(const struct dect_bearer_desc *bd)
{
	u64 t = 0;

	t |= (u64)bd->sn << DECT_PT_BEARER_SN_SHIFT;
	t |= (u64)bd->sp << DECT_PT_BEARER_SP_SHIFT;
	t |= (u64)bd->cn << DECT_PT_BEARER_CN_SHIFT;
	t |= bd->bt;
	return t;
}

static int dect_parse_rfp_identity(struct dect_tail_msg *tm, u64 t)
{
	struct dect_rfp_id *id = &tm->rfp_id;

	id->id = (t & DECT_PT_RFP_ID_MASK) >> DECT_PT_RFP_ID_SHIFT;
	tm->type = DECT_TM_TYPE_RFP_ID;

	pr_debug("page: RFPI: %.3x RFP identity: %.3x\n",
		 tm->page.rfpi, id->id);
	return 0;
}

static u64 dect_build_rfp_identity(const struct dect_rfp_id *id)
{
	u64 t = 0;

	t |= (u64)id->id << DECT_PT_RFP_ID_SHIFT;
	t |= DECT_PT_IT_RFP_IDENTITY;
	return t;
}

static int dect_parse_rfp_status(struct dect_tail_msg *tm, u64 t)
{
	struct dect_rfp_status *st = &tm->rfp_status;

	st->rfp_busy = t & DECT_PT_RFPS_RFP_BUSY_FLAG;
	st->sys_busy = t & DECT_PT_RFPS_SYS_BUSY_FLAG;
	tm->type = DECT_TM_TYPE_RFP_STATUS;

	pr_debug("page: RFPI: %.3x RFP status: rfp_busy: %d sys_busy: %d\n",
		 tm->page.rfpi, st->rfp_busy, st->sys_busy);
	return 0;
}

static u64 dect_build_rfp_status(const struct dect_rfp_status *st)
{
	u64 t = 0;

	t |= st->rfp_busy ? DECT_PT_RFPS_RFP_BUSY_FLAG : 0;
	t |= st->sys_busy ? DECT_PT_RFPS_SYS_BUSY_FLAG : 0;
	t |= DECT_PT_IT_RFP_STATUS;
	return t;
}

static int dect_parse_active_carriers(struct dect_tail_msg *tm, u64 t)
{
	struct dect_active_carriers *ac = &tm->active_carriers;

	ac->active = (t & DECT_PT_ACTIVE_CARRIERS_MASK) >>
		     DECT_PT_ACTIVE_CARRIERS_SHIFT;
	tm->type = DECT_TM_TYPE_ACTIVE_CARRIERS;

	pr_debug("page: RFPI: %.3x active carriers: %.3x\n",
		 tm->page.rfpi, ac->active);
	return 0;
}

static u64 dect_build_active_carriers(const struct dect_active_carriers *ac)
{
	u64 t = 0;

	t |= (u64)ac->active << DECT_PT_ACTIVE_CARRIERS_SHIFT;
	t |= DECT_PT_IT_ACTIVE_CARRIERS;
	return t;
}

static int dect_parse_paging_info(struct dect_tail_msg *tm, u64 t)
{
	switch (t & DECT_PT_INFO_TYPE_MASK) {
	case DECT_PT_IT_BLIND_FULL_SLOT:
		return dect_parse_blind_full_slots(tm, t);
	case DECT_PT_IT_OTHER_BEARER:
	case DECT_PT_IT_RECOMMENDED_OTHER_BEARER:
	case DECT_PT_IT_GOOD_RFP_BEARER:
	case DECT_PT_IT_DUMMY_OR_CL_BEARER_POSITION:
	case DECT_PT_IT_CL_BEARER_POSITION:
		return dect_parse_bearer_description(tm, t);
	case DECT_PT_IT_RFP_IDENTITY:
		return dect_parse_rfp_identity(tm, t);
	case DECT_PT_IT_DUMMY_OR_CL_BEARER_MARKER:
		pr_debug("dummy or cl bearer marker\n");
		return 0;
	case DECT_PT_IT_RFP_STATUS:
		return dect_parse_rfp_status(tm, t);
	case DECT_PT_IT_ACTIVE_CARRIERS:
		return dect_parse_active_carriers(tm, t);
	default:
		return -1;
	}
}

static int dect_parse_paging_msg(struct dect_tail_msg *tm, u64 t)
{
	tm->page.extend = t & DECT_PT_HDR_EXTEND_FLAG;
	tm->page.length = t & DECT_PT_HDR_LENGTH_MASK;

	switch (tm->page.length) {
	case DECT_PT_ZERO_PAGE:
		tm->page.rfpi = (t & DECT_PT_ZP_RFPI_MASK) >>
				DECT_PT_ZP_RFPI_SHIFT;

		return dect_parse_paging_info(tm, t);
	case DECT_PT_SHORT_PAGE:
		tm->page.rfpi = 0;
		return dect_parse_paging_info(tm, t);
	case DECT_PT_FULL_PAGE:
	case DECT_PT_LONG_PAGE:
	case DECT_PT_LONG_PAGE_FIRST:
	case DECT_PT_LONG_PAGE_LAST:
	case DECT_PT_LONG_PAGE_ALL:
		tm->type = DECT_TM_TYPE_PAGE;
		return 0;
	default:
		return -1;
	}
}

static int dect_parse_cctrl_common(struct dect_cctrl *cctl, u64 t)
{
	cctl->fmid = (t & DECT_CCTRL_FMID_MASK) >> DECT_CCTRL_FMID_SHIFT;
	cctl->pmid = (t & DECT_CCTRL_PMID_MASK) >> DECT_CCTRL_PMID_SHIFT;

	pr_debug("cctrl: cmd: %llx fmid: %.3x pmid: %.5x\n",
		 (unsigned long long)cctl->cmd, cctl->fmid, cctl->pmid);
	return 0;
}

static u64 dect_build_cctrl_common(const struct dect_cctrl *cctl)
{
	u64 t = 0;

	t |= cctl->cmd;
	t |= (u64)cctl->fmid << DECT_CCTRL_FMID_SHIFT;
	t |= (u64)cctl->pmid << DECT_CCTRL_PMID_SHIFT;
	return t;
}

static int dect_parse_cctrl_attr(struct dect_cctrl *cctl, u64 t)
{
	cctl->ecn     = (t & DECT_CCTRL_ATTR_ECN_MASK) >> DECT_CCTRL_ATTR_ECN_SHIFT;
	cctl->lbn     = (t & DECT_CCTRL_ATTR_LBN_MASK) >> DECT_CCTRL_ATTR_LBN_SHIFT;
	cctl->type    = (t & DECT_CCTRL_ATTR_TYPE_MASK) >> DECT_CCTRL_ATTR_TYPE_SHIFT;
	cctl->service = (t & DECT_CCTRL_ATTR_SERVICE_MASK) >> DECT_CCTRL_ATTR_SERVICE_SHIFT;
	cctl->slot    = (t & DECT_CCTRL_ATTR_SLOT_MASK) >> DECT_CCTRL_ATTR_SLOT_SHIFT;

	pr_debug("cctrl: cmd: %llx ecn: %x lbn: %x type: %x "
		 "service: %x slot: %x\n", (unsigned long long)cctl->cmd,
		 cctl->ecn, cctl->lbn, cctl->type, cctl->service, cctl->slot);
	return 0;
}

static u64 dect_build_cctrl_attr(const struct dect_cctrl *cctl)
{
	u64 t = 0;

	t |= cctl->cmd;
	t |= (u64)cctl->ecn << DECT_CCTRL_ATTR_ECN_SHIFT;
	t |= (u64)cctl->lbn << DECT_CCTRL_ATTR_LBN_SHIFT;
	t |= (u64)cctl->type << DECT_CCTRL_ATTR_TYPE_SHIFT;
	t |= (u64)cctl->service << DECT_CCTRL_ATTR_SERVICE_SHIFT;
	t |= (u64)cctl->slot << DECT_CCTRL_ATTR_SLOT_SHIFT;
	return t;
}

static int dect_parse_cctrl_release(struct dect_cctrl *cctl, u64 t)
{
	cctl->lbn    = (t & DECT_CCTRL_RELEASE_LBN_MASK) >>
		       DECT_CCTRL_RELEASE_LBN_SHIFT;
	cctl->reason = (t & DECT_CCTRL_RELEASE_REASON_MASK) >>
		       DECT_CCTRL_RELEASE_REASON_SHIFT;
	cctl->pmid   = (t & DECT_CCTRL_RELEASE_PMID_MASK) >>
		       DECT_CCTRL_RELEASE_PMID_SHIFT;

	pr_debug("cctrl: release: pmid: %.5x lbn: %x reason: %x\n",
		 cctl->pmid, cctl->lbn, cctl->reason);
	return 0;
}

static u64 dect_build_cctrl_release(const struct dect_cctrl *cctl)
{
	u64 t = 0;

	t |= cctl->cmd;
	t |= (u64)cctl->lbn << DECT_CCTRL_RELEASE_LBN_SHIFT;
	t |= (u64)cctl->reason << DECT_CCTRL_RELEASE_REASON_SHIFT;
	t |= (u64)cctl->pmid << DECT_CCTRL_RELEASE_PMID_SHIFT;
	return t;
}

static int dect_parse_basic_cctrl(struct dect_tail_msg *tm, u64 t)
{
	struct dect_cctrl *cctl = &tm->cctl;

	cctl->cmd = t & DECT_MT_CMD_MASK;
	switch (cctl->cmd) {
	case DECT_CCTRL_ACCESS_REQ:
	case DECT_CCTRL_BEARER_HANDOVER_REQ:
	case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
	case DECT_CCTRL_UNCONFIRMED_ACCESS_REQ:
	case DECT_CCTRL_BEARER_CONFIRM:
	case DECT_CCTRL_WAIT:
		return dect_parse_cctrl_common(cctl, t);
	case DECT_CCTRL_ATTRIBUTES_T_REQUEST:
	case DECT_CCTRL_ATTRIBUTES_T_CONFIRM:
		return dect_parse_cctrl_attr(cctl, t);
	case DECT_CCTRL_RELEASE:
		return dect_parse_cctrl_release(cctl, t);
	default:
		return -1;
	}
}

static int dect_parse_advanced_cctrl(struct dect_tail_msg *tm, u64 t)
{
	struct dect_cctrl *cctl = &tm->cctl;

	cctl->cmd = t & DECT_MT_CMD_MASK;
	switch (cctl->cmd) {
	case DECT_CCTRL_ACCESS_REQ:
	case DECT_CCTRL_BEARER_HANDOVER_REQ:
	case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
	case DECT_CCTRL_UNCONFIRMED_ACCESS_REQ:
	case DECT_CCTRL_BEARER_CONFIRM:
	case DECT_CCTRL_WAIT:
	case DECT_CCTRL_UNCONFIRMED_DUMMY:
	case DECT_CCTRL_UNCONFIRMED_HANDOVER:
		return dect_parse_cctrl_common(cctl, t);
	case DECT_CCTRL_ATTRIBUTES_T_REQUEST:
	case DECT_CCTRL_ATTRIBUTES_T_CONFIRM:
		return dect_parse_cctrl_attr(cctl, t);
	case DECT_CCTRL_BANDWIDTH_T_REQUEST:
	case DECT_CCTRL_BANDWIDTH_T_CONFIRM:
		return -1;
	case DECT_CCTRL_RELEASE:
		return dect_parse_cctrl_release(cctl, t);
	default:
		return -1;
	}
}

static int dect_parse_encryption_ctrl(struct dect_tail_msg *tm, u64 t)
{
	struct dect_encctrl *ectl = &tm->encctl;

	ectl->cmd  = (t & DECT_ENCCTRL_CMD_MASK) >> DECT_ENCCTRL_CMD_SHIFT;
	ectl->fmid = (t & DECT_ENCCTRL_FMID_MASK) >> DECT_ENCCTRL_FMID_SHIFT;
	ectl->pmid = (t & DECT_ENCCTRL_PMID_MASK) >> DECT_ENCCTRL_PMID_SHIFT;
	pr_debug("encctrl: cmd: %x fmid: %.4x pmid: %.5x\n",
		 ectl->cmd, ectl->fmid, ectl->pmid);
	return 0;
}

static u64 dect_build_encryption_ctrl(const struct dect_encctrl *ectl)
{
	u64 t = 0;

	t |= (u64)DECT_ENCCTRL_FILL_MASK;
	t |= (u64)ectl->cmd << DECT_ENCCTRL_CMD_SHIFT;
	t |= (u64)ectl->fmid << DECT_ENCCTRL_FMID_SHIFT;
	t |= (u64)ectl->pmid << DECT_ENCCTRL_PMID_SHIFT;
	return t;
}

static int dect_parse_mac_ctrl(struct dect_tail_msg *tm, u64 t)
{
	switch (t & DECT_MT_HDR_MASK) {
	case DECT_MT_BASIC_CCTRL:
		if (dect_parse_basic_cctrl(tm, t) < 0)
			return -1;
		tm->type = DECT_TM_TYPE_BCCTRL;
		return 0;
	case DECT_MT_ADV_CCTRL:
		if (dect_parse_advanced_cctrl(tm, t) < 0)
			return -1;
		tm->type = DECT_TM_TYPE_ACCTRL;
		return 0;
	case DECT_MT_ENC_CTRL:
		if (dect_parse_encryption_ctrl(tm, t) < 0)
			return -1;
		tm->type = DECT_TM_TYPE_ENCCTRL;
		return 0;
	default:
		return -1;
	}
}

static u64 dect_build_cctrl(const struct dect_cctrl *cctl)
{
	switch (cctl->cmd) {
	case DECT_CCTRL_ACCESS_REQ:
	case DECT_CCTRL_BEARER_HANDOVER_REQ:
	case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
	case DECT_CCTRL_UNCONFIRMED_ACCESS_REQ:
	case DECT_CCTRL_BEARER_CONFIRM:
	case DECT_CCTRL_WAIT:
	case DECT_CCTRL_UNCONFIRMED_DUMMY:
	case DECT_CCTRL_UNCONFIRMED_HANDOVER:
		return dect_build_cctrl_common(cctl);
	case DECT_CCTRL_ATTRIBUTES_T_REQUEST:
	case DECT_CCTRL_ATTRIBUTES_T_CONFIRM:
		return dect_build_cctrl_attr(cctl);
	case DECT_CCTRL_BANDWIDTH_T_REQUEST:
	case DECT_CCTRL_BANDWIDTH_T_CONFIRM:
	case DECT_CCTRL_CHANNEL_LIST:
		return 0;
	case DECT_CCTRL_RELEASE:
		return dect_build_cctrl_release(cctl);
	default:
		return 0;
	}
}

static int dect_parse_ct_data(struct dect_tail_msg *tm, u64 t, u8 seq)
{
	struct dect_ct_data *ctd = &tm->ctd;

	ctd->seq = seq;
	tm->type = DECT_TM_TYPE_CT;
	pr_debug("C_S tail sequence number %u\n", seq);
	return 0;
}

static int dect_parse_tail_msg(struct dect_tail_msg *tm,
			       const struct sk_buff *skb)
{
	u64 t;

	pr_debug("%s: Q1: %d Q2: %d csum %x ", DECT_TRX_CB(skb)->trx->name,
		 skb->data[DECT_HDR_Q1_OFF] & DECT_HDR_Q1_FLAG,
		 skb->data[DECT_HDR_Q2_OFF] & DECT_HDR_Q2_FLAG,
		 *(u16 *)&skb->data[DECT_RA_FIELD_OFF]);

	tm->type = DECT_TM_TYPE_INVALID;
	t = get_unaligned_be64((__be64 *)&skb->data[DECT_T_FIELD_OFF]);

	switch (dect_parse_tail(skb)) {
	case DECT_TI_CT_PKT_0:
		return dect_parse_ct_data(tm, t, 0);
	case DECT_TI_CT_PKT_1:
		return dect_parse_ct_data(tm, t, 1);
	case DECT_TI_NT_CL:
		pr_debug("connectionless: ");
	case DECT_TI_NT:
		return dect_parse_identities_information(tm, t);
	case DECT_TI_QT:
		return dect_parse_system_information(tm, t);
	case DECT_TI_PT:
		/* Paging tail in direction FP->PP, MAC control otherwise */
		if (DECT_TRX_CB(skb)->slot < 12)
			return dect_parse_paging_msg(tm, t);
	case DECT_TI_MT:
		return dect_parse_mac_ctrl(tm, t);
	default:
		return -1;
	}
}

static struct sk_buff *dect_build_tail_msg(struct sk_buff *skb,
					   enum dect_tail_msg_types type,
					   const void *data)
{
	enum dect_tail_identifications ti;
	unsigned int i;
	u64 t;

	switch (type) {
	case DECT_TM_TYPE_ID:
		t = dect_build_identities_information(data);
		ti = DECT_TI_NT;
		break;
	case DECT_TM_TYPE_SSI:
		t = dect_build_static_system_information(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_ERFC:
		t = dect_build_extended_rf_carrier_information(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_FPC:
		t = dect_build_fixed_part_capabilities(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_EFPC:
		t = dect_build_extended_fixed_part_capabilities(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_EFPC2:
		t = dect_build_extended_fixed_part_capabilities2(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_SARI:
		t = dect_build_sari(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_MFN:
		t = dect_build_multiframe_number(data);
		ti = DECT_TI_QT;
		break;
	case DECT_TM_TYPE_BCCTRL:
		t = dect_build_cctrl(data) | DECT_MT_BASIC_CCTRL;
		ti = DECT_TI_MT;
		break;
	case DECT_TM_TYPE_ACCTRL:
		t = dect_build_cctrl(data) | DECT_MT_ADV_CCTRL;
		ti = DECT_TI_MT;
		break;
	case DECT_TM_TYPE_ENCCTRL:
		t = dect_build_encryption_ctrl(data);
		ti = DECT_TI_MT;
		break;
	default:
		BUG();
	}

	skb_put(skb, DECT_T_FIELD_SIZE);
	for (i = 0; i < DECT_T_FIELD_SIZE; i++)
		skb->data[i] = t >> ((sizeof(t) - i - 1) * BITS_PER_BYTE);

	DECT_A_CB(skb)->id = ti;
	return skb;
}

/**
 * dect_t_skb_alloc - allocate a socket buffer for the T-Field
 *
 */
static struct sk_buff *dect_t_skb_alloc(void)
{
	struct sk_buff *skb;

	skb = alloc_skb(DECT_PREAMBLE_SIZE + DECT_A_FIELD_SIZE, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for preamble */
	skb_reset_mac_header(skb);
	skb_reserve(skb, DECT_PREAMBLE_SIZE);

	skb_reset_network_header(skb);

	/* Reserve space for Header Field */
	skb_reserve(skb, DECT_HDR_FIELD_SIZE);
	return skb;
}

/*
 * MAC Bearers
 */

static void dect_bearer_enable(struct dect_bearer *bearer)
{
	switch (bearer->mode) {
	case DECT_BEARER_RX:
		dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_RX);
		break;
	case DECT_BEARER_TX:
		dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_TX);
		break;
	};
	dect_set_carrier(bearer->trx, bearer->chd.slot, bearer->chd.carrier);
	bearer->state = DECT_BEARER_ENABLED;
}

static void dect_bearer_disable(struct dect_bearer *bearer)
{
	dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_IDLE);
}

static void dect_bearer_timer_add(struct dect_cell *cell,
				  struct dect_bearer *bearer,
				  struct dect_timer *timer,
				  unsigned int frames)
{
	u8 slot = bearer->chd.slot;

	switch (bearer->mode) {
	case DECT_BEARER_RX:
		dect_timer_add(cell, timer, DECT_TIMER_RX, frames, slot);
		break;
	case DECT_BEARER_TX:
		dect_timer_add(cell, timer, DECT_TIMER_TX, frames, slot);
		break;
	}
}

/**
 * dect_bearer_release - release a MAC bearer
 *
 * Release a MAC bearer that is no longer used. The unused slot position is
 * given to IRC and converted to a scan bearer.
 */
static void dect_scan_bearer_enable(struct dect_transceiver *trx,
				    const struct dect_channel_desc *chd);

static void dect_bearer_release(struct dect_cell *cell,
				struct dect_bearer *bearer)
{
	struct dect_transceiver *trx = bearer->trx;

	dect_timer_del(&bearer->tx_timer);
	dect_bearer_disable(bearer);
	dect_disable_cipher(trx, bearer->chd.slot);
	dect_scan_bearer_enable(trx, &bearer->chd);

	kfree(bearer);
}

static struct dect_bearer *dect_bearer_init(struct dect_cell *cell,
					    const struct dect_bearer_ops *ops,
					    enum dect_bearer_types type,
					    struct dect_transceiver *trx,
					    const struct dect_channel_desc *chd,
					    enum dect_bearer_modes mode,
					    void *data)
{
	struct dect_bearer *bearer;

	pr_debug("init bearer on slot %u carrier %u\n", chd->slot, chd->carrier);
	bearer = kzalloc(sizeof(*bearer), GFP_ATOMIC);
	if (bearer == NULL)
		goto err1;

	bearer->type  = type;
	bearer->ops   = ops;
	bearer->trx   = trx;
	bearer->chd   = *chd;
	bearer->mode  = mode;
	bearer->state = DECT_BEARER_INACTIVE;
	dect_timer_setup(&bearer->tx_timer, NULL, NULL);
	skb_queue_head_init(&bearer->m_tx_queue);
	bearer->data  = data;

	trx->slots[chd->slot].bearer = bearer;
	dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_IDLE);
	return bearer;

err1:
	return NULL;
}

/*
 * TX bearer activation:
 *
 * The first transmission of an outgoing traffic or connectionless bearer is
 * scheduled for the frame in which the remote sides' scan is on the desired
 * carrier.
 *
 * The noise value of the physical channel must be confirmed not to be more
 * than 12dBm stronger than the RSSI measurement obtained from the channel
 * list when selecting the channel within two frames before the first
 * transmission.
 *
 * Dummy bearers are activated immediately after confirming the RSSI.
 */

static void dect_tx_bearer_report_rssi(struct dect_cell *cell,
				       struct dect_bearer *bearer,
				       u8 rssi)
{
	rx_debug(cell, "RSSI confirm: last: %u new: %u\n", bearer->rssi, rssi);
	if (rssi > bearer->rssi + dect_dbm_to_rssi_rel(12))
		pr_debug("RSSI: too much noise\n");
	bearer->state = DECT_BEARER_RSSI_CONFIRMED;
}

static void dect_tx_bearer_enable_timer(struct dect_cell *cell, void *data)
{
	struct dect_bearer *bearer = data;

	switch ((int)bearer->state) {
	case DECT_BEARER_SCHEDULED:
		tx_debug(cell, "confirm RSSI carrier %u\n", bearer->chd.carrier);
		dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_RX);
		dect_set_carrier(bearer->trx, bearer->chd.slot, bearer->chd.carrier);
		dect_bearer_timer_add(cell, bearer, &bearer->tx_timer, 2);
		bearer->state = DECT_BEARER_RSSI_CONFIRM;
		break;
	case DECT_BEARER_RSSI_CONFIRMED:
		tx_debug(cell, "enable bearer\n");
		if (bearer->ops->enable != NULL)
			bearer->ops->enable(cell, bearer);
		else
			dect_bearer_enable(bearer);
		break;
	}
}

static void dect_tx_bearer_schedule(struct dect_cell *cell,
				    struct dect_bearer *bearer, u8 rssi)
{
	u8 delay = 0;

	dect_timer_setup(&bearer->tx_timer, dect_tx_bearer_enable_timer, bearer);
	if (bearer->ops->state != DECT_DUMMY_BEARER)
		delay = dect_channel_delay(cell, &bearer->chd) - 2;

	bearer->state = DECT_BEARER_SCHEDULED;
	bearer->rssi  = rssi;

	if (delay == 0)
		dect_tx_bearer_enable_timer(cell, bearer);
	else {
		dect_bearer_timer_add(cell, bearer, &bearer->tx_timer, delay);
		tx_debug(cell, "scheduled bearer: delay %u carrier %u pscn %u\n",
			 delay, bearer->chd.carrier, cell->si.ssi.pscn);
	}
}

/*
 * Broadcast Message Control - decentralized components
 */

/* Paging:
 *
 * The following rules apply to page message transmission:
 *
 * - Fast pages may be transmitted in any frame and have priority over normal
 *   pages.
 *
 * - Normal short and full pages, as well as the first segment of a normal long
 *   page, may only be transmitted in frame 0, or a frame up to 12 if the page
 *   transmitted in the previously allowed frame had the extend bit bit set.
 *
 * - Normal pages must be repeated three times in the frames following their
 *   first transmission for page detection in low duty idle mode.
 *
 * - Fast pages may be repeated up to three times following their first
 *   transmission. New page message have priority over repetitions.
 *
 * FIXME: fast pages should not interrupt repetitions
 */

static void dect_page_timer_schedule(struct dect_cell *cell)
{
	u8 framenum = dect_framenum(cell, DECT_TIMER_TX);
	u8 frames;

	if ((framenum & 0x1) == 1)
		frames = 1;
	 else
		frames = 2;
	framenum = dect_framenum_add(framenum, frames);

	if (framenum == 8 || framenum == 14)
		frames += 2;

	tx_debug(cell, "page timer: schedule in %u frames\n", frames);
	dect_timer_add(cell, &cell->page_timer, DECT_TIMER_TX, frames, 0);
}

/**
 * dect_queue_page - Add a paging message to the appropriate queue
 *
 * The first transmission of a page is added to the end of the normal or
 * fast queue. The first three repetitions of normal pages have priority
 * over first transmissions.
 */
static void dect_queue_page(struct dect_cell *cell, struct sk_buff *skb)
{
	u8 repetitions = DECT_BMC_CB(skb)->repetitions;
	bool fast = DECT_BMC_CB(skb)->fast;
	struct sk_buff_head *page_queue;

	page_queue = fast ? &cell->page_fast_queue : &cell->page_queue;
	if (!fast && repetitions > 0)
		skb_queue_head(page_queue, skb);
	else
		skb_queue_tail(page_queue, skb);

	dect_page_timer_schedule(cell);
}

/**
 * dect_queue_page_segments - perform segmentation and queue the page segments
 *
 * Segment a page message into B_S channel sized segments and add them
 * to the TX queue.
 */
static void dect_queue_page_segments(struct sk_buff_head *list,
				     struct sk_buff *skb)
{
	struct sk_buff *seg;
	u64 t;

	while (skb->len > DECT_PT_LFP_BS_DATA_SIZE) {
		seg = skb_clone(skb, GFP_ATOMIC);
		if (seg == NULL)
			goto err;
		skb_trim(seg, DECT_PT_LFP_BS_DATA_SIZE);
		if (skb_queue_empty(list))
			t = DECT_PT_LONG_PAGE_FIRST;
		else
			t = DECT_PT_LONG_PAGE;
		seg->data[0] |= t >> DECT_PT_HDR_LENGTH_SHIFT;

		__skb_queue_tail(list, seg);

		skb_pull(skb, DECT_PT_LFP_BS_DATA_SIZE);
	}

	/* Short and full pages have the extend bit set in order to reduce
	 * the delay for new pages arriving while a page is already active.
	 */
	if (skb->len == DECT_PT_SP_BS_DATA_SIZE)
		t = DECT_PT_SHORT_PAGE | DECT_PT_HDR_EXTEND_FLAG;
	else if (skb_queue_empty(list))
		t = DECT_PT_FULL_PAGE | DECT_PT_HDR_EXTEND_FLAG;
	else
		t = 0 ? DECT_PT_LONG_PAGE_ALL : DECT_PT_LONG_PAGE_LAST;

	skb->data[0] |= t >> 56;
	pr_debug("queue page segment len %u hdr %x\n", skb->len, skb->data[0] & 0xf0);
	__skb_queue_tail(list, skb);
	return;

err:
	__skb_queue_purge(list);
	kfree_skb(skb);
}

/**
 * dect_page_timer - page message transmission timer
 *
 * This timer performs maintenance of the page transmit queue. While the queue
 * is active, it is advanced by one segment per frame. When a page message has
 * been fully transmitted, the next message is selected for transmission,
 * segmented into appropriate units and queued to the transmit queue.
 */
static void dect_page_tx_timer(struct dect_cell *cell, void *data)
{
	u32 timeout, mfn = dect_mfn(cell, DECT_TIMER_TX);
	u8 framenum = dect_framenum(cell, DECT_TIMER_TX);
	struct sk_buff *skb, *last;

	tx_debug(cell, "page timer\n");

	/* Advance the transmit queue by one segment per allowed tail. */
	if (!skb_queue_empty(&cell->page_tx_queue)) {
		tx_debug(cell, "advance queue\n");
		kfree_skb(__skb_dequeue(&cell->page_tx_queue));
		if (!skb_queue_empty(&cell->page_tx_queue)) {
			dect_page_timer_schedule(cell);
			return;
		}
	}

	/* Add the last page back to the queue unless its lifetime expired. */
	last = cell->page_sdu;
	if (last != NULL) {
		cell->page_sdu = NULL;

		DECT_BMC_CB(last)->repetitions++;
		timeout = dect_mfn_add(DECT_BMC_CB(last)->stamp, DECT_PAGE_LIFETIME);
		if (dect_mfn_before(mfn, timeout))
			dect_queue_page(cell, last);
		else
			kfree_skb(last);
	}

	/* Get the next page message */
	while (1) {
		skb = skb_dequeue(&cell->page_fast_queue);
		tx_debug(cell, "fast page: %p\n", skb);
		if (skb == NULL && !skb_queue_empty(&cell->page_queue)) {
			if (framenum == 0 || (last != NULL && framenum <= 12))
				skb = skb_dequeue(&cell->page_queue);
			tx_debug(cell, "normal page: %p\n", skb);
		}
		if (skb == NULL)
			goto out;

		timeout = dect_mfn_add(DECT_BMC_CB(skb)->stamp, DECT_PAGE_LIFETIME);
		if (dect_mfn_before(mfn, timeout))
			break;
		else
			kfree_skb(skb);
	}

	/* Save a copy of short and full pages for repetitions. */
	if (skb->len <= DECT_PT_LFP_BS_DATA_SIZE &&
	    DECT_BMC_CB(skb)->repetitions < 3)
		cell->page_sdu = skb_clone(skb, GFP_ATOMIC);

	/* Segment page message and queue segments to tx queue */
	dect_queue_page_segments(&cell->page_tx_queue, skb);
out:
	if (skb != NULL || !skb_queue_empty(&cell->page_queue))
		dect_page_timer_schedule(cell);
}

static void dect_cell_bmc_init(struct dect_cell *cell)
{
	skb_queue_head_init(&cell->page_queue);
	skb_queue_head_init(&cell->page_fast_queue);
	skb_queue_head_init(&cell->page_tx_queue);
	dect_timer_setup(&cell->page_timer, dect_page_tx_timer, NULL);
}

static void dect_cell_bmc_disable(struct dect_cell *cell)
{
	dect_timer_del(&cell->page_timer);
	__skb_queue_purge(&cell->page_tx_queue);
	__skb_queue_purge(&cell->page_fast_queue);
	__skb_queue_purge(&cell->page_queue);
}

/*
 * Broadcast Control
 */

static u32 dect_build_page_rfpi(const struct dect_cell *cell)
{
	return (dect_build_rfpi(&cell->idi) >> 24) & ((1 << 20) - 1);
}

static void dect_bc_release(struct dect_bc *bc)
{
	kfree_skb(bc->p_rx_skb);
	list_del(&bc->list);
}

static void dect_bc_init(struct dect_cell *cell, struct dect_bc *bc)
{
	INIT_LIST_HEAD(&bc->list);
	bc->p_rx_skb = NULL;
	list_add_tail(&bc->list, &cell->bcs);
}

static const enum dect_mac_system_information_types dect_bc_q_cycle[] = {
	DECT_QT_SI_SSI,
	DECT_QT_SI_ERFC,
	DECT_QT_SI_SARI,
	DECT_QT_SI_FPC,
	DECT_QT_SI_EFPC,
	DECT_QT_SI_EFPC2,
	DECT_QT_SI_MFN,
};

static struct sk_buff *dect_bc_q_dequeue(struct dect_cell *cell,
					 struct dect_bearer *bearer)
{
	const struct dect_si *si = &cell->si;
	struct dect_ssi ssi;
	struct dect_mfn mfn;
	struct sk_buff *skb;
	unsigned int index;

	skb = dect_t_skb_alloc();
	if (skb == NULL)
		return NULL;

	while (1) {
		index = cell->si_idx++;
		if (cell->si_idx == ARRAY_SIZE(dect_bc_q_cycle))
			cell->si_idx = 0;

		switch (dect_bc_q_cycle[index]) {
		case DECT_QT_SI_SSI:
			memcpy(&ssi, &si->ssi, sizeof(ssi));
			ssi.sn = bearer->chd.slot;
			ssi.cn = bearer->chd.carrier;
			ssi.sp = 0;
			ssi.pscn = dect_next_carrier(ssi.rfcars, ssi.pscn);

			return dect_build_tail_msg(skb, DECT_TM_TYPE_SSI, &ssi);
		case DECT_QT_SI_ERFC:
			if (!si->ssi.mc)
				break;
			return dect_build_tail_msg(skb, DECT_TM_TYPE_ERFC,
						   &si->erfc);
		case DECT_QT_SI_SARI:
			break;
		case DECT_QT_SI_FPC:
			return dect_build_tail_msg(skb, DECT_TM_TYPE_FPC,
						   &si->fpc);
		case DECT_QT_SI_EFPC:
			if (!(si->fpc.fpc & DECT_FPC_EXTENDED_FP_INFO))
				break;
			return dect_build_tail_msg(skb, DECT_TM_TYPE_EFPC,
						   &si->efpc);
		case DECT_QT_SI_EFPC2:
			if (!(si->efpc.fpc & DECT_EFPC_EXTENDED_FP_INFO2))
				break;
			return dect_build_tail_msg(skb, DECT_TM_TYPE_EFPC2,
						   &si->efpc2);
		case DECT_QT_SI_MFN:
			mfn.num = dect_mfn(cell, DECT_TIMER_TX);
			return dect_build_tail_msg(skb, DECT_TM_TYPE_MFN, &mfn);
		default:
			BUG();
		}
	}
}

static void dect_page_add_mac_info(struct dect_cell *cell, struct sk_buff *skb)
{
	struct dect_tail_msg tm;
	void *data = NULL;
	u64 t;
	u8 *it;

	memset(&tm, 0, sizeof(tm));
	tm.type = DECT_TM_TYPE_ACTIVE_CARRIERS;

	switch (tm.type) {
	case DECT_TM_TYPE_BFS:
		tm.bfs.mask = cell->trg.blind_full_slots;
		t = dect_build_blind_full_slots(data);
		break;
	case DECT_TM_TYPE_BD:
		t = dect_build_bearer_description(data);
		break;
	case DECT_TM_TYPE_RFP_ID:
		t = dect_build_rfp_identity(data);
		break;
	case DECT_TM_TYPE_RFP_STATUS:
		t = dect_build_rfp_status(data);
		break;
	case DECT_TM_TYPE_ACTIVE_CARRIERS:
	default:
		t = dect_build_active_carriers(&tm.active_carriers);
		break;
	}

	it = skb_put(skb, DECT_PT_INFO_TYPE_SIZE);
	it[0] = t >> 32;
	it[1] = t >> 24;
}

static struct sk_buff *dect_bc_p_dequeue(struct dect_cell *cell,
					 struct dect_bearer *bearer)
{
	unsigned int headroom, tailroom = 0;
	struct sk_buff *skb;

	/* Send higher layer page messages if present */
	skb = skb_peek(&cell->page_tx_queue);
	if (skb == NULL)
		return NULL;

	/* The frame needs headroom for the preamble and hdr-field. Short and
	 * zero pages need additional tailroom for the MAC Layer Information. */
	headroom = DECT_PREAMBLE_SIZE + DECT_HDR_FIELD_SIZE;
	if (skb->len == DECT_PT_SP_BS_DATA_SIZE)
		tailroom = DECT_PT_INFO_TYPE_SIZE;

	skb = skb_copy_expand(skb, headroom, tailroom, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;
	/* Reserve space for preamble */
	skb_set_mac_header(skb, -headroom);

	DECT_A_CB(skb)->id = DECT_TI_PT;
	if (tailroom > 0)
		dect_page_add_mac_info(cell, skb);
	return skb;
}

static struct sk_buff *dect_bc_dequeue(struct dect_cell *cell,
				       struct dect_bearer *bearer,
				       struct dect_bc *bc,
				       enum dect_mac_channels chan)
{
	struct sk_buff *skb;

	switch (chan) {
	case DECT_MC_P:
		return dect_bc_p_dequeue(cell, bearer);
	case DECT_MC_Q:
		return dect_bc_q_dequeue(cell, bearer);
	case DECT_MC_N:
		skb = dect_t_skb_alloc();
		if (skb == NULL)
			return NULL;
		return dect_build_tail_msg(skb, DECT_TM_TYPE_ID, &cell->idi);
	default:
		BUG();
	}
}

/**
 * dect_bc_queue_bs_data - queue a page message to the broadcast controller for
 * 			   reassembly and delivery to broadcast message control.
 *
 * @cell:	DECT cell
 * @bc:		broadcast controller
 * @skb_in:	DECT frame
 * @page:	page message
 */
static void dect_bc_queue_bs_data(struct dect_cell *cell, struct dect_bc *bc,
				  struct sk_buff *skb_in, const struct dect_page *page)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct sk_buff *skb, *head;

	if (page->length == DECT_PT_ZERO_PAGE)
		return;

	skb = skb_clone(skb_in, GFP_ATOMIC);
	if (skb == NULL)
		return;
	skb_pull(skb, DECT_T_FIELD_OFF);

	head = bc->p_rx_skb;
	switch (page->length) {
	case DECT_PT_SHORT_PAGE:
		skb_trim(skb, DECT_PT_SP_BS_DATA_SIZE);
		break;
	case DECT_PT_FULL_PAGE:
	case DECT_PT_LONG_PAGE_ALL:
		skb_trim(skb, DECT_PT_LFP_BS_DATA_SIZE);
		break;
	case DECT_PT_LONG_PAGE_FIRST:
		if (head != NULL)
			goto err;
		skb_trim(skb, DECT_PT_LFP_BS_DATA_SIZE);
		bc->p_rx_skb = skb;
		return;
	case DECT_PT_LONG_PAGE:
		if (head == NULL)
			return;
		skb_trim(skb, DECT_PT_LFP_BS_DATA_SIZE);
		skb_append_frag(head, skb);
		if (head->len >= 30)
			goto err;
		return;
	case DECT_PT_LONG_PAGE_LAST:
		if (head == NULL)
			return;
		skb_trim(skb, DECT_PT_LFP_BS_DATA_SIZE);
		skb = skb_append_frag(head, skb);
		bc->p_rx_skb = NULL;
		break;
	default:
		BUG();
	}

	return clh->ops->bmc_page_indicate(clh, skb);

err:
	kfree_skb(bc->p_rx_skb);
	bc->p_rx_skb = NULL;
}

static bool dect_bc_update_si(struct dect_si *si,
			      const struct dect_tail_msg *tm)
{
	bool notify = false;
	unsigned int i;

	switch (tm->type) {
	case DECT_TM_TYPE_SSI:
		if (memcmp(&si->ssi, &tm->ssi, sizeof(si->ssi)))
			memcpy(&si->ssi, &tm->ssi, sizeof(si->ssi));
		break;
	case DECT_TM_TYPE_ERFC:
		if (memcmp(&si->erfc, &tm->erfc, sizeof(si->erfc)))
			memcpy(&si->erfc, &tm->erfc, sizeof(si->erfc));
		break;
	case DECT_TM_TYPE_FPC:
		if (memcmp(&si->fpc, &tm->fpc, sizeof(si->fpc))) {
			memcpy(&si->fpc, &tm->fpc, sizeof(si->fpc));
			notify = true;
		}
		break;
	case DECT_TM_TYPE_EFPC:
		if (memcmp(&si->efpc, &tm->efpc, sizeof(si->efpc))) {
			memcpy(&si->efpc, &tm->efpc, sizeof(si->efpc));
			notify = true;
		}
		break;
	case DECT_TM_TYPE_EFPC2:
		if (memcmp(&si->efpc2, &tm->efpc2, sizeof(si->efpc2))) {
			memcpy(&si->efpc2, &tm->efpc2, sizeof(si->efpc2));
			notify = true;
		}
		break;
	case DECT_TM_TYPE_SARI:
		if (si->num_saris == ARRAY_SIZE(si->sari))
			break;

		for (i = 0; i < si->num_saris; i++) {
			if (!dect_ari_cmp(&tm->sari.ari, &si->sari[i].ari))
				break;
		}
		if (i < si->num_saris)
			break;

		memcpy(&si->sari[si->num_saris++], &tm->sari,
		       sizeof(si->sari[i]));
		notify = true;
		break;
	case DECT_TM_TYPE_MFN:
		memcpy(&si->mfn, &tm->mfn, sizeof(si->mfn));
		break;
	default:
		return false;
	}

	si->mask |= 1 << tm->type;
	return notify;
}

static bool dect_bc_si_cycle_complete(struct dect_idi *idi,
				      const struct dect_si *si)
{
	if (!(si->mask & (1 << DECT_TM_TYPE_SSI))) {
		pr_debug("incomplete: SSI\n");
		return false;
	}
	if (si->ssi.mc &&
	    !(si->mask & (1 << DECT_TM_TYPE_ERFC))) {
		pr_debug("incomplete: ERFC\n");
		return false;
	}

	if (!(si->mask & (1 << DECT_TM_TYPE_FPC))) {
		pr_debug("incomplete: FPC\n");
		return false;
	}
	if (si->fpc.fpc & DECT_FPC_EXTENDED_FP_INFO &&
	    !(si->mask & (1 << DECT_TM_TYPE_EFPC))) {
		pr_debug("incomplete: EFPC\n");
		return false;
	}

	if (si->mask & (1 << DECT_TM_TYPE_EFPC) &&
	    si->efpc.fpc & DECT_EFPC_EXTENDED_FP_INFO2 &&
	    !(si->mask & (1 << DECT_TM_TYPE_EFPC2))) {
		pr_debug("incomplete: EFPC2\n");
		return false;
	}

	if (idi->e &&
	    (!(si->mask & (1 << DECT_TM_TYPE_SARI)) ||
	     si->num_saris != si->sari[0].list_cycle)) {
		pr_debug("incomplete: SARI\n");
		return false;
	}

	pr_debug("complete\n");
	return true;
}

static void dect_bc_rcv(struct dect_cell *cell, struct dect_bc *bc,
			struct sk_buff *skb, const struct dect_tail_msg *tm)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	enum dect_tail_identifications ti;
	bool notify;

	if (cell->mode != DECT_MODE_PP)
		return;

	ti = dect_parse_tail(skb);
	if (ti == DECT_TI_QT) {
		/* Q-channel information is broadcast in frame 8 */
		dect_timer_synchronize_framenum(cell, DECT_Q_CHANNEL_FRAME);
		if (tm->type == DECT_TM_TYPE_MFN)
			dect_timer_synchronize_mfn(cell, tm->mfn.num);

		notify = dect_bc_update_si(&cell->si, tm);
		if (dect_bc_si_cycle_complete(&cell->idi, &cell->si) && notify)
			clh->ops->mac_info_indicate(clh, &cell->idi, &cell->si);
	} else if (ti == DECT_TI_PT) {
		if (tm->page.length == DECT_PT_ZERO_PAGE &&
		    tm->page.rfpi != dect_build_page_rfpi(cell))
			pr_debug("RFPI mismatch %.3x %.3x\n",
				 tm->page.rfpi, dect_build_page_rfpi(cell));
	}

	switch (tm->type) {
	case DECT_TM_TYPE_BFS:
		cell->blind_full_slots = tm->bfs.mask;
	case DECT_TM_TYPE_BD:
	case DECT_TM_TYPE_RFP_ID:
	case DECT_TM_TYPE_RFP_STATUS:
	case DECT_TM_TYPE_ACTIVE_CARRIERS:
	case DECT_TM_TYPE_PAGE:
		dect_bc_queue_bs_data(cell, bc, skb, &tm->page);
		break;
	default:
		break;
	}
}

/*
 * Traffic Bearer Control (TBC)
 */

#define tbc_debug(tbc, fmt, args...) \
	pr_debug("TBC (MCEI %u): PMID: %s %x FMID: %.3x ECN: %u: " fmt, \
		 (tbc)->id.mcei, \
		 (tbc)->id.pmid.type == DECT_PMID_DEFAULT ? "default" : \
		 (tbc)->id.pmid.type == DECT_PMID_ASSIGNED ? "assigned" : \
		 (tbc)->id.pmid.type == DECT_PMID_EMERGENCY ? "emergency" : "?", \
		 (tbc)->id.pmid.tpui, (tbc)->cell->fmid, (tbc)->id.ecn, ## args);

static struct sk_buff *dect_tbc_build_bcctrl(const struct dect_tbc *tbc,
					     enum dect_cctrl_cmds cmd)
{
	struct dect_cctrl cctl;
	struct sk_buff *skb;

	skb = dect_t_skb_alloc();
	if (skb == NULL)
		return NULL;

	cctl.fmid = tbc->cell->fmid;
	cctl.pmid = dect_build_pmid(&tbc->id.pmid);
	cctl.cmd = cmd;

	if (tbc->id.type == DECT_MAC_CONN_BASIC)
		return dect_build_tail_msg(skb, DECT_TM_TYPE_BCCTRL, &cctl);
	else
		return dect_build_tail_msg(skb, DECT_TM_TYPE_ACCTRL, &cctl);
}

static struct sk_buff *dect_tbc_build_encctrl(const struct dect_tbc *tbc,
					      enum dect_encctrl_cmds cmd)
{
	struct dect_encctrl ectl;
	struct sk_buff *skb;

	skb = dect_t_skb_alloc();
	if (skb == NULL)
		return NULL;

	ectl.fmid = tbc->cell->fmid;
	ectl.pmid = dect_build_pmid(&tbc->id.pmid);
	ectl.cmd = cmd;

	return dect_build_tail_msg(skb, DECT_TM_TYPE_ENCCTRL, &ectl);
}

static int dect_tbc_send_confirm(const struct dect_tbc *tbc)
{
	struct sk_buff *skb;

	tbc_debug(tbc, "TX CONFIRM\n");
	skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_BEARER_CONFIRM);
	if (skb == NULL)
		return -ENOMEM;

	/* The first response is permitted in any frame */
	if (tbc->state == DECT_TBC_REQ_RCVD)
		skb->priority = DECT_MT_HIGH_PRIORITY;
	skb_queue_tail(&tbc->txb->m_tx_queue, skb);
	return 0;
}

static int dect_tbc_send_attributes_confirm(const struct dect_tbc *tbc)
{
	struct dect_cctrl cctl;
	struct sk_buff *skb;

	tbc_debug(tbc, "TX ATTRIBUTES_T_CONFIRM\n");

	skb = dect_t_skb_alloc();
	if (skb == NULL)
		return -ENOMEM;

	cctl.cmd     = DECT_CCTRL_ATTRIBUTES_T_CONFIRM;
	cctl.ecn     = tbc->id.ecn;
	cctl.lbn     = tbc->lbn;
	cctl.type    = DECT_CCTRL_TYPE_SYMETRIC_BEARER;
	cctl.service = tbc->id.service;
	cctl.cf      = false;

	cctl.slot   = DECT_FULL_SLOT;
	cctl.a_mod  = DECT_MODULATION_2_LEVEL;
	cctl.bz_mod = DECT_MODULATION_2_LEVEL;
	cctl.acr    = 0;

	if (tbc->id.type == DECT_MAC_CONN_BASIC)
		dect_build_tail_msg(skb, DECT_TM_TYPE_BCCTRL, &cctl);
	else
		dect_build_tail_msg(skb, DECT_TM_TYPE_ACCTRL, &cctl);

	skb_queue_tail(&tbc->txb->m_tx_queue, skb);
	return 0;
}

static int dect_tbc_event(const struct dect_tbc *tbc, enum dect_tbc_event event)
{
	const struct dect_cluster_handle *clh = tbc->cell->handle.clh;

	return clh->ops->mbc_conn_notify(clh, &tbc->id, event);
}

static void dect_tbc_release_notify(const struct dect_tbc *tbc,
				    enum dect_release_reasons reason)
{
	const struct dect_cluster_handle *clh = tbc->cell->handle.clh;

	clh->ops->mbc_dis_indicate(clh, &tbc->id, reason);
}

static void dect_tdd_channel_desc(struct dect_channel_desc *dst,
				  const struct dect_channel_desc *chd)
{
	dst->pkt     = chd->pkt;
	dst->b_fmt   = chd->b_fmt;
	dst->carrier = chd->carrier;
	dst->slot    = chd->slot < 12 ? chd->slot + 12 : chd->slot - 12;
}

static struct dect_tbc *dect_tbc_lookup(const struct dect_cell *cell,
					const struct dect_mbc_id *id)
{
	struct dect_tbc *tbc;

	list_for_each_entry(tbc, &cell->tbcs, list) {
		if (!dect_pmid_cmp(&tbc->id.pmid, &id->pmid) &&
		    tbc->id.type == id->type &&
		    tbc->id.ecn  == id->ecn)
			return tbc;
	}
	return NULL;
}

static void dect_tbc_destroy(struct dect_cell *cell, struct dect_tbc *tbc)
{
	tbc_debug(tbc, "destroy\n");
	dect_timer_del(&tbc->wd_timer);
	dect_timer_del(&tbc->wait_timer);
	dect_timer_del(&tbc->release_timer);
	dect_timer_del(&tbc->normal_rx_timer);
	dect_timer_del(&tbc->normal_tx_timer);
	dect_timer_del(&tbc->rx_timer);
	dect_timer_del(&tbc->tx_timer);
	dect_timer_del(&tbc->enc_timer);
	dect_bc_release(&tbc->bc);

	dect_transceiver_release(&cell->trg, tbc->txb->trx, &tbc->txb->chd);
	dect_bearer_release(tbc->cell, tbc->txb);

	dect_transceiver_release(&cell->trg, tbc->rxb->trx, &tbc->rxb->chd);
	dect_bearer_release(tbc->cell, tbc->rxb);

	list_del(&tbc->list);
	kfree_skb(tbc->c_rx_skb);
	kfree_skb(tbc->c_tx_skb);
	kfree(tbc);
}

static void dect_tbc_release_timer(struct dect_cell *cell, void *data)
{
	struct dect_tbc *tbc = data;
	struct sk_buff *m_skb;

	if (tbc->state == DECT_TBC_NONE ||
	    tbc->state == DECT_TBC_REQ_SENT ||
	    tbc->state == DECT_TBC_RELEASED)
		return dect_tbc_destroy(cell, tbc);

	tbc_debug(tbc, "TX RELEASE\n");
	m_skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_RELEASE);
	if (m_skb != NULL) {
		/* RELEASE messages may appear in any frame */
		m_skb->priority = DECT_MT_HIGH_PRIORITY;
		skb_queue_tail(&tbc->txb->m_tx_queue, m_skb);
	}

	switch (tbc->state) {
	default:
		tbc->state = DECT_TBC_RELEASING;
		break;
	case DECT_TBC_RELEASING:
		tbc->state = DECT_TBC_RELEASED;
		break;
	}

	dect_bearer_timer_add(tbc->cell, tbc->txb, &tbc->release_timer,
			      DECT_MT_FRAME_RATE);
}

static void dect_tbc_release(const struct dect_cell_handle *ch,
			     const struct dect_mbc_id *id,
			     enum dect_release_reasons reason)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_tbc *tbc;

	tbc = dect_tbc_lookup(cell, id);
	if (tbc == NULL)
		return;
	dect_tbc_release_timer(cell, tbc);
}

static bool dect_ct_tail_allowed(const struct dect_cell *cell, u8 framenum)
{
	if (cell->mode == DECT_MODE_FP)
		return (framenum & 0x1) == 0x1;
	else
		return (framenum & 0x1) == 0x0;
}

/**
 * TBC normal receive half frame timer:
 *
 * Deliver received data segments to the DLC at half frame boundaries.
 * Data is delivered for the following channels:
 *
 * - C_S after an ARQ window
 * - I_N normal delay
 *
 * Additionally, in half frames that end an ARQ window, acknowledgment of
 * C_S segment reception of the preceeding ransmit half frame is verified.
 */
static void dect_tbc_normal_rx_timer(struct dect_cell *cell, void *data)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_tbc *tbc = data;
	struct sk_buff *skb;

	tbc_debug(tbc, "Normal RX timer\n");

	if (tbc->c_rx_skb != NULL) {
		skb = tbc->c_rx_skb;
		tbc->c_rx_skb = NULL;
		clh->ops->mbc_data_indicate(clh, &tbc->id, DECT_MC_C_S, skb);
	}

	if (tbc->b_rx_skb != NULL) {
		skb = tbc->b_rx_skb;
		tbc->b_rx_skb = NULL;
		clh->ops->mbc_data_indicate(clh, &tbc->id, DECT_MC_I_N, skb);
	}

	if (dect_ct_tail_allowed(cell, dect_framenum(cell, DECT_TIMER_RX)) &&
	    tbc->c_tx_ok) {
		if (tbc->rxb->q) {
			tbc_debug(tbc, "ARQ acknowledgement\n");
			dect_tbc_event(tbc, DECT_TBC_ACK_RECEIVED);
		} else
			tbc_debug(tbc, "C-channel data lost\n");

		tbc->c_tx_ok = false;
	}

	tbc->rxb->q = 0;

	dect_timer_add(cell, &tbc->normal_rx_timer, DECT_TIMER_RX, 1,
		       dect_normal_receive_end(cell));
}

static void dect_tbc_rx_timer(struct dect_cell *cell, void *data)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_tbc *tbc = data;
	struct sk_buff *skb;

	tbc_debug(tbc, "RX timer\n");

	if (tbc->b_rx_skb != NULL) {
		skb = tbc->b_rx_skb;
		tbc->b_rx_skb = NULL;
		clh->ops->mbc_data_indicate(clh, &tbc->id, DECT_MC_I_N, skb);
	}

	dect_bearer_timer_add(cell, tbc->rxb, &tbc->rx_timer, 1);
}

/**
 * TBC normal transmit half frame timer:
 *
 * Request data from the DLC for the next frame. Data is requested for the
 * following channels:
 *
 * - C_S before an ARQ window starts
 * - I_N normal delay
 */
static void dect_tbc_normal_tx_timer(struct dect_cell *cell, void *data)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_tbc *tbc = data;

	tbc_debug(tbc, "Normal TX timer\n");

	if (dect_ct_tail_allowed(cell, dect_framenum(cell, DECT_TIMER_TX))) {
		if (tbc->c_tx_skb != NULL) {
			kfree_skb(tbc->c_tx_skb);
			tbc->c_tx_skb = NULL;
			tbc->c_tx_ok = false;
		}
		clh->ops->mbc_dtr_indicate(clh, &tbc->id, DECT_MC_C_S);
	}

	if (tbc->id.service != DECT_SERVICE_IN_MIN_DELAY)
		clh->ops->mbc_dtr_indicate(clh, &tbc->id, DECT_MC_I_N);

	dect_timer_add(cell, &tbc->normal_tx_timer, DECT_TIMER_TX, 1,
		       dect_normal_transmit_base(cell));
}

static void dect_tbc_tx_timer(struct dect_cell *cell, void *data)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_tbc *tbc = data;

	tbc_debug(tbc, "TX timer\n");

	clh->ops->mbc_dtr_indicate(clh, &tbc->id, DECT_MC_I_N);

	dect_bearer_timer_add(cell, tbc->txb, &tbc->tx_timer, 1);
}

static int dect_tbc_establish(struct dect_cell *cell, struct dect_tbc *tbc)
{
	tbc_debug(tbc, "established\n");

	tbc->state = DECT_TBC_ESTABLISHED;
	if (dect_tbc_event(tbc, DECT_TBC_SETUP_COMPLETE) < 0)
		return -1;

	dect_timer_add(cell, &tbc->normal_rx_timer, DECT_TIMER_RX, 0,
		       dect_normal_receive_end(cell));
	dect_timer_add(cell, &tbc->normal_tx_timer, DECT_TIMER_TX, 0,
		       dect_normal_transmit_base(cell));

	if (tbc->id.service == DECT_SERVICE_IN_MIN_DELAY) {
		dect_bearer_timer_add(cell, tbc->txb, &tbc->rx_timer, 0);
		dect_bearer_timer_add(cell, tbc->txb, &tbc->tx_timer, 0);
	}
	return 0;
}

/**
 * dect_watchdog_timer - connection watchdog timer
 *
 * The watchdog timer is forwarded when an expected event occurs, on expiry
 * it will release the TBC. The relevant event depends on the TBC's state:
 *
 * Until ESTABLISHED state, P_T tails must be sent in every allowed frame.
 * The timer is forwarded when receiving a P_T tail in an allowed frame.
 *
 * In ESTABLISHED state, an RFPI handshake must be received at least
 * every T201 (5) seconds. The timer is forwarded when receiving an N_T
 * tail containing a matching RFPI.
 */
static void dect_tbc_watchdog_timer(struct dect_cell *cell, void *data)
{
	struct dect_tbc *tbc = data;

	tbc_debug(tbc, "watchdog expire\n");
	if (tbc->state != DECT_TBC_ESTABLISHED)
		dect_tbc_event(tbc, DECT_TBC_SETUP_FAILED);
	else
		dect_tbc_release_notify(tbc, DECT_REASON_TIMEOUT_LOST_HANDSHAKE);

	dect_tbc_release_timer(cell, tbc);
}

static void dect_tbc_watchdog_reschedule(struct dect_cell *cell,
					 struct dect_tbc *tbc)
{
	u16 timeout;

	if (tbc->state == DECT_TBC_ESTABLISHED)
		timeout = DECT_TBC_RFPI_TIMEOUT;
	else
		timeout = DECT_MT_FRAME_RATE;

	tbc_debug(tbc, "watchdog reschedule timeout: %u\n", timeout);
	dect_bearer_timer_add(cell, tbc->rxb, &tbc->wd_timer, timeout);
}

static int dect_tbc_check_attributes(struct dect_cell *cell, struct dect_tbc *tbc,
				     const struct dect_cctrl *cctl)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;

	tbc_debug(tbc, "RX ATTRIBUTES_T_REQUEST\n");
	tbc->id.ecn = cctl->ecn;
	tbc->lbn = cctl->lbn;
	tbc->id.service = cctl->service;

	if (clh->ops->mbc_conn_indicate(clh, &cell->handle, &tbc->id) < 0)
		return -1;
	return 0;
}

/**
 * dect_tbc_state_process - connection setup and maintenance state proccesing
 *
 * Process all messages before ESTABLISHED state, as well as all connection
 * control messages in ESTABLISHED state.
 */
static int dect_tbc_state_process(struct dect_cell *cell, struct dect_tbc *tbc,
				  const struct dect_tail_msg *tm)
{
	const struct dect_cctrl *cctl = &tm->cctl;
	struct sk_buff *m_skb;
	u8 framenum;

	if (tbc->state == DECT_TBC_OTHER_WAIT) {
		tbc_debug(tbc, "RX in OTHER_WAIT\n");
		/* Any message except RELEASE switches the bearer to
		 * ESTABLISHED state.
		 */
		if ((tm->type == DECT_TM_TYPE_BCCTRL ||
		     tm->type == DECT_TM_TYPE_ACCTRL) &&
		    (cctl->fmid != cell->fmid ||
		     cctl->pmid != dect_build_pmid(&tbc->id.pmid) ||
		     cctl->cmd == DECT_CCTRL_RELEASE))
			goto release;

		if (dect_tbc_establish(cell, tbc) < 0)
			goto release;
		goto out;
	}

	/* Before OTHER_WAIT state, M_T tails must be received in every allowed
	 * frame. FPs may send M_T tails in uneven frames, PTs in even frames.
	 * Additionally FPs may transmit responses to BEARER_REQUEST messages in
	 * every frame.
	 */
	framenum = dect_framenum(cell, DECT_TIMER_RX);
	if (cell->mode == DECT_MODE_FP) {
		if ((framenum & 0x1) == 1)
			return 1;
	} else {
		if ((framenum & 0x1) == 0 && tbc->state != DECT_TBC_REQ_SENT)
			return 1;
	}

	if (tm->type != DECT_TM_TYPE_BCCTRL && tm->type != DECT_TM_TYPE_ACCTRL)
		goto release;

	switch (cctl->cmd) {
	case DECT_CCTRL_ATTRIBUTES_T_REQUEST:
	case DECT_CCTRL_ATTRIBUTES_T_CONFIRM:
	case DECT_CCTRL_BANDWIDTH_T_REQUEST:
	case DECT_CCTRL_BANDWIDTH_T_CONFIRM:
	case DECT_CCTRL_CHANNEL_LIST:
		break;
	default:
		if (cctl->fmid != cell->fmid)
			goto release;
		/* fall through */
	case DECT_CCTRL_RELEASE:
		if (cctl->pmid != dect_build_pmid(&tbc->id.pmid))
			goto release;
	}

	switch ((int)tbc->state) {
	case DECT_TBC_NONE:
		/*
		 * Receiving side, initial request.
		 */
		tbc->state = DECT_TBC_REQ_RCVD;
		break;

	case DECT_TBC_REQ_RCVD:
	case DECT_TBC_RESPONSE_SENT:
		/*
		 * Receiving side: waiting for LLME to create MBC. Only "WAIT"
		 * messages are valid in both directions.
		 */
		tbc_debug(tbc, "RX in REQ_RCVD: %llx\n", (unsigned long long)cctl->cmd);

		if (tbc->id.type == DECT_MAC_CONN_ADVANCED &&
		    cctl->cmd == DECT_CCTRL_ATTRIBUTES_T_REQUEST)
			dect_tbc_check_attributes(cell, tbc, cctl);
		else if (cctl->cmd != DECT_CCTRL_WAIT)
			goto release;

		m_skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_WAIT);
		if (m_skb == NULL)
			goto release;
		skb_queue_tail(&tbc->txb->m_tx_queue, m_skb);
		break;

	case DECT_TBC_REQ_SENT:
	case DECT_TBC_WAIT_RCVD:
		/*
		 * Initiator: request was sent, waiting for confirm. "WAIT"
		 * messages must be responded to with another "WAIT" message.
		 */
		tbc_debug(tbc, "Reply in REQ_SENT %u\n", tm->type);
		if (cctl->cmd != DECT_CCTRL_BEARER_CONFIRM) {
			if (cctl->cmd != DECT_CCTRL_WAIT)
				goto release;

			m_skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_WAIT);
			if (m_skb == NULL)
				goto release;
			skb_queue_tail(&tbc->txb->m_tx_queue, m_skb);

			tbc->state = DECT_TBC_WAIT_RCVD;
		} else {
			tbc_debug(tbc, "Confirmed\n");
			m_skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_WAIT);
			if (m_skb == NULL)
				goto release;
			skb_queue_tail(&tbc->txb->m_tx_queue, m_skb);

			tbc->state = DECT_TBC_OTHER_WAIT;
		}
		break;

	case DECT_TBC_ESTABLISHED:
		if (cctl->cmd != DECT_CCTRL_RELEASE)
			break;
		/* Immediate release */
		dect_tbc_release_notify(tbc, DECT_REASON_BEARER_RELEASE);
		dect_tbc_destroy(cell, tbc);
		return 0;

	case DECT_TBC_RELEASING:
		/*
		 * Unacknowledged release procedure in progress, ignore the
		 * packet unless its a release message, in which case the
		 * bearer can be destroyed immediately (crossed bearer release
		 * procedure).
		 */
		if (cctl->cmd == DECT_CCTRL_RELEASE)
			dect_tbc_destroy(cell, tbc);

	case DECT_TBC_RELEASED:
		return 0;
	}

out:
	dect_tbc_watchdog_reschedule(cell, tbc);
	return 1;

release:
	dect_tbc_event(tbc, DECT_TBC_SETUP_FAILED);
	dect_tbc_release_timer(cell, tbc);
	return 0;
}

static void dect_tbc_enc_timer(struct dect_cell *cell, void *data)
{
	struct dect_tbc *tbc = data;
	enum dect_encctrl_cmds cmd;
	struct sk_buff *skb;

	tbc_debug(tbc, "encryption timer: state: %u cnt: %u\n",
		  tbc->enc_state, tbc->enc_msg_cnt);

	if (++tbc->enc_msg_cnt > 5) {
		dect_tbc_release_notify(tbc, DECT_REASON_BEARER_RELEASE);
		return dect_tbc_release_timer(cell, tbc);
	}

	dect_bearer_timer_add(cell, tbc->txb, &tbc->enc_timer, 2);

	switch (tbc->enc_state) {
	case DECT_TBC_ENC_START_REQ_RCVD:
		tbc_debug(tbc, "TX encryption enabled\n");
		dect_enable_cipher(tbc->txb->trx, tbc->txb->chd.slot, tbc->ck);
		/* fall through */
	case DECT_TBC_ENC_START_CFM_SENT:
		tbc->enc_state = DECT_TBC_ENC_START_CFM_SENT;
		cmd = DECT_ENCCTRL_START_CONFIRM;
		break;
	case DECT_TBC_ENC_START_REQ_SENT:
		cmd = DECT_ENCCTRL_START_REQUEST;
		break;
	default:
		return;
	}

	skb = dect_tbc_build_encctrl(tbc, cmd);
	if (skb == NULL)
		return;
	skb_queue_tail(&tbc->txb->m_tx_queue, skb);
}

static int dect_tbc_enc_state_process(struct dect_cell *cell,
				      struct dect_tbc *tbc,
				      const struct dect_tail_msg *tm)
{
	const struct dect_encctrl *ectl = &tm->encctl;

	if (ectl->fmid != cell->fmid ||
	    ectl->pmid != dect_build_pmid(&tbc->id.pmid))
		return 0;

	switch (ectl->cmd) {
	case DECT_ENCCTRL_START_REQUEST:
		if (tbc->enc_state != DECT_TBC_ENC_DISABLED ||
		    cell->mode != DECT_MODE_FP)
			break;
		tbc->enc_state = DECT_TBC_ENC_START_REQ_RCVD;
		tbc->enc_msg_cnt = 0;

		dect_bearer_timer_add(cell, tbc->txb, &tbc->enc_timer, 0);
		break;
	case DECT_ENCCTRL_START_CONFIRM:
		if (tbc->enc_state != DECT_TBC_ENC_START_REQ_SENT)
			break;
		tbc->enc_state = DECT_TBC_ENC_START_CFM_RCVD;
		tbc->enc_msg_cnt = 0;
		break;
	case DECT_ENCCTRL_START_GRANT:
		if (tbc->enc_state != DECT_TBC_ENC_START_CFM_SENT)
			break;
		tbc->enc_state = DECT_TBC_ENC_ENABLED;

		dect_timer_del(&tbc->enc_timer);
		dect_enable_cipher(tbc->rxb->trx, tbc->rxb->chd.slot, tbc->ck);
		tbc_debug(tbc, "RX encryption enabled\n");
		dect_tbc_event(tbc, DECT_TBC_CIPHER_ENABLED);
		break;
	case DECT_ENCCTRL_STOP_REQUEST:
		break;
	case DECT_ENCCTRL_STOP_CONFIRM:
		break;
	case DECT_ENCCTRL_STOP_GRANT:
		break;
	default:
		return 0;
	}
	return 1;
}

static void dect_tbc_queue_cs_data(struct dect_cell *cell, struct dect_tbc *tbc,
				   struct sk_buff *skb,
				   const struct dect_tail_msg *tm)
{
	skb = skb_clone(skb, GFP_ATOMIC);
	if (skb == NULL)
		return;
	skb_pull(skb, DECT_T_FIELD_OFF);
	skb_trim(skb, DECT_C_S_SDU_SIZE);

	DECT_CS_CB(skb)->seq = tm->ctd.seq;
	tbc->c_rx_skb = skb;
}

static void dect_tbc_rcv(struct dect_cell *cell, struct dect_bearer *bearer,
			 struct sk_buff *skb)
{
	struct dect_tbc *tbc = bearer->tbc;
	struct dect_tail_msg _tm, *tm = &_tm;

	/* Verify A-field checksum. Sucessful reception of the A-field is
	 * indicated by transmitting the Q2 bit in the reverse direction.
	 */
	if (DECT_TRX_CB(skb)->csum & DECT_CHECKSUM_A_CRC_OK)
		tbc->txb->q = DECT_HDR_Q2_FLAG;
	else
		goto rcv_b_field;

	tbc->rxb->q = skb->data[DECT_HDR_Q2_OFF] & DECT_HDR_Q2_FLAG;

	if (dect_parse_tail_msg(tm, skb) < 0)
		goto err;

	if (tbc->state != DECT_TBC_ESTABLISHED ||
	    tm->type == DECT_TM_TYPE_BCCTRL ||
	    tm->type == DECT_TM_TYPE_ACCTRL) {
		if (!dect_tbc_state_process(cell, tbc, tm))
			goto err;
	}

	tbc_debug(tbc, "receive\n");

	/* Reschedule watchdog on successful RFPI handshake. */
	if (tm->type == DECT_TM_TYPE_ID && !dect_rfpi_cmp(&tm->idi, &cell->idi))
		dect_tbc_watchdog_reschedule(cell, tbc);

	if (tm->type == DECT_TM_TYPE_ENCCTRL) {
		if (!dect_tbc_enc_state_process(cell, tbc, tm))
			goto err;
	}

	dect_bc_rcv(cell, &tbc->bc, skb, tm);

	switch (tbc->enc_state) {
	case DECT_TBC_ENC_START_REQ_SENT:
	case DECT_TBC_ENC_START_CFM_SENT:
		goto err;
	default:
		break;
	}

	if (tbc->state != DECT_TBC_REQ_RCVD &&
	    tbc->state != DECT_TBC_RESPONSE_SENT) {
		if (tm->type == DECT_TM_TYPE_CT)
			dect_tbc_queue_cs_data(cell, tbc, skb, tm);
	}

rcv_b_field:
	skb_pull(skb, DECT_A_FIELD_SIZE);
	skb_trim(skb, DECT_B_FIELD_SIZE);
	tbc->b_rx_skb = skb;
	return;

err:
	kfree_skb(skb);
}

static void dect_tbc_data_request(const struct dect_cell_handle *ch,
				  const struct dect_mbc_id *id,
				  enum dect_data_channels chan,
				  struct sk_buff *skb)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_tbc *tbc;

	tbc = dect_tbc_lookup(cell, id);
	if (tbc == NULL)
		goto err;

	switch (chan) {
	case DECT_MC_C_S:
		tbc_debug(tbc, "data request len: %u sequence: %u cur_tx: %p\n",
			  skb->len, DECT_CS_CB(skb)->seq, tbc->c_tx_skb);

		DECT_A_CB(skb)->id = DECT_CS_CB(skb)->seq ? DECT_TI_CT_PKT_1 :
							    DECT_TI_CT_PKT_0;
		tbc->c_tx_skb = skb;
		break;
	case DECT_MC_I_N:
		tbc->b_tx_skb = skb;
		break;
	default:
		goto err;
	}
	return;

err:
	kfree_skb(skb);
}

static int dect_tbc_enc_eks_request(const struct dect_cell_handle *ch,
				    const struct dect_mbc_id *id,
				    enum dect_cipher_states status)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_tbc *tbc;
	struct sk_buff *skb;

	tbc = dect_tbc_lookup(cell, id);
	if (tbc == NULL)
		return -ENOENT;

	skb = dect_tbc_build_encctrl(tbc, DECT_ENCCTRL_START_REQUEST);
	if (skb != NULL)
		skb_queue_tail(&tbc->txb->m_tx_queue, skb);

	tbc->enc_state = DECT_TBC_ENC_START_REQ_SENT;
	tbc->enc_msg_cnt = 0;
	dect_bearer_timer_add(cell, tbc->txb, &tbc->enc_timer, 0);
	return 0;
}

static int dect_tbc_enc_key_request(const struct dect_cell_handle *ch,
				    const struct dect_mbc_id *id, u64 ck)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_tbc *tbc;

	tbc = dect_tbc_lookup(cell, id);
	if (tbc == NULL)
		return -ENOENT;

	tbc_debug(tbc, "enc key request: %.16llx\n", (unsigned long long)ck);
	tbc->ck = ck;
	return 0;
}

static void dect_tbc_enable(struct dect_cell *cell, struct dect_tbc *tbc)
{
	dect_bearer_enable(tbc->rxb);
	dect_bearer_enable(tbc->txb);
	dect_bc_init(cell, &tbc->bc);
}

/*
 * Activation timer: enable the bearer once the TX channel is accessible,
 * which is defined by the receivers scanning sequence.
 */
static void dect_tbc_enable_timer(struct dect_cell *cell,
				  struct dect_bearer *bearer)
{
	struct dect_tbc *tbc = bearer->tbc;
	struct sk_buff *skb;

	tbc_debug(tbc, "TX ACCESS_REQUEST\n");
	skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_ACCESS_REQ);
	if (skb == NULL)
		return;

	/* The packet overrides the T-MUX rules. PPs use a special tail
	 * coding for the first transmission. */
	skb->priority = DECT_MT_HIGH_PRIORITY;
	if (cell->mode == DECT_MODE_FP)
		DECT_A_CB(skb)->id = DECT_TI_MT;
	else
		DECT_A_CB(skb)->id = DECT_TI_MT_PKT_0;

	dect_tbc_enable(cell, tbc);
	skb_queue_tail(&tbc->txb->m_tx_queue, skb);
	tbc->state = DECT_TBC_REQ_SENT;

	/* Start watchdog */
	dect_bearer_timer_add(cell, tbc->rxb, &tbc->wd_timer, 1);
}

static const struct dect_bearer_ops dect_tbc_ops = {
	.state		= DECT_TRAFFIC_BEARER,
	.enable		= dect_tbc_enable_timer,
	.rcv		= dect_tbc_rcv,
};

/**
 * dect_tbc_init - initialise a traffic bearer control instance
 *
 * @cell:	DECT cell
 * @id:		MBC ID
 * @rchd:	RX channel description
 * @tchd:	TX channel description
 */
static struct dect_tbc *dect_tbc_init(struct dect_cell *cell,
				      const struct dect_mbc_id *id,
				      struct dect_transceiver *rtrx,
				      struct dect_transceiver *ttrx,
				      const struct dect_channel_desc *rchd,
				      const struct dect_channel_desc *tchd)

{
	struct dect_tbc *tbc;

	tbc = kzalloc(sizeof(*tbc), GFP_ATOMIC);
	if (tbc == NULL)
		goto err1;
	tbc->cell = cell;
	memcpy(&tbc->id, id, sizeof(tbc->id));
	INIT_LIST_HEAD(&tbc->bc.list);
	dect_timer_init(&tbc->wait_timer);
	dect_timer_setup(&tbc->wd_timer, dect_tbc_watchdog_timer, tbc);
	dect_timer_setup(&tbc->release_timer, dect_tbc_release_timer, tbc);

	dect_timer_setup(&tbc->normal_rx_timer, dect_tbc_normal_rx_timer, tbc);
	dect_timer_setup(&tbc->normal_tx_timer, dect_tbc_normal_tx_timer, tbc);
	dect_timer_setup(&tbc->rx_timer, dect_tbc_rx_timer, tbc);
	dect_timer_setup(&tbc->tx_timer, dect_tbc_tx_timer, tbc);

	dect_timer_setup(&tbc->enc_timer, dect_tbc_enc_timer, tbc);

	tbc->rxb = dect_bearer_init(cell, &dect_tbc_ops, DECT_DUPLEX_BEARER,
				    rtrx, rchd, DECT_BEARER_RX, tbc);
	if (tbc->rxb == NULL)
		goto err2;

	tbc->txb = dect_bearer_init(cell, &dect_tbc_ops, DECT_DUPLEX_BEARER,
				    ttrx, tchd, DECT_BEARER_TX, tbc);
	if (tbc->txb == NULL)
		goto err3;

	list_add_tail(&tbc->list, &cell->tbcs);
	return tbc;

err3:
	dect_bearer_release(cell, tbc->rxb);
err2:
	kfree(tbc);
err1:
	return NULL;
}

static int dect_tbc_initiate(const struct dect_cell_handle *ch,
			     const struct dect_mbc_id *id,
			     const struct dect_channel_desc *chd)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_transceiver *ttrx, *rtrx;
	struct dect_channel_desc tchd, rchd;
	struct dect_tbc *tbc;
	u8 rssi;
	int err;

	/* Select TDD slot pair and reserve transceiver resources */
	tchd.pkt   = chd->pkt;
	tchd.b_fmt = chd->b_fmt;
	err = dect_select_channel(cell, &ttrx, &tchd, &rssi, true);
	if (err < 0)
		goto err1;
	dect_transceiver_reserve(&cell->trg, ttrx, &tchd);

	err = -ENOSPC;
	dect_tdd_channel_desc(&rchd, &tchd);
	rtrx = dect_select_transceiver(cell, &rchd);
	if (rtrx == NULL)
		goto err2;
	dect_transceiver_reserve(&cell->trg, rtrx, &rchd);

	err = -ENOMEM;
	tbc = dect_tbc_init(cell, id, rtrx, ttrx, &rchd, &tchd);
	if (tbc == NULL)
		goto err3;
	dect_tx_bearer_schedule(cell, tbc->txb, rssi);
	return 0;

err3:
	dect_transceiver_release(&cell->trg, rtrx, &rchd);
err2:
	dect_transceiver_release(&cell->trg, ttrx, &tchd);
err1:
	return err;
}

static int dect_tbc_confirm(const struct dect_cell_handle *ch,
			    const struct dect_mbc_id *id)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_tbc *tbc;
	int err;

	tbc = dect_tbc_lookup(cell, id);
	if (tbc == NULL)
		return -ENOENT;
	tbc->id.mcei = id->mcei;
	tbc_debug(tbc, "confirm\n");

	/* Stop wait timer and send CONFIRM */
	dect_timer_del(&tbc->wait_timer);
	if (id->type == DECT_MAC_CONN_BASIC)
		err = dect_tbc_send_confirm(tbc);
	else
		err = dect_tbc_send_attributes_confirm(tbc);
	if (err < 0)
		return err;
	tbc->state = DECT_TBC_OTHER_WAIT;
	return 0;
}

static void dect_tbc_wait_timer(struct dect_cell *cell, void *data)
{
	struct dect_tbc *tbc = data;
	struct sk_buff *skb;

	tbc_debug(tbc, "wait timer\n");
	skb = dect_tbc_build_bcctrl(tbc, DECT_CCTRL_WAIT);
	if (skb == NULL)
		return;

	/* The first response is permitted in any frame */
	if (tbc->state == DECT_TBC_REQ_RCVD)
		skb->priority = DECT_MT_HIGH_PRIORITY;
	skb_queue_tail(&tbc->txb->m_tx_queue, skb);

	tbc->state = DECT_TBC_RESPONSE_SENT;
}

/**
 * dect_tbc_rcv_request - handle incoming connection setup attempts
 *
 *
 */
static void dect_tbc_rcv_request(struct dect_cell *cell,
				 const struct dect_transceiver_slot *ts,
				 const struct dect_tail_msg *tm,
				 struct sk_buff *skb)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_transceiver *rtrx, *ttrx;
	struct dect_channel_desc rchd, tchd;
	struct dect_mbc_id id;
	struct dect_tbc *tbc;

	if (tm->cctl.fmid != cell->fmid)
		goto err1;
	switch (tm->cctl.cmd) {
	case DECT_CCTRL_ACCESS_REQ:
		break;
	case DECT_CCTRL_BEARER_HANDOVER_REQ:
	case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
		/* Handover can only be initiated by the PP */
		/* FIXME: temporarily disabled since not handled */
		if (0 && cell->mode == DECT_MODE_FP)
			break;
	default:
		rx_debug(cell, "unhandled TBC request: %llu\n",
			 (unsigned long long)tm->cctl.cmd);
		goto err1;
	}

	/* Select transceivers for RX/TX and reserve resources */
	memcpy(&rchd, &ts->chd, sizeof(rchd));
	rchd.pkt   = DECT_PACKET_P32;
	rchd.b_fmt = DECT_B_UNPROTECTED;
	rtrx = dect_select_transceiver(cell, &rchd);
	if (rtrx == NULL)
		goto err1;
	dect_transceiver_reserve(&cell->trg, rtrx, &rchd);

	dect_tdd_channel_desc(&tchd, &rchd);
	ttrx = dect_select_transceiver(cell, &tchd);
	if (ttrx == NULL)
		goto err2;
	dect_transceiver_reserve(&cell->trg, ttrx, &tchd);

	memset(&id, 0, sizeof(id));
	memcpy(&id.ari, &cell->idi.pari, sizeof(id.ari));
	dect_parse_pmid(&id.pmid, tm->cctl.pmid);

	if (tm->type == DECT_TM_TYPE_BCCTRL) {
		/* Basic MAC connections only support the I_N_minimal_delay service */
		id.type    = DECT_MAC_CONN_BASIC;
		id.service = DECT_SERVICE_IN_MIN_DELAY;
	} else {
		/* Service is unknown at this time */
		id.type    = DECT_MAC_CONN_ADVANCED;
		id.service = DECT_SERVICE_UNKNOWN;
	}

	/* Initialize TBC */
	tbc = dect_tbc_init(cell, &id, rtrx, ttrx, &rchd, &tchd);
	if (tbc == NULL)
		goto err3;
	tbc->state = DECT_TBC_REQ_RCVD;
	tbc_debug(tbc, "RCV ACCESS_REQUEST\n");

	/* Set Q2 bit on first response */
	tbc->txb->q = DECT_HDR_Q2_FLAG;

	/* Start the WAIT transmit timer */
	dect_timer_setup(&tbc->wait_timer, dect_tbc_wait_timer, tbc);
	dect_bearer_timer_add(cell, tbc->txb, &tbc->wait_timer, 1);

	/* Start watchdog timer: until ESTABLISHED state, the remote side
	 * must transmit a M-tail in every allowed frame. */
	dect_tbc_watchdog_reschedule(cell, tbc);
	dect_tbc_enable(cell, tbc);

	if (tbc->id.type == DECT_MAC_CONN_BASIC) {
		if (clh->ops->mbc_conn_indicate(clh, &cell->handle, &tbc->id) < 0)
			goto err4;
	} else {
		if (dect_tbc_send_confirm(tbc) < 0)
			goto err4;
		tbc->state = DECT_TBC_RESPONSE_SENT;
	}

	kfree_skb(skb);
	return;

err4:
	dect_tbc_destroy(cell, tbc);
err3:
	dect_transceiver_release(&cell->trg, ttrx, &tchd);
err2:
	dect_transceiver_release(&cell->trg, rtrx, &rchd);
err1:
	kfree_skb(skb);
}

/*
 * Connectionless Bearer Control (CBC)
 */

static void dect_cbc_rcv(struct dect_cell *cell, struct dect_bearer *bearer,
			 struct sk_buff *skb)
{
	struct dect_cbc *cbc = bearer->cbc;
	struct dect_tail_msg tm;

	dect_parse_tail_msg(&tm, skb);
	dect_bc_rcv(cell, &cbc->bc, skb, &tm);
	kfree_skb(skb);
}

static const struct dect_bearer_ops dect_cbc_ops = {
	.state		= DECT_CL_BEARER,
	.rcv		= dect_cbc_rcv,
};

/**
 * dect_cbc_init - Initialise a connectionless bearer control
 *
 * @cell:	DECT cell
 * @chd:	channel description
 */
static struct dect_cbc *dect_cbc_init(struct dect_cell *cell,
				      struct dect_channel_desc *chd)
{
	struct dect_bearer *bearer;
	enum dect_slot_states mode;
	struct dect_cbc *cbc = NULL;

	bearer = dect_bearer_init(cell, &dect_cbc_ops, DECT_SIMPLEX_BEARER,
				  NULL, chd, mode, cbc);
	if (bearer == NULL)
		return NULL;
	cbc->dl_bearer = bearer;

	dect_bc_init(cell, &cbc->bc);
	return cbc;
}

/*
 * Dummy Bearer Control (DBC)
 */

#define dbc_debug(dbc, fmt, args...) \
	pr_debug("DBC slot %u carrier %u: " fmt, \
		 (dbc)->bearer->chd.slot, (dbc)->bearer->chd.carrier, ## args)

static void dect_dbc_rcv(struct dect_cell *cell, struct dect_bearer *bearer,
			 struct sk_buff *skb)
{
	struct dect_dbc *dbc = bearer->dbc;
	struct dect_tail_msg tm;

	dect_parse_tail_msg(&tm, skb);
	dect_bc_rcv(cell, &dbc->bc, skb, &tm);
	kfree_skb(skb);
}

static void dect_dbc_report_rssi(struct dect_cell *cell,
				 struct dect_bearer *bearer,
				 u8 slot, u8 rssi)
{
	dbc_debug(bearer->dbc, "RSSI: selection: %u now: %u\n", bearer->rssi, rssi);
}

static void dect_dbc_quality_control_timer(struct dect_cell *cell, void *data)
{
	struct dect_dbc *dbc = data;
	struct dect_bearer *bearer = dbc->bearer;

	switch (dbc->qctrl) {
	case DECT_BEARER_QCTRL_WAIT:
		dbc_debug(dbc, "quality control: confirm quality\n");
		dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_RX);
		dect_set_carrier(bearer->trx, bearer->chd.slot, bearer->chd.carrier);
		dbc->qctrl = DECT_BEARER_QCTRL_CONFIRM;
		dect_timer_add(cell, &dbc->qctrl_timer, DECT_TIMER_TX,
			       1, bearer->chd.slot);
		break;
	case DECT_BEARER_QCTRL_CONFIRM:
		dbc_debug(dbc, "quality control: wait\n");
		dect_set_channel_mode(bearer->trx, &bearer->chd, DECT_SLOT_TX);
		dect_set_carrier(bearer->trx, bearer->chd.slot, bearer->chd.carrier);
		dbc->qctrl = DECT_BEARER_QCTRL_WAIT;
		dect_timer_add(cell, &dbc->qctrl_timer, DECT_TIMER_TX,
			       DECT_BEARER_QCTRL_PERIOD - 1, bearer->chd.slot);
		break;
	}
}

static void dect_dbc_enable(struct dect_cell *cell, struct dect_bearer *bearer)
{
	struct dect_dbc *dbc = bearer->dbc;
	u8 framenum = dect_framenum(cell, DECT_TIMER_TX);
	u8 extra;

	extra = DECT_BEARER_QCTRL_FRAMENUM - framenum;
	dbc->qctrl = DECT_BEARER_QCTRL_WAIT;
	dect_timer_add(cell, &dbc->qctrl_timer, DECT_TIMER_TX,
		       DECT_BEARER_QCTRL_PERIOD + extra, bearer->chd.slot);

	dect_bearer_enable(bearer);
}

static const struct dect_bearer_ops dect_dbc_ops = {
	.state		= DECT_DUMMY_BEARER,
	.enable		= dect_dbc_enable,
	.report_rssi	= dect_dbc_report_rssi,
	.rcv		= dect_dbc_rcv,
};

static void dect_dbc_release(struct dect_dbc *dbc)
{
	dect_timer_del(&dbc->qctrl_timer);
	dect_bc_release(&dbc->bc);
	kfree(dbc);
}

/**
 * dect_dbc_init - initialise dummy bearer control
 *
 * @cell:	DECT cell
 * @chd:	channel description (PP only)
 */
static struct dect_dbc *dect_dbc_init(struct dect_cell *cell,
				      const struct dect_channel_desc *chd)
{
	struct dect_channel_desc tchd;
	struct dect_transceiver *trx;
	enum dect_bearer_modes mode;
	struct dect_dbc *dbc;
	u8 uninitialized_var(rssi);

	/* Transmission is always in direction FP -> PP */
	if (cell->mode == DECT_MODE_FP) {
		tchd.pkt   = DECT_PACKET_P00;
		tchd.b_fmt = DECT_B_NONE;
		if (dect_select_channel(cell, &trx, &tchd, &rssi, false) < 0)
			goto err1;
		chd = &tchd;

		mode = DECT_BEARER_TX;
	} else {
		trx = dect_select_transceiver(cell, chd);
		if (trx == NULL)
			goto err1;
		mode = DECT_BEARER_RX;
	}

	dect_transceiver_reserve(&cell->trg, trx, chd);

	dbc = kzalloc(sizeof(*dbc), GFP_ATOMIC);
	if (dbc == NULL)
		goto err2;
	dbc->cell = cell;
	dect_timer_setup(&dbc->qctrl_timer, dect_dbc_quality_control_timer, dbc);
	dect_bc_init(cell, &dbc->bc);

	dbc->bearer = dect_bearer_init(cell, &dect_dbc_ops, DECT_SIMPLEX_BEARER,
				       trx, chd, mode, dbc);
	if (dbc->bearer == NULL)
		goto err3;

	if (cell->mode == DECT_MODE_FP)
		dect_tx_bearer_schedule(cell, dbc->bearer, rssi);
	else
		dect_bearer_enable(dbc->bearer);

	list_add_tail(&dbc->list, &cell->dbcs);
	return dbc;

err3:
	kfree(dbc);
err2:
	dect_transceiver_release(&cell->trg, trx, chd);
err1:
	return NULL;
}

/*
 * Idle Receiver Control
 */

static void dect_initiate_scan(struct dect_transceiver *trx,
			       const struct dect_ari *ari,
			       const struct dect_ari *ari_mask,
			       void (*notify)(struct dect_cell *,
				       	      struct dect_transceiver *,
					      enum dect_scan_status))
{
	struct dect_irc *irc = trx->irc;

	if (ari != NULL) {
		memcpy(&irc->ari, ari, sizeof(irc->ari));
		if (ari_mask != NULL)
			memcpy(&irc->ari_mask, ari_mask, sizeof(irc->ari_mask));
		else
			memset(&irc->ari_mask, 0xff, sizeof(irc->ari_mask));
	}

	memset(&irc->si, 0, sizeof(irc->si));
	irc->notify = notify;

	dect_transceiver_enable(trx);
}

static void dect_restart_scan(struct dect_cell *cell,
			      struct dect_transceiver *trx)
{
	struct dect_irc *irc = trx->irc;

	memset(&irc->si, 0, sizeof(irc->si));
	dect_transceiver_unlock(trx);
	dect_set_channel_mode(trx, &trx->slots[DECT_SCAN_SLOT].chd, DECT_SLOT_SCANNING);
}

/* This function controls the transceiver while scanning. It collects the
 * information requested in struct dect_scan_ctrl and invokes the completion
 * handler once all information is available.
 */
void dect_mac_irc_rcv(struct dect_transceiver *trx, struct sk_buff *skb)
{
	struct dect_cell *cell = trx->cell;
	struct dect_irc *irc = trx->irc;
	struct dect_tail_msg tm;

	dect_parse_tail_msg(&tm, skb);

	switch (trx->state) {
	case DECT_TRANSCEIVER_UNLOCKED:
		if (tm.type != DECT_TM_TYPE_ID)
			break;
		if (dect_ari_masked_cmp(&tm.idi.pari, &irc->ari, &irc->ari_mask))
			break;
		memcpy(&irc->idi, &tm.idi, sizeof(irc->idi));

		irc->timeout = 16 * DECT_FRAMES_PER_MULTIFRAME;
		irc->rssi    = dect_average_rssi(0, DECT_TRX_CB(skb)->rssi);
		dect_transceiver_confirm(trx);
		break;
	case DECT_TRANSCEIVER_LOCK_PENDING:
		irc->rssi = dect_average_rssi(irc->rssi, DECT_TRX_CB(skb)->rssi);
		if (dect_parse_tail(skb) == DECT_TI_QT) {
			dect_bc_update_si(&irc->si, &tm);
			if (dect_bc_si_cycle_complete(&irc->idi, &irc->si) &&
			    irc->si.mask & (1 << DECT_TM_TYPE_MFN))
				irc->notify(cell, trx, DECT_SCAN_COMPLETE);
		}
		break;
	default:
		break;
	}

	kfree_skb(skb);
}

void dect_mac_irc_tick(struct dect_transceiver *trx)
{
	struct dect_cell *cell = trx->cell;
	struct dect_irc *irc = trx->irc;

	switch (trx->state) {
	case DECT_TRANSCEIVER_UNLOCKED:
		/* maintain scan until clock is running */
		irc->rx_scn = dect_next_carrier(0x3ff, irc->rx_scn);
		dect_set_carrier(trx, DECT_SCAN_SLOT, irc->rx_scn);
		break;
	case DECT_TRANSCEIVER_LOCK_PENDING:
		if (--irc->timeout == 0)
			irc->notify(cell, trx, DECT_SCAN_TIMEOUT);
		break;
	default:
		break;
	}
}

static void dect_scan_bearer_rcv(struct dect_cell *cell,
				 struct dect_bearer *bearer,
				 struct sk_buff *skb)
{
	struct dect_transceiver *trx = bearer->trx;
	struct dect_transceiver_slot *ts;
	enum dect_tail_identifications ti;
	struct dect_tail_msg tm;

	ti = dect_parse_tail(skb);
	/* A PP uses a special encoding for the first transmission */
	if (cell->mode == DECT_MODE_PP && ti != DECT_TI_MT)
		goto out;
	if (cell->mode == DECT_MODE_FP && ti != DECT_TI_MT_PKT_0)
		goto out;
	if (dect_parse_tail_msg(&tm, skb) < 0)
		goto out;

	ts = &trx->slots[DECT_TRX_CB(skb)->slot];
	switch (tm.type) {
	case DECT_TM_TYPE_BCCTRL:
	case DECT_TM_TYPE_ACCTRL:
		return dect_tbc_rcv_request(cell, ts, &tm, skb);
	default:
		break;
	}
out:
	kfree_skb(skb);
}

static void dect_scan_bearer_report_rssi(struct dect_cell *cell,
					 struct dect_bearer *bearer,
					 u8 slot, u8 rssi)
{
	if (cell->chl == NULL)
		return;
	dect_chl_update(cell, cell->chl, &bearer->trx->slots[slot].chd, rssi);
}

static const struct dect_bearer_ops dect_scan_ops = {
	.report_rssi	= dect_scan_bearer_report_rssi,
	.rcv		= dect_scan_bearer_rcv,
};

static void dect_scan_channel_desc(struct dect_channel_desc *chd)
{
	memset(chd, 0, sizeof(*chd));
	chd->pkt   = DECT_PACKET_P32;
	chd->b_fmt = DECT_B_UNPROTECTED;
}

static void dect_chl_scan_channel_desc(struct dect_channel_desc *chd,
				       const struct dect_channel_list *chl)
{
	memset(chd, 0, sizeof(*chd));
	chd->pkt = chl->pkt;
	if (chl->pkt == DECT_PACKET_P00)
		chd->b_fmt = DECT_B_NONE;
	else
		chd->b_fmt = DECT_B_UNPROTECTED;
}

static void dect_scan_bearer_enable(struct dect_transceiver *trx,
				    const struct dect_channel_desc *chd)
{
	trx->slots[chd->slot].bearer = &trx->irc->scan_bearer;
	dect_set_channel_mode(trx, chd, DECT_SLOT_SCANNING);
}

static void dect_scan_bearer_disable(struct dect_transceiver *trx,
				     const struct dect_channel_desc *chd)
{
	dect_set_channel_mode(trx, chd, DECT_SLOT_IDLE);
	trx->slots[chd->slot].bearer = NULL;
}

static void dect_irc_tx_frame_timer(struct dect_cell *cell, void *data)
{
	struct dect_irc *irc = data;
	struct dect_transceiver *trx = irc->trx;
	struct dect_channel_desc chd;
	u8 end;

	irc->tx_scn = dect_next_carrier(cell->si.ssi.rfcars, irc->tx_scn);

	/* Begin a pending channel list update:
	 *
	 * The IRC of the first transceiver that reaches a new frame queues the
	 * channel list. All IRCs then switch the idle normal transmit slots
	 * to scanning mode and switch all scanning slots to the lists physical
	 * channel type. The actual update will begin once the receive side
	 * reaches the same frame.
	 */
	if (cell->chl == NULL && cell->chl_next == NULL)
		cell->chl_next = dect_chl_get_pending(cell);

	if (cell->chl_next != NULL) {
		dect_chl_scan_channel_desc(&chd, cell->chl_next);
		dect_foreach_receive_slot(chd.slot, end, cell) {
			if (trx->slots[chd.slot].state != DECT_SLOT_SCANNING)
				continue;
			dect_scan_bearer_enable(trx, &chd);
		}
		dect_foreach_transmit_slot(chd.slot, end, cell) {
			if (trx->slots[chd.slot].state != DECT_SLOT_IDLE)
				continue;
			if (!dect_slot_available(trx, chd.slot))
				continue;
			dect_scan_bearer_enable(trx, &chd);
		}
	} else if (cell->chl == NULL) {
		dect_scan_channel_desc(&chd);
		dect_foreach_receive_slot(chd.slot, end, cell) {
			if (trx->slots[chd.slot].state != DECT_SLOT_SCANNING)
				continue;
			dect_scan_bearer_enable(trx, &chd);
		}
		dect_foreach_transmit_slot(chd.slot, end, cell) {
			if (trx->slots[chd.slot].state != DECT_SLOT_SCANNING)
				continue;
			dect_scan_bearer_disable(trx, &chd);
		}
	}

	dect_timer_add(cell, &irc->tx_frame_timer, DECT_TIMER_TX, 1, 0);
}

static void dect_irc_rx_frame_timer(struct dect_cell *cell, void *data)
{
	struct dect_irc *irc = data;

	/* Update the list status at the end of a frame in case of an
	 * active update or activate an update before a new frame begins.
	 */
	if (cell->chl != NULL)
		dect_chl_update_carrier(cell, irc->rx_scn);
	else if (cell->chl_next != NULL) {
		cell->chl = cell->chl_next;
		cell->chl_next = NULL;
		chl_debug(cell, cell->chl, "begin update\n");
	}

	irc->rx_scn = dect_next_carrier(cell->si.ssi.rfcars, irc->rx_scn);
	dect_timer_add(cell, &irc->rx_frame_timer, DECT_TIMER_RX, 1, 23);
}

static void dect_irc_enable(struct dect_cell *cell, struct dect_irc *irc)
{
	struct dect_transceiver *trx = irc->trx;
	struct dect_channel_desc chd;
	u8 end, scn_off, scn;

	if (trx->index < 3) {
		scn_off = trx->index * DECT_IRC_SCN_OFF;
		scn = dect_carrier_sub(cell->si.ssi.rfcars,
				       cell->si.ssi.pscn, scn_off);
		irc->rx_scn = scn;
		irc->tx_scn = scn;

		/* Set all idle slots to scanning */
		dect_scan_channel_desc(&chd);
		dect_foreach_receive_slot(chd.slot, end, cell) {
			if (trx->slots[chd.slot].state != DECT_SLOT_IDLE)
				continue;
			if (!dect_transceiver_channel_available(trx, &chd))
				continue;
			dect_scan_bearer_enable(trx, &chd);
		}
	}

	/* Start frame timers */
	dect_timer_add(cell, &irc->tx_frame_timer, DECT_TIMER_TX, 1, 0);
	dect_timer_add(cell, &irc->rx_frame_timer, DECT_TIMER_RX, 0, 23);
}

static struct dect_irc *dect_irc_init(struct dect_cell *cell,
				      struct dect_transceiver *trx)
{
	struct dect_irc *irc;

	irc = kzalloc(sizeof(*irc), GFP_KERNEL);
	if (irc == NULL)
		return NULL;

	irc->cell = cell;
	dect_timer_setup(&irc->rx_frame_timer, dect_irc_rx_frame_timer, irc);
	dect_timer_setup(&irc->tx_frame_timer, dect_irc_tx_frame_timer, irc);
	irc->scan_bearer.ops   = &dect_scan_ops;
	irc->scan_bearer.irc   = irc;
	irc->scan_bearer.trx   = trx;
	irc->scan_bearer.mode  = DECT_BEARER_RX;
	irc->scan_bearer.state = DECT_BEARER_ENABLED;
	irc->trx = trx;
	trx->irc = irc;
	return irc;
}

/*
 * Transmission: A- and B-Field MUXes
 */

static struct sk_buff *dect_u_mux(struct dect_cell *cell,
				  struct dect_bearer *bearer)
{
	struct sk_buff *skb = NULL;
	struct dect_tbc *tbc;

	if (bearer->ops->state == DECT_TRAFFIC_BEARER) {
		tbc = bearer->tbc;
		skb = tbc->b_tx_skb;
		tbc->b_tx_skb = NULL;
	}

	if (skb == NULL) {
		skb = alloc_skb(DECT_B_FIELD_SIZE, GFP_ATOMIC);
		if (skb == NULL)
			return NULL;
		skb_put(skb, DECT_B_FIELD_SIZE);
		memset(skb->data, 0xff, DECT_B_FIELD_SIZE);
		DECT_B_CB(skb)->id = DECT_BI_UTYPE_0;
	}
	return skb;
}

static struct sk_buff *dect_eu_mux(struct dect_cell *cell,
				   struct dect_bearer *bearer)
{
	return dect_u_mux(cell, bearer);
}

static struct sk_buff *dect_b_map(struct dect_cell *cell,
				  struct dect_bearer *bearer)
{
	return dect_eu_mux(cell, bearer);
}

#define tmux_debug(cell, fmt, args...) \
	tx_debug(cell, "%s T-MUX: " fmt, \
		 cell->mode == DECT_MODE_FP ? "FT" : "PT", ## args)

/**
 * dect_pt_t_mux - DECT T-MUX for PT transmissions
 *
 * @cell:	DECT cell
 * @bearer:	MAC bearer
 *
 * The PT T-MUX sequence is used by PTs for all traffic bearers in connection
 * oriented services and is defined as:
 *
 * Even frames: 	M_T, C_T, N_T
 * Uneven frames:	N_T
 *
 * Exception: M_T tails containing "bearer request" or "bearer release"
 * messages may be placed in any frame.
 */
static struct sk_buff *dect_pt_t_mux(struct dect_cell *cell,
				     struct dect_bearer *bearer)
{
	struct dect_tbc *tbc = NULL;
	struct sk_buff *skb;

	switch (bearer->ops->state) {
	case DECT_DUMMY_BEARER:
	case DECT_CL_BEARER:
		WARN_ON(0);
		break;
	case DECT_TRAFFIC_BEARER:
		tbc = bearer->tbc;
		break;
	}

	if ((dect_framenum(cell, DECT_TIMER_TX) & 0x1) == 0) {
		skb = skb_dequeue(&bearer->m_tx_queue);
		if (skb != NULL) {
			tmux_debug(cell, "M-channel\n");
			return skb;
		}
		if (tbc != NULL && tbc->c_tx_skb != NULL) {
			skb = tbc->c_tx_skb;
			tbc->c_tx_skb = NULL;
			tbc->c_tx_ok = true;
			tmux_debug(cell, "C-channel\n");
			return skb;
		}
	} else {
		skb = skb_peek(&bearer->m_tx_queue);
		if (skb != NULL && skb->priority == DECT_MT_HIGH_PRIORITY) {
			tmux_debug(cell, "M-channel (high priority)\n");
			skb_unlink(skb, &bearer->m_tx_queue);
			return skb;
		}
	}

	tmux_debug(cell, "N-channel\n");
	return dect_bc_dequeue(cell, bearer, &tbc->bc, DECT_MC_N);
}

/**
 * dect_rfp_t_mux - DECT T-MUX for RFP transmissions
 *
 * @cell:	DECT cell
 * @bearer:	MAC bearer
 *
 * The RFP T-MUX sequence is used for all RFP transmissions and is defined as:
 *
 * Frame 8:		Q_T
 * Frame 14:		N_T
 * Other even frames: 	P_T, N_T
 * Uneven frames:	M_T, C_T, N_T
 *
 * Exception: M_T tails sent in response to "bearer request" messages or during
 * bearer release may be placed in any frame.
 */
static struct sk_buff *dect_rfp_t_mux(struct dect_cell *cell,
				      struct dect_bearer *bearer)
{
	u8 framenum = dect_framenum(cell, DECT_TIMER_TX);
	struct dect_tbc *tbc = NULL;
	struct dect_bc *bc = NULL;
	struct sk_buff *skb;

	switch (bearer->ops->state) {
	case DECT_DUMMY_BEARER:
		bc = &bearer->dbc->bc;
		break;
	case DECT_TRAFFIC_BEARER:
		tbc = bearer->tbc;
		bc = &bearer->tbc->bc;
		break;
	case DECT_CL_BEARER:
		break;
	}

	if ((framenum & 0x1) == 0) {
		skb = skb_peek(&bearer->m_tx_queue);
		if (skb != NULL && skb->priority == DECT_MT_HIGH_PRIORITY) {
			tmux_debug(cell, "M-channel (high priority)\n");
			skb_unlink(skb, &bearer->m_tx_queue);
			return skb;
		}

		if (framenum == 8) {
			tmux_debug(cell, "Q-channel\n");
			return dect_bc_dequeue(cell, bearer, bc, DECT_MC_Q);
		}
		if (framenum == 14) {
			tmux_debug(cell, "N-channel\n");
			return dect_bc_dequeue(cell, bearer, bc, DECT_MC_N);
		}

		skb = dect_bc_dequeue(cell, bearer, bc, DECT_MC_P);
		if (skb != NULL) {
			tmux_debug(cell, "P-channel\n");
			return skb;
		}
	} else {
		skb = skb_dequeue(&bearer->m_tx_queue);
		if (skb != NULL) {
			tmux_debug(cell, "M-channel\n");
			return skb;
		}
		if (tbc != NULL && tbc->c_tx_skb != NULL) {
			skb = tbc->c_tx_skb;
			tbc->c_tx_skb = NULL;
			tbc->c_tx_ok = true;
			tmux_debug(cell, "C-channel\n");
			return skb;
		}
	}

	tmux_debug(cell, "N-channel\n");
	return dect_bc_dequeue(cell, bearer, bc, DECT_MC_N);
}

/**
 * dect_a_map - DECT A-Field mapping
 *
 * @cell:	DECT cell
 * @bearer:	MAC bearer
 *
 * Combine the H-, T- and RA-Fields into the A-Field.
 */
static struct sk_buff *dect_a_map(struct dect_cell *cell,
				  struct dect_bearer *bearer)
{
	struct sk_buff *skb;

	switch (cell->mode) {
	case DECT_MODE_PP:
		skb = dect_pt_t_mux(cell, bearer);
		break;
	case DECT_MODE_FP:
		skb = dect_rfp_t_mux(cell, bearer);
		break;
	default:
		return NULL;
	}

	if (skb == NULL)
		return NULL;

	/* Append empty RA-Field */
	memset(skb_put(skb, DECT_RA_FIELD_SIZE), 0, DECT_RA_FIELD_SIZE);

	/* Prepend Header field */
	skb_push(skb, DECT_HDR_FIELD_SIZE);
	skb->data[DECT_HDR_FIELD_OFF] = DECT_A_CB(skb)->id;
	skb->data[DECT_HDR_FIELD_OFF] |= bearer->q;
	bearer->q = 0;
	return skb;
}

static struct sk_buff *dect_raw_tx_peek(struct dect_cell *cell)
{
	struct dect_timer_base *base = &cell->timer_base[DECT_TIMER_TX];
	struct dect_skb_trx_cb *cb;
	struct sk_buff *skb;

	skb = skb_peek(&cell->raw_tx_queue);
	if (skb == NULL)
		return NULL;
	cb = DECT_TRX_CB(skb);

	if ((!cb->mfn || cb->mfn == base->mfn) &&
	    (!cb->frame || cb->frame == base->framenum) &&
	    cb->slot == base->slot)
		return skb;

	return NULL;
}

static void dect_raw_tx_configure(struct dect_cell *cell,
				  struct dect_transceiver *trx,
				  struct dect_transceiver_slot *ts)
{
	if (dect_raw_tx_peek(cell)) {
		if (ts->state == DECT_SLOT_RX) {
			tx_debug(cell, "enable raw TX\n");
			dect_set_channel_mode(trx, &ts->chd, DECT_SLOT_TX);
			dect_set_carrier(trx, ts->chd.slot, ts->chd.carrier);
			ts->priv_flags |= DECT_SLOT_RAW_TX;
		}
	} else if (ts->priv_flags & DECT_SLOT_RAW_TX) {
		tx_debug(cell, "disable raw TX\n");
		dect_set_channel_mode(trx, &ts->chd, DECT_SLOT_RX);
		dect_set_carrier(trx, ts->chd.slot, ts->chd.carrier);
		ts->priv_flags &= ~DECT_SLOT_RAW_TX;
	}
}

static struct sk_buff *dect_raw_tx(struct dect_cell *cell)
{
	struct sk_buff *skb;

	skb = dect_raw_tx_peek(cell);
	if (skb == NULL)
		return NULL;

	tx_debug(cell, "raw transmit\n");
	skb_unlink(skb, &cell->raw_tx_queue);
	return skb;
}

/**
 * dect_d_map - DECT D-Field mapping
 *
 * @cell:	DECT cell
 * @bearer:	MAC bearer
 *
 * Combine the A- and B-Fields from their respective MAPs into one D-Field.
 */
static struct sk_buff *dect_d_map(struct dect_cell *cell,
				  struct dect_bearer *bearer)
{
	struct sk_buff *skb_a, *skb_b, *skb;

	skb = dect_raw_tx(cell);
	if (skb != NULL)
		return skb;

	skb_a = dect_a_map(cell, bearer);
	if (skb_a == NULL)
		goto err1;

	if (bearer->chd.pkt != DECT_PACKET_P00) {
		skb_b = dect_b_map(cell, bearer);
		if (skb_b == NULL)
			goto err2;
		skb_a->data[DECT_HDR_BA_OFF] |= DECT_B_CB(skb_b)->id;

		skb = skb_append_frag(skb_a, skb_b);
		if (skb_linearize(skb) < 0) {
			kfree_skb(skb);
			skb = NULL;
		}
	} else {
		skb_a->data[DECT_HDR_BA_OFF] |= DECT_BI_NONE;
		skb = skb_a;
	}

	return skb;

err2:
	kfree_skb(skb_a);
err1:
	return NULL;
}

static void dect_mac_xmit_frame(struct dect_transceiver *trx,
				struct dect_transceiver_slot *ts)
{
	struct dect_cell *cell = trx->cell;
	struct dect_bearer *bearer = ts->bearer;
	struct sk_buff *skb;

	skb = dect_d_map(cell, bearer);
	if (skb == NULL)
		return;

	tx_debug(cell, "%s: TX slot %u carrier %u PSCN %u Q1: %d Q2: %d\n",
		 trx->name, ts->chd.slot, ts->chd.carrier, cell->si.ssi.pscn,
		 skb->data[DECT_HDR_Q1_OFF] & DECT_HDR_Q1_FLAG,
		 skb->data[DECT_HDR_Q2_OFF] & DECT_HDR_Q2_FLAG);

	switch (cell->mode) {
	case DECT_MODE_FP:
		skb->mac_len = sizeof(dect_fp_preamble);
		memcpy(skb_mac_header(skb), dect_fp_preamble, skb->mac_len);
		break;
	case DECT_MODE_PP:
		skb->mac_len = sizeof(dect_pp_preamble);
		memcpy(skb_mac_header(skb), dect_pp_preamble, skb->mac_len);
		break;
	case DECT_MODE_MONITOR:
		BUG();
	}

	DECT_TRX_CB(skb)->trx   = trx;
	DECT_TRX_CB(skb)->slot  = ts->chd.slot;
	DECT_TRX_CB(skb)->frame = dect_framenum(cell, DECT_TIMER_TX);
	DECT_TRX_CB(skb)->mfn	= dect_mfn(cell, DECT_TIMER_TX);
	dect_raw_rcv(skb);

	dect_transceiver_tx(trx, skb);
}

void dect_mac_rcv(struct dect_transceiver *trx,
		  struct dect_transceiver_slot *ts,
		  struct sk_buff *skb)
{
	struct dect_cell *cell = trx->cell;

	rx_debug(cell, "slot %u: ", DECT_TRX_CB(skb)->slot);
	DECT_TRX_CB(skb)->frame = dect_framenum(cell, DECT_TIMER_RX);
	DECT_TRX_CB(skb)->mfn	= dect_mfn(cell, DECT_TIMER_RX);
	dect_raw_rcv(skb);

	/* TX bearers can temporarily switch to RX mode for noise measurement */
	if (ts->bearer != NULL &&
	    ts->bearer->mode == DECT_BEARER_RX)
		ts->bearer->ops->rcv(cell, ts->bearer, skb);
	else {
		if (ts->bearer == NULL && net_ratelimit())
			pr_debug("packet without bearer slot %u\n", ts->chd.slot);
		kfree_skb(skb);
	}
}

void dect_mac_report_rssi(struct dect_transceiver *trx,
			  struct dect_transceiver_slot *ts,
			  u8 rssi)
{
	struct dect_cell *cell = trx->cell;

	if (ts->bearer == NULL) {
		pr_debug("%s: rssi slot %u state %u no bearer\n",
			 trx->name, ts->chd.slot, ts->state);
		return;
	}
	if (ts->bearer->state != DECT_BEARER_ENABLED)
		dect_tx_bearer_report_rssi(cell, ts->bearer, rssi);
	else if (ts->bearer->ops->report_rssi != NULL)
		ts->bearer->ops->report_rssi(cell, ts->bearer, ts->chd.slot, rssi);
}

void dect_mac_rx_tick(struct dect_transceiver_group *grp, u8 slot)
{
	struct dect_cell *cell = container_of(grp, struct dect_cell, trg);

	dect_run_timers(cell, DECT_TIMER_RX);
	dect_timer_base_update(cell, DECT_TIMER_RX, slot);
}

void dect_mac_tx_tick(struct dect_transceiver_group *grp, u8 slot)
{
	struct dect_cell *cell = container_of(grp, struct dect_cell, trg);
	struct dect_channel_desc chd;
	struct dect_transceiver *trx;
	struct dect_transceiver_slot *ts;

	/* TX timers run at the beginning of a slot, update the time first */
	dect_timer_base_update(cell, DECT_TIMER_TX, slot);
	dect_run_timers(cell, DECT_TIMER_TX);

	// FIXME: move somewhere reasonable
	if (list_empty(&cell->chanlists) && list_empty(&cell->chl_pending)) {
		dect_chl_schedule_update(cell, DECT_PACKET_P00);
		dect_chl_schedule_update(cell, DECT_PACKET_P32);
	}

	switch ((int)cell->mode) {
	case DECT_MODE_FP:
		if (!list_empty(&cell->dbcs))
			break;
		dect_dbc_init(cell, &chd);
		break;
	case DECT_MODE_PP:
		break;
	}

	dect_foreach_transceiver(trx, grp) {
		if (trx->state != DECT_TRANSCEIVER_LOCKED)
			continue;
		ts = &trx->slots[slot];

		dect_raw_tx_configure(cell, trx, ts);

		switch (ts->state) {
		case DECT_SLOT_SCANNING:
			dect_set_carrier(trx, slot, trx->irc->tx_scn);
			break;
		case DECT_SLOT_TX:
			dect_mac_xmit_frame(trx, ts);
			break;
		}
	}

	if (slot == DECT_FRAME_SIZE - 1)
		cell->si.ssi.pscn = dect_next_carrier(cell->si.ssi.rfcars,
						      cell->si.ssi.pscn);
}

static void dect_lock_fp(struct dect_cell *cell, struct dect_transceiver *trx,
			 enum dect_scan_status status)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_irc *irc = trx->irc;
	struct dect_si *si = &irc->si;
	struct dect_channel_desc chd;

	switch (status) {
	case DECT_SCAN_FAIL:
	case DECT_SCAN_TIMEOUT:
		return dect_restart_scan(cell, trx);
	case DECT_SCAN_COMPLETE:
		break;
	}

	dect_set_channel_mode(trx, &trx->slots[DECT_SCAN_SLOT].chd, DECT_SLOT_IDLE);

	chd.slot    = si->ssi.sn + (si->ssi.nr ? DECT_HALF_FRAME_SIZE : 0);
	chd.carrier = si->ssi.cn;
	chd.pkt     = DECT_PACKET_P00;
	chd.b_fmt   = DECT_B_NONE;

	if (!dect_transceiver_channel_available(trx, &chd))
		return dect_restart_scan(cell, trx);

	if (cell->mode != DECT_MODE_FP) {
		memcpy(&cell->idi, &irc->idi, sizeof(cell->idi));
		cell->fmid = dect_build_fmid(&cell->idi);
		memcpy(&cell->si, si, sizeof(cell->si));

		dect_timer_synchronize_mfn(cell, si->mfn.num);

		/* Lock framing based on slot position and create DBC */
		dect_transceiver_lock(trx, chd.slot);
		dect_dbc_init(cell, &chd);

		clh->ops->mac_info_indicate(clh, &cell->idi, &cell->si);
	} else {
		dect_transceiver_lock(trx, chd.slot);

		/* Lock to the primary dummy bearer to keep the radio synchronized */
		/* FIXME: do this cleanly */
		dect_set_channel_mode(trx, &chd, DECT_SLOT_RX);
		dect_set_flags(trx, chd.slot, DECT_SLOT_SYNC);
		dect_set_carrier(trx, chd.slot, chd.carrier);
	}

	/* Enable IRC */
	dect_irc_enable(cell, irc);
}

static void dect_attempt_lock(struct dect_cell *cell,
			      struct dect_transceiver *trx)
{
	dect_initiate_scan(trx, &cell->idi.pari, NULL, dect_lock_fp);
}

static void dect_fp_init_primary(struct dect_cell *cell,
				 struct dect_transceiver *trx)
{
	dect_transceiver_enable(trx);
	dect_irc_enable(cell, trx->irc);
}

static void dect_cell_enable_transceiver(struct dect_cell *cell,
					 struct dect_transceiver *trx)
{
	/* The primary transceiver of a FP is a timing master. All other
	 * transceivers need to synchronize.
	 */
	if (trx->index == 0 && cell->mode == DECT_MODE_FP &&
	    !(cell->flags & DECT_CELL_SLAVE)) {
		trx->mode = DECT_TRANSCEIVER_MASTER;
		dect_fp_init_primary(cell, trx);
	} else {
		trx->mode = DECT_TRANSCEIVER_SLAVE;
		dect_attempt_lock(cell, trx);
	}
}

static int dect_cell_preload(const struct dect_cell_handle *ch,
			     const struct dect_ari *pari, u8 rpn,
			     const struct dect_si *si)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);

	/* Initialise identity */
	spin_lock_bh(&cell->lock);
	cell->idi.e = false;
	memcpy(&cell->idi.pari, pari, sizeof(cell->idi.pari));
	cell->idi.rpn = rpn;
	cell->fmid = dect_build_fmid(&cell->idi);

	memcpy(&cell->si.ssi, &si->ssi, sizeof(cell->si.ssi));
	memcpy(&cell->si.erfc, &si->erfc, sizeof(cell->si.erfc));
	memcpy(&cell->si.fpc, &si->fpc, sizeof(cell->si.fpc));
	memcpy(&cell->si.efpc, &si->efpc, sizeof(cell->si.efpc));
	memcpy(&cell->si.efpc2, &si->efpc2, sizeof(cell->si.efpc2));
	memcpy(cell->si.sari, si->sari, sizeof(cell->si.sari));
	cell->si.num_saris = si->num_saris;
	spin_unlock_bh(&cell->lock);
	return 0;
}

static int dect_cell_enable(const struct dect_cell_handle *ch)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_transceiver *trx;

	cell->state |= DECT_CELL_ENABLED;
	dect_foreach_transceiver(trx, &cell->trg) {
		dect_cell_enable_transceiver(cell, trx);
		if (cell->mode == DECT_MODE_PP)
			break;
	}
	return 0;
}

static void dect_scan_report(struct dect_cell *cell,
			     struct dect_transceiver *trx,
			     enum dect_scan_status status)
{
	const struct dect_cluster_handle *clh = cell->handle.clh;
	const struct dect_irc *irc = trx->irc;
	struct dect_scan_result res;

	switch (status) {
	case DECT_SCAN_FAIL:
		break;
	case DECT_SCAN_TIMEOUT:
		pr_debug("timeout\n");
	case DECT_SCAN_COMPLETE:
		res.lreq = irc->lreq;
		res.rssi = irc->rssi;
		res.idi  = irc->idi;
		res.si   = irc->si;
		clh->ops->scan_report(clh, &res);
		break;
	}

	return dect_restart_scan(cell, trx);
}

static int dect_cell_scan(const struct dect_cell_handle *ch,
			  const struct dect_llme_req *lreq,
			  const struct dect_ari *pari,
			  const struct dect_ari *pari_mask)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);
	struct dect_transceiver *trx = cell->trg.trx[0];

	if (trx == NULL)
		return -ENODEV;
	// FIXME
	memcpy(&trx->irc->lreq, lreq, sizeof(trx->irc->lreq));
	dect_initiate_scan(trx, pari, pari_mask, dect_scan_report);
	return 0;
}

static int dect_cell_set_mode(const struct dect_cell_handle *ch,
			      enum dect_cluster_modes mode)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);

	cell->mode = mode;
	return 0;
}

static void dect_cell_page_request(const struct dect_cell_handle *ch,
				   struct sk_buff *skb)
{
	struct dect_cell *cell = container_of(ch, struct dect_cell, handle);

	DECT_BMC_CB(skb)->stamp = dect_mfn(cell, DECT_TIMER_TX);
	dect_queue_page(cell, skb);
}

static const struct dect_csf_ops dect_csf_ops = {
	.set_mode		= dect_cell_set_mode,
	.scan			= dect_cell_scan,
	.enable			= dect_cell_enable,
	.preload		= dect_cell_preload,
	.page_request		= dect_cell_page_request,
	.tbc_initiate		= dect_tbc_initiate,
	.tbc_confirm		= dect_tbc_confirm,
	.tbc_release		= dect_tbc_release,
	.tbc_enc_key_request	= dect_tbc_enc_key_request,
	.tbc_enc_eks_request	= dect_tbc_enc_eks_request,
	.tbc_data_request	= dect_tbc_data_request,
};

int dect_cell_bind(struct dect_cell *cell, u8 index)
{
	struct dect_cluster_handle *clh;
	struct dect_cluster *cl;

	if (cell->flags & DECT_CELL_CCP) {
		clh = dect_ccp_cell_init(cell, index);
		if (clh == NULL)
			return -ENOMEM;
	} else {
		cl = dect_cluster_get_by_index(index);
		if (cl == NULL)
			return -ENOENT;
		clh = &cl->handle;
	}

	return clh->ops->bind(clh, &cell->handle);
}

void dect_cell_shutdown(struct dect_cell *cell)
{
	struct dect_cluster_handle *clh = cell->handle.clh;
	struct dect_transceiver *trx;

	if (clh != NULL)
		clh->ops->unbind(clh, &cell->handle);

	dect_foreach_transceiver(trx, &cell->trg)
		dect_cell_detach_transceiver(cell, trx);
	dect_cell_bmc_disable(cell);
	skb_queue_purge(&cell->raw_tx_queue);
}

/**
 * dect_mac_init_cell - Initialize a DECT cell
 */
void dect_cell_init(struct dect_cell *cell)
{
	spin_lock_init(&cell->lock);
	INIT_LIST_HEAD(&cell->bcs);
	INIT_LIST_HEAD(&cell->dbcs);
	INIT_LIST_HEAD(&cell->tbcs);
	INIT_LIST_HEAD(&cell->chl_pending);
	INIT_LIST_HEAD(&cell->chanlists);
	INIT_LIST_HEAD(&cell->timer_base[DECT_TIMER_RX].timers);
	INIT_LIST_HEAD(&cell->timer_base[DECT_TIMER_TX].timers);
	skb_queue_head_init(&cell->raw_tx_queue);
	dect_cell_bmc_init(cell);
	cell->blind_full_slots = DECT_SLOT_MASK,
	dect_transceiver_group_init(&cell->trg);
	cell->handle.ops = &dect_csf_ops;
}

/**
 * dect_cell_attach_transceiver - attach a transceiver to a DECT cell
 *
 * Attach the transceiver to the cell's transceiver group and initialize
 * an idle receiver control instance.
 */
int dect_cell_attach_transceiver(struct dect_cell *cell,
				 struct dect_transceiver *trx)
{
	int err;

	if (trx->cell != NULL)
		return -EBUSY;

	err = dect_transceiver_group_add(&cell->trg, trx);
	if (err < 0)
		goto err1;

	err = -ENOMEM;
	if (!dect_irc_init(cell, trx))
		goto err2;

	trx->cell = cell;
	if (cell->state & DECT_CELL_ENABLED)
		dect_cell_enable_transceiver(cell, trx);

	return 0;

err2:
	dect_transceiver_group_remove(&cell->trg, trx);
err1:
	return err;
}

/**
 * dect_cell_detach_transceiver - detach a transceiver from a DECT cell
 *
 * Detach the transceiver from the cell's transceiver group and release
 * the associated resources.
 */
void dect_cell_detach_transceiver(struct dect_cell *cell,
				  struct dect_transceiver *trx)
{
	dect_transceiver_disable(trx);
	dect_transceiver_group_remove(&cell->trg, trx);
	kfree(trx->irc);
	trx->cell = NULL;
}
