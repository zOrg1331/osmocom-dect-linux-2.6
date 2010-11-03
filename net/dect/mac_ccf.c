/*
 * DECT MAC Cluster Control Functions
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
#include <net/dect/mac_ccf.h>
#include <net/dect/mac_csf.h>
#include <net/dect/ccp.h>

static struct dect_cluster *dect_cluster(const struct dect_cluster_handle *clh)
{
	return container_of(clh, struct dect_cluster, handle);
}

static struct dect_cell_handle *
dect_cluster_get_cell_by_rpn(struct dect_cluster *cl, u8 rpn)
{
	struct dect_cell_handle *ch;

	list_for_each_entry(ch, &cl->cells, list) {
		if (ch->rpn == rpn)
			return ch;
	}
	return NULL;
}

/*
 * MAC CCF layer timers
 */

static u8 dect_slotnum(const struct dect_cluster *cl, enum dect_timer_bases b)
{
	return __dect_slotnum(&cl->timer_base[b]);
}

static u8 dect_framenum(const struct dect_cluster *cl, enum dect_timer_bases b)
{
	return __dect_framenum(&cl->timer_base[b]);
}

static u32 dect_mfn(const struct dect_cluster *cl, enum dect_timer_bases b)
{
	return __dect_mfn(&cl->timer_base[b]);
}

static void dect_run_timers(struct dect_cluster *cl, enum dect_timer_bases b)
{
	__dect_run_timers(cl->name, &cl->timer_base[b]);
}

static void dect_timer_base_update(struct dect_cluster *cl,
				   enum dect_timer_bases base,
				   u32 mfn, u8 framenum, u8 slot)
{
	cl->timer_base[base].mfn      = mfn;
	cl->timer_base[base].framenum = framenum;
	cl->timer_base[base].slot     = slot;
}

static void dect_timer_add(struct dect_cluster *cl, struct dect_timer *timer,
			   enum dect_timer_bases b, u32 frame, u8 slot)
{
	timer->cluster = cl;
	__dect_timer_add(cl->name, &cl->timer_base[b], timer, frame, slot);
}

static void dect_timer_setup(struct dect_timer *timer,
			     void (*func)(struct dect_cluster *, void *),
			     void *data)
{
	dect_timer_init(timer);
	timer->cb.cluster = func;
	timer->data       = data;
}

static void dect_ccf_time_ind(struct dect_cluster_handle *clh,
			      enum dect_timer_bases base,
			      u32 mfn, u8 framenum, u8 slot)
{
	struct dect_cluster *cl = dect_cluster(clh);

	if (base == DECT_TIMER_TX) {
		dect_timer_base_update(cl, base, mfn, framenum, slot);
		dect_run_timers(cl, base);
	} else {
		dect_run_timers(cl, base);
		dect_timer_base_update(cl, base, mfn, framenum, slot);
	}
}

static void dect_scan_report(const struct dect_cluster_handle *clh,
			     const struct dect_scan_result *res)
{
	struct dect_cluster *cl = dect_cluster(clh);

	dect_llme_scan_result_notify(cl, res);
}

static void dect_mac_info_ind(const struct dect_cluster_handle *clh,
			      const struct dect_idi *idi,
			      const struct dect_si *si)
{
	struct dect_cluster *cl = dect_cluster(clh);

	pr_debug("cl %p: MAC_INFO-ind: rpn: %u\n", cl, idi->rpn);
	cl->si	= *si;
	cl->rpn	= idi->rpn;

	dect_llme_mac_info_ind(cl, idi, &cl->si);
}

/*
 * Broadcast message control
 */

/**
 * dect_bmc_mac_page_req - queue one segment of B_S channel data
 *
 * @cl:		DECT cluster
 * @skb:	SDU
 */
void dect_bmc_mac_page_req(struct dect_cluster *cl, struct sk_buff *skb)
{
	const struct dect_cell_handle *ch, *prev = NULL;
	struct sk_buff *clone;

	BUG_ON(cl->mode != DECT_MODE_FP);

	list_for_each_entry(ch, &cl->cells, list) {
		if (prev != NULL) {
			clone = skb_clone(skb, GFP_ATOMIC);
			if (clone != NULL)
				prev->ops->page_req(prev, clone);
		}
		prev = ch;
	}
	if (prev != NULL)
		prev->ops->page_req(prev, skb);
}

static void dect_bmc_page_ind(const struct dect_cluster_handle *clh,
			      struct sk_buff *skb)
{
	struct dect_cluster *cl = dect_cluster(clh);

	return dect_mac_page_ind(cl, skb);
}

/*
 * Multi-Bearer Control
 */

#define mbc_debug(mbc, fmt, args...) \
	pr_debug("MBC (MCEI %u/%s): " fmt, \
		 (mbc)->id.mcei, dect_mbc_states[(mbc)->state], ## args);

static const char * const dect_mbc_states[] = {
	[DECT_MBC_NONE]		= "NONE",
	[DECT_MBC_INITIATED]	= "INITIATED",
	[DECT_MBC_ESTABLISHED]	= "ESTABLISHED",
	[DECT_MBC_RELEASED]	= "RELEASED",
};

static void dect_mbc_hold(struct dect_mbc *mbc)
{
	mbc->refcnt++;
}

static void dect_mbc_put(struct dect_mbc *mbc)
{
	if (--mbc->refcnt > 0)
		return;
	kfree(mbc);
}

static struct dect_tb *dect_mbc_tb_get_by_lbn(const struct dect_mbc *mbc,
					      const struct dect_tbc_id *id)
{
	struct dect_tb *tb;

	list_for_each_entry(tb, &mbc->tbs, list) {
		if (tb->id.lbn == id->lbn)
			return tb;
	}
	return NULL;
}

static struct dect_tb *dect_mbc_tb_get_by_tbei(const struct dect_mbc *mbc,
					       const struct dect_tbc_id *id)
{
	struct dect_tb *tb;

	list_for_each_entry(tb, &mbc->tbs, list) {
		if (tb->id.tbei == id->tbei)
			return tb;
	}
	return NULL;
}

static struct dect_mbc *dect_mbc_get_by_tbc_id(const struct dect_cluster *cl,
					       const struct dect_tbc_id *id)
{
	struct dect_mbc *mbc;

	list_for_each_entry(mbc, &cl->mbcs, list) {
		if (!memcmp(&mbc->id.ari, &id->ari, sizeof(id->ari)) &&
		    !memcmp(&mbc->id.pmid, &id->pmid, sizeof(id->pmid)) &&
		    mbc->id.ecn == id->ecn)
			return mbc;
	}
	return NULL;
}

static struct dect_mbc *dect_mbc_get_by_mcei(const struct dect_cluster *cl, u32 mcei)
{
	struct dect_mbc *mbc;

	list_for_each_entry(mbc, &cl->mbcs, list) {
		if (mbc->id.mcei == mcei)
			return mbc;
	}
	return NULL;
}

u32 dect_mbc_alloc_mcei(struct dect_cluster *cl)
{
	u32 mcei;

	while (1) {
		mcei = ++cl->mcei_rover;
		if (mcei == 0)
			continue;
		if (dect_mbc_get_by_mcei(cl, mcei))
			continue;
		return mcei;
	}
}

static bool dect_ct_tail_allowed(const struct dect_cluster *cl, u8 framenum)
{
	if (cl->mode == DECT_MODE_FP)
		return (framenum & 0x1) == 0x1;
	else
		return (framenum & 0x1) == 0x0;
}

/*
 * MBC normal receive half frame timer:
 *
 * Deliver received data segments to the DLC at half frame boundaries.
 * Data is delivered for the following channels:
 *
 * - C_S after an ARQ window
 * - I_N normal delay
 *
 * Additionally in half frames that end an ARQ window, acknowledgment
 * of C_S segment reception of the preceeding transmit half frame is
 * verified.
 */
static void dect_mbc_normal_rx_timer(struct dect_cluster *cl, void *data)
{
	struct dect_mbc *mbc = data;
	struct dect_tb *tb;
	struct sk_buff *skb;

	mbc_debug(mbc, "Normal RX timer\n");
	dect_mbc_hold(mbc);

	if (mbc->cs_rx_skb != NULL) {
		skb = mbc->cs_rx_skb;
		mbc->cs_rx_skb = NULL;
		dect_mac_co_data_ind(cl, mbc->id.mcei, DECT_MC_C_S, skb);

		/* C-channel reception might trigger release of the MBC in case
		 * it acknowledges the last outstanding LAPC I-frame. */
		if (mbc->state == DECT_MBC_RELEASED)
			goto out;
	}

	if (mbc->cs_tx_ok && mbc->cs_rx_ok) {
		kfree_skb(mbc->cs_tx_skb);
		mbc->cs_tx_skb = NULL;
	}
	mbc->cs_rx_ok = false;

	list_for_each_entry(tb, &mbc->tbs, list) {
		if (tb->b_rx_skb == NULL)
			continue;
		skb = tb->b_rx_skb;
		tb->b_rx_skb = NULL;
		dect_mac_co_data_ind(cl, mbc->id.mcei, DECT_MC_I_N, skb);
	}

	dect_timer_add(cl, &mbc->normal_rx_timer, DECT_TIMER_RX,
		       1, dect_normal_receive_base(cl->mode));
out:
	dect_mbc_put(mbc);
}

/*
 * MBC slot based receive timer:
 *
 * Deliver received I_N minimal delay B-field segments to the DLC.
 */
static void dect_mbc_slot_rx_timer(struct dect_cluster *cl, void *data)
{
	struct dect_tb *tb = data;
	struct dect_mbc *mbc = tb->mbc;
	struct sk_buff *skb;

	mbc_debug(mbc, "Slot RX timer: TBEI: %u LBN: %u slot: %u\n",
		  tb->id.tbei, tb->id.lbn, tb->rx_slot);

	if (tb->b_rx_skb != NULL) {
		skb = tb->b_rx_skb;
		tb->b_rx_skb = NULL;
		dect_mac_co_data_ind(cl, mbc->id.mcei, DECT_MC_I_N, skb);
	}

	dect_timer_add(cl, &tb->slot_rx_timer, DECT_TIMER_RX, 1, tb->rx_slot);
}

/*
 * MBC normal transmit half frame timer:
 *
 * Request data from the DLC for the next frame. Data is requested for the
 * following channels:
 *
 * - C_S before an ARQ window starts
 * - I_N normal delay
 */
static void dect_mbc_normal_tx_timer(struct dect_cluster *cl, void *data)
{
	const struct dect_cell_handle *ch;
	struct dect_mbc *mbc = data;
	struct dect_tb *tb;
	struct sk_buff *skb;

	mbc_debug(mbc, "Normal TX timer\n");

	if (dect_ct_tail_allowed(cl, dect_framenum(cl, DECT_TIMER_TX))) {
		if (mbc->cs_tx_skb == NULL) {
			skb = dect_mac_co_dtr_ind(cl, mbc->id.mcei, DECT_MC_C_S);
			if (skb != NULL) {
				DECT_CS_CB(skb)->seq = mbc->cs_tx_seq;
				mbc->cs_tx_seq = !mbc->cs_tx_seq;
				mbc->cs_tx_skb = skb;
			}
		}

		if (mbc->cs_tx_skb != NULL) {
			list_for_each_entry(tb, &mbc->tbs, list) {
				skb = skb_clone(mbc->cs_tx_skb, GFP_ATOMIC);
				if (skb == NULL)
					continue;
				ch = tb->ch;
				ch->ops->tbc_data_req(ch, &tb->id, DECT_MC_C_S, skb);
				mbc->cs_tx_ok = true;
			}
		}
	}

	if (mbc->service != DECT_SERVICE_IN_MIN_DELAY) {
		list_for_each_entry(tb, &mbc->tbs, list) {
			ch = tb->ch;
			skb = dect_mac_co_dtr_ind(cl, mbc->id.mcei, DECT_MC_I_N);
			if (skb != NULL)
				ch->ops->tbc_data_req(ch, &tb->id, DECT_MC_I_N, skb);
		}
	}

	dect_timer_add(cl, &mbc->normal_tx_timer, DECT_TIMER_TX,
		       1, dect_normal_transmit_base(cl->mode));
}

/*
 * MBC slot based transmit timer:
 *
 * Request data from the DLC for the I_N minimal delay channel.
 */
static void dect_mbc_slot_tx_timer(struct dect_cluster *cl, void *data)
{
	struct dect_tb *tb = data;
	struct dect_mbc *mbc = tb->mbc;
	const struct dect_cell_handle *ch = tb->ch;
	struct sk_buff *skb;

	mbc_debug(mbc, "Slot TX timer: TBEI: %u LBN: %u slot: %u\n",
		  tb->id.tbei, tb->id.lbn, tb->tx_slot);

	skb = dect_mac_co_dtr_ind(cl, mbc->id.mcei, DECT_MC_I_N);
	if (skb != NULL)
		ch->ops->tbc_data_req(ch, &tb->id, DECT_MC_I_N, skb);

	dect_timer_add(cl, &tb->slot_tx_timer, DECT_TIMER_TX, 1, tb->tx_slot);
}

static int dect_mbc_complete_setup(struct dect_cluster *cl, struct dect_mbc *mbc)
{
	if (!del_timer(&mbc->timer))
		return 0;

	dect_timer_add(cl, &mbc->normal_rx_timer, DECT_TIMER_RX,
		       0, dect_normal_receive_base(cl->mode));
	dect_timer_add(cl, &mbc->normal_tx_timer, DECT_TIMER_TX,
		       0, dect_normal_transmit_base(cl->mode));
	mbc->state = DECT_MBC_ESTABLISHED;

	return 1;
}

static void dect_mbc_tb_release(struct dect_tb *tb);

static void dect_mbc_tb_handover_timer(struct dect_cluster *cl, void *data)
{
	struct dect_tb *tb = data, *tb1, *i;
	struct dect_mbc *mbc = tb->mbc;

	mbc_debug(mbc, "Handover timer: TBEI: %u LBN: %u\n",
		  tb->id.tbei, tb->id.lbn);

	tb1 = NULL;
	list_for_each_entry(i, &mbc->tbs, list) {
		if (i->id.lbn == tb->id.lbn) {
			tb1 = i;
			break;
		}
	}
	if (tb1 == NULL)
		return;

	tb1->ch->ops->tbc_dis_req(tb1->ch, &tb1->id,
				  DECT_REASON_BEARER_HANDOVER_COMPLETED);
	list_del(&tb1->list);
	dect_mbc_tb_release(tb1);
}

static void dect_mbc_tb_complete_setup(struct dect_cluster *cl, struct dect_tb *tb)
{
	if (cl->mode == DECT_MODE_FP && tb->handover)
		dect_timer_add(cl, &tb->handover_timer, DECT_TIMER_RX,
			       DECT_MBC_TB_HANDOVER_TIMEOUT, tb->rx_slot);

	if (tb->mbc->service == DECT_SERVICE_IN_MIN_DELAY) {
		dect_timer_add(cl, &tb->slot_rx_timer, DECT_TIMER_RX,
			       0, tb->rx_slot);
		dect_timer_add(cl, &tb->slot_tx_timer, DECT_TIMER_TX,
			       0, tb->tx_slot);
	}
}

static void dect_mbc_tb_release(struct dect_tb *tb)
{
	dect_timer_del(&tb->handover_timer);
	dect_timer_del(&tb->slot_rx_timer);
	dect_timer_del(&tb->slot_tx_timer);
	kfree(tb);
}

static struct dect_tb *dect_mbc_tb_init(struct dect_mbc *mbc,
					const struct dect_cell_handle *ch, u8 lbn)
{
	struct dect_tb *tb;

	tb = kzalloc(sizeof(*tb), GFP_ATOMIC);
	if (tb == NULL)
		return NULL;

	tb->mbc      = mbc;
	tb->ch       = ch;
	tb->id.ari   = mbc->id.ari;
	tb->id.pmid  = mbc->id.pmid;
	tb->id.ecn   = 0;
	tb->id.lbn   = lbn;
	tb->id.tbei  = 0;
	tb->handover = false;
	tb->rx_slot  = 0;
	tb->tx_slot  = 0;

	dect_timer_setup(&tb->handover_timer, dect_mbc_tb_handover_timer, tb);
	dect_timer_setup(&tb->slot_rx_timer, dect_mbc_slot_rx_timer, tb);
	dect_timer_setup(&tb->slot_tx_timer, dect_mbc_slot_tx_timer, tb);

	return tb;
}

static void dect_mbc_release(struct dect_mbc *mbc)
{
	struct dect_tb *tb, *next;

	mbc_debug(mbc, "release\n");
	mbc->state = DECT_MBC_RELEASED;
	del_timer(&mbc->timer);
	list_del(&mbc->list);

	dect_timer_del(&mbc->normal_rx_timer);
	dect_timer_del(&mbc->normal_tx_timer);

	list_for_each_entry_safe(tb, next, &mbc->tbs, list)
		dect_mbc_tb_release(tb);

	kfree_skb(mbc->cs_rx_skb);
	kfree_skb(mbc->cs_tx_skb);
	dect_mbc_put(mbc);
}

static void dect_mbc_timeout(unsigned long data)
{
	struct dect_mbc *mbc = (struct dect_mbc *)data;
	struct dect_tb *tb;
	enum dect_release_reasons reason;

	mbc_debug(mbc, "timeout\n");
	reason = DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED;

	list_for_each_entry(tb, &mbc->tbs, list)
		tb->ch->ops->tbc_dis_req(tb->ch, &tb->id, reason);

	if (mbc->state != DECT_MBC_NONE)
		dect_mac_dis_ind(mbc->cl, mbc->id.mcei, reason);

	dect_mbc_release(mbc);
}

static struct dect_mbc *dect_mbc_init(struct dect_cluster *cl,
				      const struct dect_mbc_id *id)
{
	struct dect_mbc *mbc;

	mbc = kzalloc(sizeof(*mbc), GFP_ATOMIC);
	if (mbc == NULL)
		return NULL;
	mbc->refcnt   = 1;
	mbc->cl       = cl;
	mbc->id       = *id;
	mbc->state    = DECT_MBC_NONE;
	mbc->ho_stamp = jiffies - DECT_MBC_HANDOVER_TIMER;

	INIT_LIST_HEAD(&mbc->tbs);
	dect_timer_setup(&mbc->normal_rx_timer, dect_mbc_normal_rx_timer, mbc);
	dect_timer_setup(&mbc->normal_tx_timer, dect_mbc_normal_tx_timer, mbc);

	mbc->cs_tx_seq = 1;
	mbc->cs_rx_seq = 1;

	setup_timer(&mbc->timer, dect_mbc_timeout, (unsigned long)mbc);
	list_add_tail(&mbc->list, &cl->mbcs);
	return mbc;
}

static int dect_mbc_tb_setup(struct dect_mbc *mbc, struct dect_tb *tb)
{
	const struct dect_cell_handle *ch = tb->ch;
	struct dect_channel_desc chd;
	int err;

	memset(&chd, 0, sizeof(chd));
	chd.pkt   = DECT_PACKET_P32;
	chd.b_fmt = DECT_B_UNPROTECTED;

	err = ch->ops->tbc_establish_req(ch, &tb->id, &chd,
					 DECT_SERVICE_IN_MIN_DELAY,
					 tb->handover);
	if (err < 0)
		return err;

	mbc->setup_cnt++;
	return 0;
}

/**
 * dect_mac_con_req - request a new MAC connection
 *
 * @cl:		DECT cluster
 * @id:		MBC identifier
 */
int dect_mac_con_req(struct dect_cluster *cl, const struct dect_mbc_id *id)
{
	struct dect_cell_handle *ch;
	struct dect_mbc *mbc;
	struct dect_tb *tb;
	int err;

	err = -EHOSTUNREACH;
	ch = dect_cluster_get_cell_by_rpn(cl, 0);
	if (ch == NULL)
		goto err1;

	err = -ENOMEM;
	mbc = dect_mbc_init(cl, id);
	if (mbc == NULL)
		goto err1;
	mbc->state = DECT_MBC_INITIATED;
	mbc_debug(mbc, "MAC_CON-req\n");

	tb = dect_mbc_tb_init(mbc, ch, 0xf);
	if (tb == NULL)
		goto err2;

	err = dect_mbc_tb_setup(mbc, tb);
	if (err < 0)
		goto err3;

	list_add_tail(&tb->list, &mbc->tbs);
	mod_timer(&mbc->timer, jiffies + DECT_MBC_SETUP_TIMEOUT);
	return 0;

err3:
	dect_mbc_tb_release(tb);
err2:
	dect_mbc_release(mbc);
err1:
	return err;
}

void dect_mac_dis_req(struct dect_cluster *cl, u32 mcei)
{
	const struct dect_cell_handle *ch;
	struct dect_mbc *mbc;
	struct dect_tb *tb;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "MAC_DIS-req\n");

	list_for_each_entry(tb, &mbc->tbs, list) {
		ch = tb->ch;
		ch->ops->tbc_dis_req(ch, &tb->id, DECT_REASON_CONNECTION_RELEASE);
	}

	dect_mbc_release(mbc);
}

/* TBC establishment indication from CSF */
static int dect_tbc_establish_ind(const struct dect_cluster_handle *clh,
				  const struct dect_cell_handle *ch,
				  const struct dect_tbc_id *id,
				  enum dect_mac_service_types service,
				  bool handover)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc_id mid;
	struct dect_mbc *mbc;
	struct dect_tb *tb;
	unsigned int cnt;
	int err;

	mbc = dect_mbc_get_by_tbc_id(cl, id);
	if (mbc == NULL) {
		if (handover)
			return -ENOENT;

		mid.mcei = dect_mbc_alloc_mcei(cl);
		mid.type = 0;
		mid.ari  = id->ari;
		mid.pmid = id->pmid;
		mid.ecn  = id->ecn;

		err = -ENOMEM;
		mbc = dect_mbc_init(cl, &mid);
		if (mbc == NULL)
			goto err1;
		mbc->service = service;
	} else {
		if (!handover)
			return -EEXIST;

		cnt = 0;
		list_for_each_entry(tb, &mbc->tbs, list) {
			if (tb->id.lbn == id->lbn)
				cnt++;
		}
		if (cnt > 1)
			return -EEXIST;

		if (mbc->cipher_state == DECT_CIPHER_ENABLED) {
			err = ch->ops->tbc_enc_req(ch, id, mbc->ck);
			if (err < 0)
				return err;
		}
	}

	mbc_debug(mbc, "TBC_ESTABLISH-ind: TBEI: %u LBN: %u H/O: %u\n",
		  id->tbei, id->lbn, handover);

	err = -ENOMEM;
	tb = dect_mbc_tb_init(mbc, ch, id->lbn);
	if (tb == NULL)
		goto err2;
	tb->handover = handover;

	err = ch->ops->tbc_establish_res(ch, id);
	if (err < 0)
		goto err3;

	list_add_tail(&tb->list, &mbc->tbs);
	if (!handover)
		mod_timer(&mbc->timer, jiffies + DECT_MBC_SETUP_TIMEOUT);
	return 0;

err3:
	dect_mbc_tb_release(tb);
err2:
	dect_mbc_release(mbc);
err1:
	return err;
}

static int dect_tbc_establish_cfm(const struct dect_cluster_handle *clh,
				  const struct dect_tbc_id *id, bool success,
				  u8 rx_slot)
{
	struct dect_cluster *cl = dect_cluster(clh);
	const struct dect_cell_handle *ch;
	struct dect_mbc *mbc;
	struct dect_tb *tb, *i;

	mbc = dect_mbc_get_by_tbc_id(cl, id);
	if (mbc == NULL)
		return -ENOENT;

	mbc_debug(mbc, "TBC_ESTABLISH-cfm: TBEI: %u LBN: %u success: %d\n",
		  id->tbei, id->lbn, success);

	tb = NULL;
	list_for_each_entry(i, &mbc->tbs, list) {
		if (i->id.lbn  == id->lbn &&
		    i->id.tbei == 0) {
			tb = i;
			break;
		}
	}
	if (tb == NULL)
		return -ENOENT;

	if (success) {
		tb->id.tbei = id->tbei;
		tb->rx_slot = rx_slot;
		tb->tx_slot = dect_tdd_slot(rx_slot);

		switch (mbc->state) {
		case DECT_MBC_NONE:
			if (!dect_mbc_complete_setup(cl, mbc))
				return 0;
			dect_mbc_tb_complete_setup(cl, tb);

			return dect_mac_con_ind(cl, &mbc->id, mbc->service);
		case DECT_MBC_INITIATED:
			if (!dect_mbc_complete_setup(cl, mbc))
				return 0;
			dect_mbc_tb_complete_setup(cl, tb);

			return dect_mac_con_cfm(cl, mbc->id.mcei, mbc->service);
		case DECT_MBC_ESTABLISHED:
			ch = tb->ch;
			if (mbc->cipher_state == DECT_CIPHER_ENABLED &&
			    ch->ops->tbc_enc_req(ch, id, mbc->ck) < 0) {
				ch->ops->tbc_dis_req(ch, id, DECT_REASON_UNKNOWN);
				return -1;
			}
			dect_mbc_tb_complete_setup(cl, tb);
			return 0;
		default:
			return WARN_ON(-1);
		}
	} else {
		switch (mbc->state) {
		case DECT_MBC_NONE:
			dect_mbc_release(mbc);
			return 0;
		case DECT_MBC_INITIATED:
			if (mbc->setup_cnt > DECT_MBC_SETUP_MAX_ATTEMPTS ||
			    dect_mbc_tb_setup(mbc, tb) < 0) {
				dect_mac_dis_ind(cl, mbc->id.mcei,
					DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED);
				dect_mbc_release(mbc);
			}
			return 0;
		case DECT_MBC_ESTABLISHED:
			list_del(&tb->list);
			dect_mbc_tb_release(tb);
			return 0;
		default:
			return WARN_ON(-1);
		}
	}
}

static int dect_tbc_event_ind(const struct dect_cluster_handle *clh,
			      const struct dect_tbc_id *id,
			      enum dect_tbc_event event)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc *mbc;
	struct dect_tb *tb;

	mbc = dect_mbc_get_by_tbc_id(cl, id);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "TBC_EVENT-ind: TBEI: %u LBN: %u event: %u\n",
		  id->tbei, id->lbn, event);

	tb = dect_mbc_tb_get_by_tbei(mbc, id);
	if (tb == NULL)
		return -ENOENT;

	switch (event) {
	case DECT_TBC_ACK_RECEIVED:
		mbc->cs_rx_ok = true;
		return 0;
	case DECT_TBC_CIPHER_ENABLED:
		mbc->cipher_state = DECT_TBC_CIPHER_ENABLED;
		dect_mac_enc_eks_ind(cl, mbc->id.mcei, DECT_CIPHER_ENABLED);
		return 0;
	case DECT_TBC_CIPHER_DISABLED:
		mbc->cipher_state = DECT_TBC_CIPHER_DISABLED;
		dect_mac_enc_eks_ind(cl, mbc->id.mcei, DECT_CIPHER_DISABLED);
		return 0;
	default:
		return WARN_ON(-1);
	}
}

static int dect_tbc_handover_req(const struct dect_cluster_handle *clh,
				 const struct dect_tbc_id *id)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_cell_handle *ch;
	struct dect_mbc *mbc;
	struct dect_tb *tb;
	unsigned int cnt;
	int err;

	mbc = dect_mbc_get_by_tbc_id(cl, id);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "TBC_HANDOVER-req: TBEI: %u LBN: %u\n",
		  id->tbei, id->lbn);

	/* Handover already in progress or two bearers active?? */
	cnt = 0;
	list_for_each_entry(tb, &mbc->tbs, list) {
		if (tb->id.lbn  != id->lbn)
			continue;
		 if (tb->id.tbei == 0)
			return 0;
		 cnt++;
	}
	if (cnt > 1)
		return 0;

	/* Handover rate-limiting */
	if (mbc->ho_tokens == 0) {
		if (time_after_eq(jiffies, mbc->ho_stamp + DECT_MBC_HANDOVER_TIMER)) {
			mbc->ho_tokens = DECT_MBC_HANDOVER_LIMIT;
			mbc->ho_stamp  = jiffies;
		}
		mbc_debug(mbc, "handover: tokens: %u\n", mbc->ho_tokens);
		if (mbc->ho_tokens == 0)
			return 0;
	}

	ch = dect_cluster_get_cell_by_rpn(cl, 0);
	if (ch == NULL)
		return -EHOSTUNREACH;

	tb = dect_mbc_tb_init(mbc, ch, id->lbn);
	if (tb == NULL)
		return -ENOMEM;
	tb->handover = true;

	err = dect_mbc_tb_setup(mbc, tb);
	if (err < 0)
		goto err1;

	list_add_tail(&tb->list, &mbc->tbs);
	mbc->ho_tokens--;
	return 0;

err1:
	dect_mbc_tb_release(tb);
	return err;
}

/* TBC release indication from CSF */
static void dect_tbc_dis_ind(const struct dect_cluster_handle *clh,
			     const struct dect_tbc_id *id,
			     enum dect_release_reasons reason)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc *mbc;
	struct dect_tb *tb;

	mbc = dect_mbc_get_by_tbc_id(cl, id);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "TBC_DIS-ind: TBEI: %u LBN: %u reason: %u\n",
		  id->tbei, id->lbn, reason);

	tb = dect_mbc_tb_get_by_tbei(mbc, id);
	if (tb == NULL)
		return;

	list_del(&tb->list);
	dect_mbc_tb_release(tb);
	if (!list_empty(&mbc->tbs))
		return;

	dect_mac_dis_ind(cl, mbc->id.mcei, reason);
	dect_mbc_release(mbc);
}

/* Set Encryption key request from DLC */
int dect_mac_enc_key_req(const struct dect_cluster *cl, u32 mcei, u64 ck)
{
	struct dect_mbc *mbc;
	struct dect_tb *tb;
	int err;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "MAC_ENC_KEY-req: key: %016llx\n", (unsigned long long)ck);

	mbc->ck = ck;
	list_for_each_entry(tb, &mbc->tbs, list) {
		err = tb->ch->ops->tbc_enc_key_req(tb->ch, &tb->id, ck);
		if (err < 0)
			return err;
	}

	return 0;
}

/* Change encryption status requst from DLC */
int dect_mac_enc_eks_req(const struct dect_cluster *cl, u32 mcei,
			 enum dect_cipher_states status)
{
	struct dect_mbc *mbc;
	struct dect_tb *tb;
	int err;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "MAC_ENC_EKS-req: status: %d\n", status);

	if (mbc->cipher_state == status)
		return 0;

	list_for_each_entry(tb, &mbc->tbs, list) {
		err = tb->ch->ops->tbc_enc_eks_req(tb->ch, &tb->id, status);
		if (err < 0)
			return err;
	}
	return 0;
}

static void dect_tbc_data_ind(const struct dect_cluster_handle *clh,
			      const struct dect_tbc_id *id,
			      enum dect_data_channels chan,
			      struct sk_buff *skb)
{
	const struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc *mbc;
	struct dect_tb *tb;

	mbc = dect_mbc_get_by_tbc_id(cl, id);
	if (mbc == NULL)
		goto err;
	mbc_debug(mbc, "TBC_DATA-ind: TBEI: %u LBN: %u chan: %u len: %u\n",
		  id->tbei, id->lbn, chan, skb->len);

	switch (chan) {
	case DECT_MC_C_S:
		/* Drop duplicate segments */
		if (DECT_CS_CB(skb)->seq != mbc->cs_rx_seq)
			goto err;
		if (mbc->cs_rx_skb != NULL)
			goto err;
		mbc->cs_rx_seq = !mbc->cs_rx_seq;
		mbc->cs_rx_skb = skb;
		return;
	case DECT_MC_I_N:
		tb = dect_mbc_tb_get_by_tbei(mbc, id);
		if (tb == NULL)
			goto err;
		tb->b_rx_skb = skb;
		return;
	default:
		break;
	}
err:
	kfree_skb(skb);
}

static void dect_cluster_unbind_cell(struct dect_cluster_handle *clh,
				     struct dect_cell_handle *ch)
{
	list_del(&ch->list);
}

static int dect_cluster_enable_cell(struct dect_cluster *cl,
				    struct dect_cell_handle *ch)
{
	int err;

	err = ch->ops->preload(ch, &cl->pari, ch->rpn, &cl->si);
	if (err < 0)
		return err;

	err = ch->ops->enable(ch);
	if (err < 0)
		return err;
	return 0;
}

static int dect_cluster_bind_cell(struct dect_cluster_handle *clh,
				  struct dect_cell_handle *ch)
{
	struct dect_cluster *cl = dect_cluster(clh);
	u8 rpn, max;
	int err;

	/* Allocate RPN for the cell */
	max = 8;
	for (rpn = 0; rpn < max; rpn++) {
		if (!dect_cluster_get_cell_by_rpn(cl, rpn))
			break;
	}
	if (rpn == max)
		return -EMFILE;

	ch->clh = clh;
	ch->rpn = rpn;

	err = ch->ops->set_mode(ch, cl->mode);
	if (err < 0)
		return err;

	err = dect_cluster_enable_cell(cl, ch);
	if (err < 0)
		return err;

	list_add_tail(&ch->list, &cl->cells);
	return 0;
}

static const struct dect_ccf_ops dect_ccf_ops = {
	.bind			= dect_cluster_bind_cell,
	.unbind			= dect_cluster_unbind_cell,
	.time_ind		= dect_ccf_time_ind,
	.scan_report		= dect_scan_report,
	.mac_info_ind		= dect_mac_info_ind,
	.tbc_establish_ind	= dect_tbc_establish_ind,
	.tbc_establish_cfm	= dect_tbc_establish_cfm,
	.tbc_event_ind		= dect_tbc_event_ind,
	.tbc_handover_req	= dect_tbc_handover_req,
	.tbc_dis_ind		= dect_tbc_dis_ind,
	.tbc_data_ind		= dect_tbc_data_ind,
	.bmc_page_ind		= dect_bmc_page_ind,
};

int dect_cluster_preload(struct dect_cluster *cl, const struct dect_ari *pari,
			 const struct dect_si *si)
{
	const struct dect_cell_handle *ch;
	int err = 0;

	list_for_each_entry(ch, &cl->cells, list) {
		err = ch->ops->preload(ch, pari, ch->rpn, si);
		if (err < 0)
			return err;
	}

	cl->pari = *pari;
	cl->si   = *si;
	return 0;
}

int dect_cluster_scan(struct dect_cluster *cl,
		      const struct dect_llme_req *lreq,
		      const struct dect_ari *pari,
		      const struct dect_ari *pari_mask)
{
	struct dect_cell_handle *ch;

	ch = dect_cluster_get_cell_by_rpn(cl, 0);
	if (ch == NULL)
		return -ENOENT;
	return ch->ops->scan(ch, lreq, pari, pari_mask);
}

static void dect_fp_init_si(struct dect_cluster *cl)
{
	struct dect_si *si = &cl->si;

	/* Make phone not go into "call technician" mode :) */
	si->fpc.fpc = DECT_FPC_FULL_SLOT |
		      DECT_FPC_CO_SETUP_ON_DUMMY |
   		      DECT_FPC_CL_UPLINK |
   		      DECT_FPC_CL_DOWNLINK |
		      DECT_FPC_BASIC_A_FIELD_SETUP |
		      DECT_FPC_ADV_A_FIELD_SETUP |
		      DECT_FPC_CF_MESSAGES |
   		      DECT_FPC_IN_MIN_DELAY |
   		      DECT_FPC_IN_NORM_DELAY |
		      DECT_FPC_IP_ERROR_DETECTION |
		      DECT_FPC_IP_ERROR_CORRECTION;
	si->fpc.hlc = DECT_HLC_ADPCM_G721_VOICE |
		      DECT_HLC_GAP_PAP_BASIC_SPEECH |
		      DECT_HLC_CISS_SERVICE |
		      DECT_HLC_CLMS_SERVICE |
		      DECT_HLC_COMS_SERVICE |
		      DECT_HLC_LOCATION_REGISTRATION |
		      DECT_HLC_ACCESS_RIGHTS_REQUESTS |
		      DECT_HLC_STANDARD_AUTHENTICATION |
		      DECT_HLC_STANDARD_CIPHERING;
}

int dect_cluster_init(struct dect_cluster *cl)
{
	spin_lock_init(&cl->lock);
	INIT_LIST_HEAD(&cl->bmc.bcs);
	INIT_LIST_HEAD(&cl->mbcs);
	INIT_LIST_HEAD(&cl->cells);
	INIT_LIST_HEAD(&cl->mac_connections);
	dect_timer_base_init(cl->timer_base, DECT_TIMER_TX);
	dect_timer_base_init(cl->timer_base, DECT_TIMER_RX);

	if (cl->mode == DECT_MODE_FP)
		dect_fp_init_si(cl);

	cl->handle.ops = &dect_ccf_ops;
	cl->handle.index = cl->index;

	return dect_ccp_cluster_init(cl);
}

void dect_cluster_shutdown(struct dect_cluster *cl)
{
	struct dect_cell_handle *ch, *ch_next;
	struct dect_mbc *mbc, *mbc_next;

	list_for_each_entry_safe(mbc, mbc_next, &cl->mbcs, list) {
		dect_mac_dis_ind(cl, mbc->id.mcei, DECT_REASON_UNKNOWN);
		dect_mbc_release(mbc);
	}

	list_for_each_entry_safe(ch, ch_next, &cl->cells, list)
		dect_cluster_unbind_cell(&cl->handle, ch);

	dect_ccp_cluster_shutdown(cl);
}
