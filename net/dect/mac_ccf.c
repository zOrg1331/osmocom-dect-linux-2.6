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
	pr_debug("MBC (MCEI %u): " fmt, (mbc)->id.mcei, ## args);

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
	struct sk_buff *skb;

	mbc_debug(mbc, "Normal RX timer\n");

	if (mbc->cs_rx_skb != NULL) {
		skb = mbc->cs_rx_skb;
		mbc->cs_rx_skb = NULL;
		dect_mac_co_data_ind(cl, mbc->id.mcei, DECT_MC_C_S, skb);
	}

	if (mbc->cs_tx_ok && mbc->cs_rx_ok) {
		kfree_skb(mbc->cs_tx_skb);
		mbc->cs_tx_skb = NULL;
	}
	mbc->cs_rx_ok = false;

	if (mbc->b_rx_skb != NULL) {
		skb = mbc->b_rx_skb;
		mbc->b_rx_skb = NULL;
		dect_mac_co_data_ind(cl, mbc->id.mcei, DECT_MC_I_N, skb);
	}

	dect_timer_add(cl, &mbc->normal_rx_timer, DECT_TIMER_RX,
		       1, dect_normal_receive_base(cl->mode));
}

/*
 * MBC slot based receive timer:
 *
 * Deliver received I_N minimal delay B-field segments to the DLC.
 */
static void dect_mbc_slot_rx_timer(struct dect_cluster *cl, void *data)
{
	struct dect_mbc *mbc = data;
	struct sk_buff *skb;

	mbc_debug(mbc, "Slot RX timer\n");

	if (mbc->b_rx_skb != NULL) {
		skb = mbc->b_rx_skb;
		mbc->b_rx_skb = NULL;
		dect_mac_co_data_ind(cl, mbc->id.mcei, DECT_MC_I_N, skb);
	}

	dect_timer_add(cl, &mbc->slot_rx_timer, DECT_TIMER_RX, 1, mbc->slot);
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
	struct dect_mbc *mbc = data;
	const struct dect_cell_handle *ch = mbc->ch;
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

		if (mbc->cs_tx_skb != NULL &&
		    (skb = skb_clone(mbc->cs_tx_skb, GFP_ATOMIC)) != NULL) {
			ch->ops->tbc_data_req(ch, &mbc->id, DECT_MC_C_S, skb);
			mbc->cs_tx_ok = true;
		}
	}

	if (1 || mbc->id.service != DECT_SERVICE_IN_MIN_DELAY) {
		skb = dect_mac_co_dtr_ind(cl, mbc->id.mcei, DECT_MC_I_N);
		if (skb != NULL)
			ch->ops->tbc_data_req(ch, &mbc->id, DECT_MC_I_N, skb);
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
	struct dect_mbc *mbc = data;
	const struct dect_cell_handle *ch = mbc->ch;
	struct sk_buff *skb;

	mbc_debug(mbc, "Slot TX timer\n");

	skb = dect_mac_co_dtr_ind(cl, mbc->id.mcei, DECT_MC_I_N);
	if (skb != NULL)
		ch->ops->tbc_data_req(ch, &mbc->id, DECT_MC_I_N, skb);

	dect_timer_add(cl, &mbc->slot_tx_timer, DECT_TIMER_TX, 1, mbc->slot);
}

static int dect_mbc_complete_setup(struct dect_cluster *cl, struct dect_mbc *mbc)
{
	if (!del_timer(&mbc->timer))
		return 0;

	dect_timer_add(cl, &mbc->normal_rx_timer, DECT_TIMER_RX,
		       0, dect_normal_receive_base(cl->mode));
	dect_timer_add(cl, &mbc->normal_tx_timer, DECT_TIMER_TX,
		       0, dect_normal_transmit_base(cl->mode));

	if (0 && mbc->id.service == DECT_SERVICE_IN_MIN_DELAY) {
		dect_timer_add(cl, &mbc->normal_rx_timer, DECT_TIMER_RX,
			       0, mbc->slot);
		dect_timer_add(cl, &mbc->normal_tx_timer, DECT_TIMER_TX,
			       0, mbc->slot);
	}
	return 1;
}

static void dect_mbc_release(struct dect_mbc *mbc)
{
	mbc_debug(mbc, "release\n");
	del_timer(&mbc->timer);
	list_del(&mbc->list);

	dect_timer_del(&mbc->normal_rx_timer);
	dect_timer_del(&mbc->normal_tx_timer);
	dect_timer_del(&mbc->slot_rx_timer);
	dect_timer_del(&mbc->slot_tx_timer);

	kfree_skb(mbc->cs_rx_skb);
	kfree_skb(mbc->cs_tx_skb);
	kfree(mbc);
}

static void dect_mbc_timeout(unsigned long data)
{
	struct dect_mbc *mbc = (struct dect_mbc *)data;
	enum dect_release_reasons reason;

	mbc_debug(mbc, "timeout\n");
	reason = DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED;
	mbc->ch->ops->tbc_dis_req(mbc->ch, &mbc->id, reason);
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
	mbc->cl    = cl;
	mbc->id    = *id;
	mbc->state = DECT_MBC_NONE;

	dect_timer_setup(&mbc->normal_rx_timer, dect_mbc_normal_rx_timer, mbc);
	dect_timer_setup(&mbc->normal_tx_timer, dect_mbc_normal_tx_timer, mbc);
	dect_timer_setup(&mbc->slot_rx_timer, dect_mbc_slot_rx_timer, mbc);
	dect_timer_setup(&mbc->slot_tx_timer, dect_mbc_slot_tx_timer, mbc);

	mbc->cs_tx_seq = 1;
	mbc->cs_rx_seq = 1;

	setup_timer(&mbc->timer, dect_mbc_timeout, (unsigned long)mbc);
	list_add_tail(&mbc->list, &cl->mbcs);
	return mbc;
}

static int dect_mbc_setup_tbc(struct dect_mbc *mbc)
{
	const struct dect_cell_handle *ch = mbc->ch;
	struct dect_channel_desc chd;
	int err;

	memset(&chd, 0, sizeof(chd));
	chd.pkt   = DECT_PACKET_P32;
	chd.b_fmt = DECT_B_UNPROTECTED;

	err = ch->ops->tbc_establish_req(ch, &mbc->id, &chd);
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
	mbc->ch = ch;
	mbc_debug(mbc, "MAC_CON-req\n");

	err = dect_mbc_setup_tbc(mbc);
	if (err < 0)
		goto err2;

	mod_timer(&mbc->timer, jiffies + DECT_MBC_SETUP_TIMEOUT);
	return 0;
err2:
	dect_mbc_release(mbc);
err1:
	return err;
}

void dect_mac_dis_req(struct dect_cluster *cl, u32 mcei)
{
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "MAC_DIS-req\n");
	mbc->ch->ops->tbc_dis_req(mbc->ch, &mbc->id,
				  DECT_REASON_CONNECTION_RELEASE);
	dect_mbc_release(mbc);
}

/* TBC establishment indication from CSF */
static int dect_tbc_establish_ind(const struct dect_cluster_handle *clh,
				  const struct dect_cell_handle *ch,
				  const struct dect_mbc_id *id)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc_id mid;
	struct dect_mbc *mbc;
	int err;

	memcpy(&mid, id, sizeof(mid));
	mid.mcei = dect_mbc_alloc_mcei(cl);

	err = -ENOMEM;
	mbc = dect_mbc_init(cl, &mid);
	if (mbc == NULL)
		goto err1;
	mbc->ch = ch;
	mbc_debug(mbc, "TBC_ESTABLISH-ind\n");

	err = ch->ops->tbc_establish_res(ch, &mid);
	if (err < 0)
		goto err2;

	mod_timer(&mbc->timer, jiffies + DECT_MBC_SETUP_TIMEOUT);
	return 0;
err2:
	dect_mbc_release(mbc);
err1:
	return err;
}

static int dect_mbc_conn_notify(const struct dect_cluster_handle *clh,
				const struct dect_mbc_id *id,
				enum dect_tbc_event event)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, id->mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "notify event: %u\n", event);

	switch (event) {
	case DECT_TBC_SETUP_FAILED:
		switch (mbc->state) {
		case DECT_MBC_NONE:
			return 0;
		case DECT_MBC_INITIATED:
			if (mbc->setup_cnt > DECT_MBC_SETUP_MAX_ATTEMPTS ||
			    dect_mbc_setup_tbc(mbc) < 0) {
				dect_mac_dis_ind(cl, id->mcei,
					DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED);
				dect_mbc_release(mbc);
			}
			return 0;
		default:
			return WARN_ON(-1);
		}
	case DECT_TBC_SETUP_COMPLETE:
		switch (mbc->state) {
		case DECT_MBC_NONE:
			if (!dect_mbc_complete_setup(cl, mbc))
				return 0;
			return dect_mac_con_ind(cl, id);
		case DECT_MBC_INITIATED:
			if (!dect_mbc_complete_setup(cl, mbc))
				return 0;
			return dect_mac_con_cfm(cl, id->mcei, id->service);
		default:
			return WARN_ON(-1);
		}
	case DECT_TBC_ACK_RECEIVED:
		mbc->cs_rx_ok = true;
		return 0;
	case DECT_TBC_CIPHER_ENABLED:
		dect_mac_enc_eks_ind(cl, id->mcei, DECT_CIPHER_ENABLED);
		return 0;
	case DECT_TBC_CIPHER_DISABLED:
		dect_mac_enc_eks_ind(cl, id->mcei, DECT_CIPHER_DISABLED);
		return 0;
	default:
		return WARN_ON(-1);
	}
}

/* TBC release indication from CSF */
static void dect_tbc_dis_ind(const struct dect_cluster_handle *clh,
			     const struct dect_mbc_id *id,
			     enum dect_release_reasons reason)
{
	struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, id->mcei);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "TBC_DIS-ind: reason: %u\n", reason);
	dect_mac_dis_ind(cl, id->mcei, reason);
	dect_mbc_release(mbc);
}

/* Set Encryption key request from DLC */
int dect_mac_enc_key_req(const struct dect_cluster *cl, u32 mcei, u64 ck)
{
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "MAC_ENC_KEY-req: key: %016llx\n", (unsigned long long)ck);
	return mbc->ch->ops->tbc_enc_key_req(mbc->ch, &mbc->id, ck);
}

/* Change encryption status requst from DLC */
int dect_mac_enc_eks_req(const struct dect_cluster *cl, u32 mcei,
			 enum dect_cipher_states status)
{
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "MAC_ENC_EKS-req: status: %d\n", status);
	return mbc->ch->ops->tbc_enc_eks_req(mbc->ch, &mbc->id, status);
}

static void dect_tbc_data_ind(const struct dect_cluster_handle *clh,
			      const struct dect_mbc_id *id,
			      enum dect_data_channels chan,
			      struct sk_buff *skb)
{
	const struct dect_cluster *cl = dect_cluster(clh);
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, id->mcei);
	if (mbc == NULL)
		goto err;
	mbc_debug(mbc, "TBC_DATA-ind: chan: %u len: %u\n", chan, skb->len);

	switch (chan) {
	case DECT_MC_C_S:
		/* Drop duplicate segments */
		if (DECT_CS_CB(skb)->seq != mbc->cs_rx_seq)
			goto err;
		mbc->cs_rx_seq = !mbc->cs_rx_seq;
		mbc->cs_rx_skb = skb;
		return;
	case DECT_MC_I_N:
		mbc->b_rx_skb = skb;
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
	.mbc_conn_notify	= dect_mbc_conn_notify,
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

void dect_cluster_init(struct dect_cluster *cl)
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

	// FIXME:
	if (dect_ccp_cluster_init(cl) < 0)
		printk("CCP init failed\n");
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
