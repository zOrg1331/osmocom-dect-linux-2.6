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

static void dect_scan_report(const struct dect_cluster_handle *clh,
			     const struct dect_scan_result *res)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);

	dect_llme_scan_result_notify(cl, res);
}

static void dect_mac_info_indicate(const struct dect_cluster_handle *clh,
				   const struct dect_idi *idi,
				   const struct dect_si *si)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);

	pr_debug("cl %p: mac info indicate\n", cl);
	memcpy(&cl->si, si, sizeof(cl->si));
}

/*
 * Broadcast message control
 */

/**
 * dect_bmc_mac_page_request - queue one segment of B_S channel data
 *
 * @cl:		DECT cluster
 * @skb:	SDU
 * @expedited:	fast/normal page indication
 */
void dect_bmc_mac_page_request(struct dect_cluster *cl, struct sk_buff *skb,
			       bool expedited)
{
	const struct dect_cell_handle *ch, *last = NULL;
	struct sk_buff *clone;

	BUG_ON(cl->mode != DECT_MODE_FP);

	DECT_BMC_CB(skb)->fast = expedited;
	list_for_each_entry(ch, &cl->cells, list) {
		if (last != NULL) {
			clone = skb_clone(skb, GFP_ATOMIC);
			if (clone != NULL)
				ch->ops->page_request(ch, clone);
		}
		last = ch;
	}
	if (last != NULL)
		last->ops->page_request(last, skb);
}

static void dect_bmc_page_indicate(const struct dect_cluster_handle *clh,
				   struct sk_buff *skb)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);

	return dect_dlc_mac_page_indicate(cl, skb);
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

static void dect_mbc_release(struct dect_mbc *mbc)
{
	mbc_debug(mbc, "release\n");
	del_timer(&mbc->timer);
	list_del(&mbc->list);
	kfree_skb(mbc->cs_tx_skb);
	kfree(mbc);
}

static void dect_mbc_timeout(unsigned long data)
{
	struct dect_mbc *mbc = (struct dect_mbc *)data;
	enum dect_release_reasons reason;

	mbc_debug(mbc, "timeout\n");
	reason = DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED;
	mbc->ch->ops->tbc_release(mbc->ch, &mbc->id, reason);
	dect_dlc_mac_dis_indicate(mbc->cl, mbc->id.mcei, reason);
	dect_mbc_release(mbc);
}

static struct dect_mbc *dect_mbc_init(struct dect_cluster *cl,
				      const struct dect_mbc_id *id)
{
	struct dect_mbc *mbc;

	mbc = kzalloc(sizeof(*mbc), GFP_ATOMIC);
	if (mbc == NULL)
		return NULL;
	mbc->cl = cl;
	memcpy(&mbc->id, id, sizeof(mbc->id));
	mbc->state = DECT_MBC_NONE;
	mbc->cs_tx_seq = 1;

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

	err = ch->ops->tbc_initiate(ch, &mbc->id, &chd);
	if (err < 0)
		return err;

	mbc->setup_cnt++;
	return 0;
}

/**
 * dect_mbc_con_request - request a new MAC connection
 *
 * @cl:		DECT cluster
 * @id:		MBC identifier
 */
int dect_mbc_con_request(struct dect_cluster *cl, const struct dect_mbc_id *id)
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

void dect_mbc_dis_request(struct dect_cluster *cl, u32 mcei)
{
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "disconnect\n");
	mbc->ch->ops->tbc_release(mbc->ch, &mbc->id, DECT_REASON_CONNECTION_RELEASE);
	dect_mbc_release(mbc);
}

static int dect_mbc_conn_indicate(const struct dect_cluster_handle *clh,
				  const struct dect_cell_handle *ch,
				  const struct dect_mbc_id *id)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);
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

	err = ch->ops->tbc_confirm(ch, &mid);
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
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);
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
				dect_dlc_mac_dis_indicate(cl, id->mcei,
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
			if (del_timer(&mbc->timer))
				return dect_dlc_mac_conn_indicate(cl, id);
			return 0;
		case DECT_MBC_INITIATED:
			if (del_timer(&mbc->timer))
				return dect_dlc_mac_conn_confirm(cl, id->mcei,
								 id->service);
			return 0;
		default:
			return WARN_ON(-1);
		}
	case DECT_TBC_ACK_RECEIVED:
		if (mbc->cs_tx_skb != NULL) {
			kfree_skb(mbc->cs_tx_skb);
			mbc->cs_tx_skb = NULL;
		}
		return 0;
	case DECT_TBC_CIPHER_ENABLED:
		dect_dlc_mac_enc_eks_indicate(cl, id->mcei, DECT_CIPHER_ENABLED);
		return 0;
	case DECT_TBC_CIPHER_DISABLED:
		dect_dlc_mac_enc_eks_indicate(cl, id->mcei, DECT_CIPHER_DISABLED);
		return 0;
	default:
		return WARN_ON(-1);
	}
}

static void dect_mbc_dis_indicate(const struct dect_cluster_handle *clh,
				  const struct dect_mbc_id *id,
				  enum dect_release_reasons reason)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, id->mcei);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "disconnect reason: %u\n", reason);
	dect_dlc_mac_dis_indicate(cl, id->mcei, reason);
	dect_mbc_release(mbc);
}

int dect_mbc_enc_key_request(const struct dect_cluster *cl, u32 mcei, u64 ck)
{
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "enc key request: %.16llx\n", (unsigned long long)ck);
	return mbc->ch->ops->tbc_enc_key_request(mbc->ch, &mbc->id, ck);
}

int dect_mbc_enc_eks_request(const struct dect_cluster *cl, u32 mcei,
			     enum dect_cipher_states status)
{
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, mcei);
	if (mbc == NULL)
		return -ENOENT;
	mbc_debug(mbc, "enc eks request: %d\n", status);
	return mbc->ch->ops->tbc_enc_eks_request(mbc->ch, &mbc->id, status);
}

static void dect_mbc_data_indicate(const struct dect_cluster_handle *clh,
				   const struct dect_mbc_id *id,
				   enum dect_data_channels chan,
				   struct sk_buff *skb)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);
	struct dect_mbc *mbc;

	mbc = dect_mbc_get_by_mcei(cl, id->mcei);
	if (mbc == NULL)
		goto err;

	switch (chan) {
	case DECT_MC_C_S:
		/* Drop duplicate segments */
		if (DECT_CS_CB(skb)->seq == mbc->cs_rx_seq)
			goto err;
		mbc->cs_rx_seq = !mbc->cs_rx_seq;
		break;
	default:
		break;
	}

	return dect_dlc_mac_co_data_indicate(cl, mbc->id.mcei, chan, skb);

err:
	kfree_skb(skb);
}

static void dect_mbc_dtr_indicate(const struct dect_cluster_handle *clh,
				  const struct dect_mbc_id *id,
				  enum dect_data_channels chan)
{
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);
	struct dect_mbc *mbc;
	struct sk_buff *skb;

	mbc = dect_mbc_get_by_mcei(cl, id->mcei);
	if (mbc == NULL)
		return;
	mbc_debug(mbc, "DTR-indicate\n");

	switch (chan) {
	case DECT_MC_C_S:
		if (mbc->cs_tx_skb == NULL) {
			/* Queue a new segment for transmission */
			skb = dect_dlc_mac_co_dtr_indicate(cl, mbc->id.mcei, chan);
			if (skb == NULL)
				return;
			DECT_CS_CB(skb)->seq = mbc->cs_tx_seq;
			mbc->cs_tx_seq = !mbc->cs_tx_seq;
			mbc->cs_tx_skb = skb;
		}

		skb = skb_clone(mbc->cs_tx_skb, GFP_ATOMIC);
		break;
	default:
		skb = dect_dlc_mac_co_dtr_indicate(cl, mbc->id.mcei, chan);
		break;
	}

	if (skb != NULL)
		mbc->ch->ops->tbc_data_request(mbc->ch, &mbc->id, chan, skb);
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
	struct dect_cluster *cl = container_of(clh, struct dect_cluster, handle);
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
	.scan_report		= dect_scan_report,
	.mac_info_indicate	= dect_mac_info_indicate,
	.mbc_conn_indicate	= dect_mbc_conn_indicate,
	.mbc_conn_notify	= dect_mbc_conn_notify,
	.mbc_dis_indicate	= dect_mbc_dis_indicate,
	.mbc_data_indicate	= dect_mbc_data_indicate,
	.mbc_dtr_indicate	= dect_mbc_dtr_indicate,
	.bmc_page_indicate	= dect_bmc_page_indicate,
};

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
	si->ssi.rfcars = 0x3ff;
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
		      DECT_HLC_ACCESS_RIGHT_REQUESTS |
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
		dect_dlc_mac_dis_indicate(cl, mbc->id.mcei, DECT_REASON_UNKNOWN);
		dect_mbc_release(mbc);
	}

	list_for_each_entry_safe(ch, ch_next, &cl->cells, list)
		dect_cluster_unbind_cell(&cl->handle, ch);

	dect_ccp_cluster_shutdown(cl);
}
