/*
 * DECT DLC C-plane
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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <net/dect/dect.h>

void dect_dlc_mac_page_indicate(struct dect_cluster *cl, struct sk_buff *skb)
{
	dect_bsap_rcv(cl, skb);
}

static void dect_fa_parse_len(struct dect_fa_len *len, const struct sk_buff *skb)
{
	u8 l;

	l = skb->data[DECT_FA_LI_OFF];
	len->len  = (l & DECT_FA_LI_LENGTH_MASK) >> DECT_FA_LI_LENGTH_SHIFT;
	len->more = (l & DECT_FA_LI_M_FLAG);
}

/*
 * LAPC entity
 */

#define lapc_debug(lapc, fmt, args...) \
	pr_debug("LAPC (MCEI: %u LLN: %u): " fmt, \
		 (lapc)->lc->mc->mcei, (lapc)->dli.lln, ## args)

static inline u8 lapc_seq_add(const struct dect_lapc *lapc, u8 s1, u8 s2)
{
	return (s1 + s2) & (lapc->mod - 1);
}

static inline bool dect_fa_seq_before(const struct dect_lapc *lapc, u8 s1, u8 s2)
{
	if (lapc->window == 1)
		return s1 != s2;
	else
		return (s8)((s2 << 5) - (s1 << 5)) > 0;
}

static inline bool dect_fa_seq_after(const struct dect_lapc *lapc, u8 s1, u8 s2)
{
	return dect_fa_seq_before(lapc, s2, s1);
}

static void dect_lapc_transmit_skb(struct dect_lapc *lapc)
{
	struct sk_buff *skb = skb_peek(&lapc->retransmit_queue);
	struct dect_fa_hdr *fh;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (skb == NULL)
		return;

	fh = (struct dect_fa_hdr *)skb->data;
	lapc_debug(lapc, "queue I-frame v_a: %u v_r: %u v_s: %u "
		   "len: %u addr: %.2x ctrl: %.2x\n", lapc->v_a, lapc->v_r,
		   lapc->v_s, skb->len, fh->addr, fh->ctrl);
	skb_queue_tail(&lapc->lc->txq, skb);
}

static void dect_lapc_error_report(struct dect_lapc *lapc, int err)
{
	struct sock *sk = lapc->sk;

	lapc_debug(lapc, "socket error: %d\n", err);
	sk->sk_err = err;
	sk->sk_error_report(sk);
}

static void dect_lapc_state_change(struct dect_lapc *lapc, int state)
{
	struct sock *sk = lapc->sk;

	lapc_debug(lapc, "socket state change: %d\n", state);
	sk->sk_state = state;
	sk->sk_state_change(sk);
}

/**
 * dect_lapc_timeout - retransmission timer
 *
 * Handle missing acknowledgements:
 *
 * - If not already in timer recovery condition, enter it
 * - otherwise add one to retransmission count
 *
 * If the retransmission count is below the maximum, restart the timer and
 * send an "appropriate" S-frame acknowledgement or retransmit the last
 * I-frame, in both cases with the poll bit set.
 */
static void dect_lapc_timeout(unsigned long data)
{
	struct dect_lapc *lapc = (struct dect_lapc *)data;

	lapc_debug(lapc, "retransmission timer: cnt: %u\n", lapc->retransmit_cnt);
	if (lapc->retransmit_cnt++ < DECT_LAPC_RETRANSMIT_MAX) {
		dect_lapc_transmit_skb(lapc);
		mod_timer(&lapc->timer, jiffies + DECT_LAPC_CLASS_A_ESTABLISH_TIMEOUT);
	} else
		dect_lapc_error_report(lapc, ETIMEDOUT);
}

static bool dect_lapc_done(const struct dect_lapc *lapc)
{
	return skb_queue_empty(&lapc->sk->sk_write_queue) &&
	       skb_queue_empty(&lapc->retransmit_queue);
}

void dect_lapc_destroy(struct dect_lapc *lapc)
{
	lapc_debug(lapc, "destroy\n");

	del_timer_sync(&lapc->timer);
	skb_queue_purge(&lapc->retransmit_queue);
	dect_lc_unbind(lapc->lc, lapc);
	sock_put(lapc->sk);
	kfree(lapc);
}

static void dect_lapc_reset(struct dect_lapc *lapc)
{
	lapc->nlf = true;
	lapc->v_s = 0;
	lapc->v_a = 0;
	lapc->v_r = 0;
}

/**
 * dect_lapc_init - initialize a new LAPC entity
 */
struct dect_lapc *dect_lapc_init(struct sock *sk, const struct dect_dli *dli,
				 enum dect_sapis sapi, struct dect_lc *lc,
				 gfp_t gfp)
{
	struct dect_lapc *lapc;

	lapc = kzalloc(sizeof(*lapc), gfp);
	if (lapc == NULL)
		return NULL;

	lapc->sk = sk;
	sock_hold(sk);

	memcpy(&lapc->dli, dli, sizeof(lapc->dli));
	lapc->sapi = sapi;
	lapc->state = DECT_LAPC_ULI;
	skb_queue_head_init(&lapc->retransmit_queue);

	lapc->lc = lc;
	setup_timer(&lapc->timer, dect_lapc_timeout, (unsigned long)lapc);
	lapc->cmd = (lc->mc->cl->mode == DECT_MODE_FP) ? true : false;

	switch (lapc->dli.lln) {
	case DECT_LLN_CLASS_U:
		break;
	case DECT_LLN_CLASS_A:
		lapc->window = DECT_LAPC_CLASS_A_WINDOW;
		lapc->mod = DECT_LAPC_CLASS_A_MOD;
		break;
	default:
		lapc->window = DECT_LAPC_CLASS_B_INITIAL_WINDOW;
		lapc->mod = DECT_LAPC_CLASS_B_MOD;
		break;
	}

	dect_lapc_reset(lapc);

	lapc_debug(lapc, "init\n");
	return lapc;
}

#define DECT_FA_FRAME_RESERVE	16
#define DECT_FA_FRAME_SPACE	16

static struct sk_buff *dect_lapc_alloc_skb(struct dect_lapc *lapc)
{
	struct sk_buff *skb;

	skb = alloc_skb(DECT_FA_FRAME_SPACE + DECT_FA_FRAME_RESERVE, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;
	skb_reset_mac_header(skb);
	skb_reserve(skb, DECT_FA_FRAME_RESERVE);
	skb_reserve(skb, DECT_FA_HDR_SIZE);
	skb_reset_network_header(skb);
	return skb;
}

static struct dect_fa_hdr *dect_prepare_fa_frame(const struct dect_lapc *lapc,
						 bool command,
						 struct sk_buff *skb)
{
	struct dect_fa_hdr *fh;
	u8 ilen = skb->len;

	fh = (struct dect_fa_hdr *)skb_push(skb, DECT_FA_HDR_SIZE);
	fh->addr  = lapc->dli.lln << DECT_FA_ADDR_LLN_SHIFT;
	fh->addr |= lapc->sapi << DECT_FA_ADDR_SAPI_SHIFT;
	fh->addr |= DECT_FA_ADDR_RES_BIT;
	fh->addr |= (command ? lapc->cmd : !lapc->cmd) ? DECT_FA_ADDR_CR_FLAG : 0;
	fh->addr |= lapc->nlf ? DECT_FA_ADDR_NLF_FLAG : 0;
	fh->ctrl  = 0;
	fh->li    = ilen << DECT_FA_LI_LENGTH_SHIFT;
	fh->li	 |= DECT_FA_LI_EXT_FLAG;
	return fh;
}

static bool dect_lapc_send_iframe(struct dect_lapc *lapc, bool pf)
{
	struct dect_fa_hdr *fh;
	struct sk_buff *skb;

	/* Window size full? */
	lapc_debug(lapc, "send iframe v_a: %u window: %u v_s: %u\n",
		   lapc->v_a, lapc->window, lapc->v_s);
	if (lapc_seq_add(lapc, lapc->v_a, lapc->window) == lapc->v_s)
		return false;

	/* Prepare a new I-frame */
	skb = skb_dequeue(&lapc->sk->sk_write_queue);
	if (skb == NULL)
		return false;
	fh = dect_prepare_fa_frame(lapc, true, skb);
	fh->ctrl |= DECT_FA_CTRL_I_FMT_ID;
	fh->ctrl |= lapc->v_r << DECT_FA_CTRL_I_NR_SHIFT;
	fh->ctrl |= lapc->v_s << DECT_FA_CTRL_I_NS_SHIFT;
	fh->ctrl |= pf ? DECT_FA_CTRL_I_P_FLAG : 0;

	/* Append to retransmission queue and (re)start retransmission timer */
	skb_queue_tail(&lapc->retransmit_queue, skb);
	if (!timer_pending(&lapc->timer))
		mod_timer(&lapc->timer, jiffies + DECT_LAPC_RETRANSMISSION_TIMEOUT);

	lapc->v_s = lapc_seq_add(lapc, lapc->v_s, 1);

	dect_lapc_transmit_skb(lapc);
	return true;
}

/*
 * Send a S-frame with the specified command. The command/response bit setting
 * depends on the role of the LAPC, a PP uses 0 for commands and 1 for responses,
 * a FT 1 for commands and 0 for responses.
 */
static bool dect_lapc_send_sframe(struct dect_lapc *lapc, u8 cr,
				  bool command, bool pf)
{
	struct dect_fa_hdr *fh;
	struct sk_buff *skb;

	skb = dect_lapc_alloc_skb(lapc);
	if (skb == NULL)
		return false;

	fh = dect_prepare_fa_frame(lapc, command, skb);
	fh->ctrl |= DECT_FA_CTRL_S_FMT_ID;
	fh->ctrl |= lapc->v_r << DECT_FA_CTRL_S_NR_SHIFT;
	fh->ctrl |= cr;
	fh->ctrl |= pf ? DECT_FA_CTRL_S_PF_FLAG : 0;

	lapc_debug(lapc, "queue S-frame v_r: %u len: %u addr: %.2x ctrl: %.2x\n",
		   lapc->v_r, skb->len, fh->addr, fh->ctrl);
	skb_queue_tail(&lapc->lc->txq, skb);

	lapc->nlf = false;
	return true;
}

/*
 * Send an acknowledgement frame. Class B entities use RNR responses to indicate
 * their status while busy. Otherwise an I-frame is used when data is available
 * and a RR response frame otherwise.
 */
static void dect_lapc_send_ack(struct dect_lapc *lapc, bool pf)
{
	lapc_debug(lapc, "send ACK I-frame present: %u\n",
		   skb_peek(&lapc->sk->sk_write_queue) ? 1 : 0);
	if (lapc->dli.lln != DECT_LLN_CLASS_A && lapc->busy)
		dect_lapc_send_sframe(lapc, DECT_FA_CTRL_S_CR_RNR, false, false);
	else if (!lapc->peer_busy && skb_peek(&lapc->sk->sk_write_queue))
		dect_lapc_send_iframe(lapc, pf);
	else
		dect_lapc_send_sframe(lapc, DECT_FA_CTRL_S_CR_RR, false, pf);
}

static void dect_lapc_queue_data(struct dect_lapc *lapc, struct sk_buff *skb)
{
	struct dect_fa_hdr *fh = (struct dect_fa_hdr *)skb->data;

	skb_pull(skb, DECT_FA_HDR_SIZE);
	if (skb->len == 0) {
		kfree_skb(skb);
		return;
	}
	lapc_debug(lapc, "reassemble: segment len %u more %u\n",
		   skb->len, (fh->li & DECT_FA_LI_M_FLAG) ? 1 : 0);

	lapc->rcv_head = skb_append_frag(lapc->rcv_head, skb);
	if (!(fh->li & DECT_FA_LI_M_FLAG)) {
		skb = lapc->rcv_head;
		lapc->rcv_head = NULL;
		lapc_debug(lapc, "reassembled: message len %u\n", skb->len);
		sock_queue_rcv_skb(lapc->sk, skb);
	}
}

static bool dect_lapc_update_ack(struct dect_lapc *lapc, u8 seq)
{
	u8 v_a = lapc->v_a;

	lapc_debug(lapc, "update ACK: v_a: %u v_s: %u seq: %u\n",
		   lapc->v_a, lapc->v_s, seq);
	lapc_debug(lapc, "seq %u after v_a %u: %u\n", seq, lapc->v_a,
		   dect_fa_seq_after(lapc, seq, lapc->v_a));
	lapc_debug(lapc, "v_s %u !after seq %u: %u\n", lapc->v_s, seq,
		   !dect_fa_seq_after(lapc, lapc->v_s, seq));

	/* If all outstanding I-frames have been acknowledged, stop
	 * retransmission timer, otherwise reset it.
	 */
	if (dect_fa_seq_after(lapc, seq, lapc->v_a) &&
	    !dect_fa_seq_after(lapc, lapc->v_s, seq)) {
		lapc->v_a = seq;
		if (lapc->v_a == lapc->v_s) {
			del_timer_sync(&lapc->timer);
			lapc->retransmit_cnt = 0;
		} else
			mod_timer(&lapc->timer, jiffies + DECT_LAPC_RETRANSMISSION_TIMEOUT);
	} else if (seq != lapc->v_a)
		return false;

	/* Purge acknowledged frames from transmit queue */
	while (v_a != lapc->v_a) {
		lapc_debug(lapc, "purge retransmit queue seq: %u\n", v_a);
		kfree_skb(skb_dequeue(&lapc->retransmit_queue));
		v_a = lapc_seq_add(lapc, v_a, 1);
	}

	if (lapc->sk->sk_state == DECT_SK_RELEASE_PENDING &&
	    dect_lapc_done(lapc)) {
		dect_lapc_state_change(lapc, DECT_SK_RELEASED);
		dect_lapc_destroy(lapc);
		return false;
	}

	return true;
}

/*
 * Receive a Class A or Class B I-frame. Frames with valid sequence numbers
 * are acknowledged and queued for segment reassembly. Invalid sequence
 * numbers cause an ACK with the expected sequence number to be sent.
 *
 * Class B entities need to indicate their receiver busy status when busy or
 * when explicitly polled.
 */
static void dect_lapc_rcv_iframe(struct dect_lapc *lapc, struct sk_buff *skb)
{
	struct dect_fa_hdr *fh = (struct dect_fa_hdr *)skb->data;
	bool poll = false;
	u8 n_s, n_r, res;

	if (lapc->dli.lln == DECT_LLN_CLASS_U) {
		kfree_skb(skb);
		return;
	}

	if (fh->addr & DECT_FA_ADDR_NLF_FLAG)
		dect_lapc_reset(lapc);

	n_r = (fh->ctrl & DECT_FA_CTRL_I_NR_MASK) >> DECT_FA_CTRL_I_NR_SHIFT;
	n_s = (fh->ctrl & DECT_FA_CTRL_I_NS_MASK) >> DECT_FA_CTRL_I_NS_SHIFT;
	if (lapc->dli.lln != DECT_LLN_CLASS_A)
		poll = fh->ctrl & DECT_FA_CTRL_I_P_FLAG;

	lapc_debug(lapc, "receive I-frame: n_r: %u n_s: %u poll: %u\n",
		   n_r, n_s, poll);
	dect_lapc_update_ack(lapc, n_r);

	/* While in receiver busy condition, all I-frames are dropped after
	 * updating the acknowledgement number. In Class B mode receiver status
	 * queries are still answered.
	 */
	if (lapc->busy) {
		kfree_skb(skb);
		if (poll)
			goto poll;
		return;
	}

	/* When the frame contains an invalid sequence number, send an
	 * immediate ACK. */
	if (n_s != lapc->v_r) {
		lapc_debug(lapc, "invalid sequence number %u %u\n", n_s, lapc->v_r);
		kfree_skb(skb);
		goto ack;
	}

	lapc->v_r = lapc_seq_add(lapc, lapc->v_r, 1);
	dect_lapc_queue_data(lapc, skb);
	if (poll)
		goto poll;
ack:
	return dect_lapc_send_ack(lapc, poll);

poll:
	res = lapc->busy ? DECT_FA_CTRL_S_CR_RNR : DECT_FA_CTRL_S_CR_RR;
	dect_lapc_send_sframe(lapc, res, false, true);
}

static void dect_lapc_rcv_sframe(struct dect_lapc *lapc, struct sk_buff *skb)
{
	struct dect_fa_hdr *fh = (struct dect_fa_hdr *)skb->data;
	bool pf;
	u8 n_r;

	n_r = (fh->ctrl & DECT_FA_CTRL_S_NR_MASK) >> DECT_FA_CTRL_S_NR_SHIFT;
	pf  = (fh->ctrl & DECT_FA_CTRL_S_PF_FLAG);
	lapc_debug(lapc, "receive S-frame: n_r: %u pf: %u\n", n_r, pf);

	switch (fh->ctrl & DECT_FA_CTRL_S_CR_MASK) {
	case DECT_FA_CTRL_S_CR_RR:
		if (!dect_lapc_update_ack(lapc, n_r))
			goto err;

		if (lapc->lc->elapc == lapc) {
			/* Connection establishment completed */
			lapc_debug(lapc, "established\n");
			lapc->lc->elapc = NULL;
			del_timer_sync(&lapc->timer);
			dect_lapc_state_change(lapc, DECT_SK_ESTABLISHED);
		}

		dect_lapc_send_iframe(lapc, pf);
		break;
	case DECT_FA_CTRL_S_CR_RNR:
		/*
		 * Note peer receiver busy condition. If it was a RNR command
		 * with the P bit set to 1, send a RR response with the F bit
		 * set to 1. If it was a RNR response with the F bit set to 1,
		 * clear timer recovery condition and update V(S).
		 */
		lapc->peer_busy = true;

		if (fh->addr & DECT_FA_ADDR_CR_FLAG && pf)
			dect_lapc_send_sframe(lapc, DECT_FA_CTRL_S_CR_RR, true, true);
		else if (!(fh->addr & DECT_FA_ADDR_CR_FLAG) && pf) {
			del_timer_sync(&lapc->timer);
			lapc->v_s = n_r;
		}

		dect_lapc_update_ack(lapc, n_r);
		break;
	case DECT_FA_CTRL_S_CR_REJ:
		lapc->peer_busy = false;
		lapc->v_s = n_r;
		lapc->v_a = n_r;
		del_timer_sync(&lapc->timer);
		break;
	default:
		goto err;
	}

err:
	kfree_skb(skb);
}

static void dect_lapc_rcv_uframe(struct dect_lapc *lapc, struct sk_buff *skb)
{
	struct dect_fa_hdr *fh = (struct dect_fa_hdr *)skb->data;
	u8 pf, cr;

	pf = (fh->ctrl & DECT_FA_CTRL_U_PF_FLAG);
	cr = (fh->ctrl & DECT_FA_CTRL_U_U1_MASK) |
	     (fh->ctrl & DECT_FA_CTRL_U_CR_MASK);

	/* unnumbered information is only valid in class U mode */
	if (cr == DECT_FA_CTRL_U_CR_UI) {
		if (lapc->dli.lln != DECT_LLN_CLASS_U)
			goto err;
		lapc_debug(lapc, "queue UI message len: %u\n", skb->len);
		sock_queue_rcv_skb(lapc->sk, skb);
		return;
	}

	/* the remaining commands/responses are only valid in class B mode */
	if (lapc->dli.lln == DECT_LLN_CLASS_A)
		goto err;

	switch (cr) {
	case DECT_FA_CTRL_U_CR_SABM:
		break;
	case DECT_FA_CTRL_U_CR_DM:
		break;
	case DECT_FA_CTRL_U_CR_DISC:
		break;
	case DECT_FA_CTRL_U_CR_UA:
		break;
	}

err:
	kfree_skb(skb);
}

static void dect_lapc_rcv(struct dect_lapc *lapc, struct sk_buff *skb)
{
	struct dect_fa_hdr *fh = (struct dect_fa_hdr *)skb->data;

	if ((fh->ctrl & DECT_FA_CTRL_I_FMT_MASK) == DECT_FA_CTRL_I_FMT_ID)
		return dect_lapc_rcv_iframe(lapc, skb);
	else if ((fh->ctrl & DECT_FA_CTRL_S_FMT_MASK) == DECT_FA_CTRL_S_FMT_ID)
		return dect_lapc_rcv_sframe(lapc, skb);
	else if ((fh->ctrl & DECT_FA_CTRL_U_FMT_MASK) == DECT_FA_CTRL_U_FMT_ID)
		return dect_lapc_rcv_uframe(lapc, skb);
	else
		kfree_skb(skb);
}

int dect_lapc_transmit(struct dect_lapc *lapc)
{
	dect_lapc_send_iframe(lapc, 0);
	return 0;
}

int dect_lapc_establish(struct dect_lapc *lapc)
{
	struct sk_buff *skb;

	lapc_debug(lapc, "establish\n");

	/* Prepend zero-sized message to transmit queue to trigger connection
	 * establishment.
	 */
	skb = dect_lapc_alloc_skb(lapc);
	if (skb == NULL)
		return -ENOMEM;
	skb_queue_head(&lapc->sk->sk_write_queue, skb);

	lapc->lc->elapc = lapc;
	dect_lapc_send_iframe(lapc, lapc->dli.lln != DECT_LLN_CLASS_A);
	lapc->nlf = false;

	mod_timer(&lapc->timer, jiffies + DECT_LAPC_CLASS_A_ESTABLISH_TIMEOUT);
	return 0;
}

/*
 * Initiate link release.
 */
void dect_lapc_release(struct dect_lapc *lapc, bool normal)
{
	lapc_debug(lapc, "release normal: %u\n", normal);
	if (dect_lapc_done(lapc) || !normal) {
		lapc->sk->sk_state = DECT_SK_RELEASED;
		dect_lapc_destroy(lapc);
	} else
		dect_lapc_state_change(lapc, DECT_SK_RELEASE_PENDING);
}

/*
 * Lc entity
 *
 * The Lc entity receives and transmits LAPC frames from/to the MAC layer.
 *
 * For transmission the frames are checksummed and fragmented into channel
 * sized units. The channel is chosen before transmission of a new frame
 * based on availability and demand. All fragments of one frame are
 * transmitted in the chosen channel.
 *
 * Received fragments are resegmented and have their checksum validated,
 * then routed to the LAPC entity associated with the logical link number.
 */

#define lc_debug(lc, fmt, args...) \
	pr_debug("Lc (MCEI %u): " fmt, (lc)->mc->mcei, ## args)

void dect_lc_destroy(struct dect_lc *lc)
{
	lc_debug(lc, "destroy\n");
	dect_dlc_mac_conn_unbind(lc->mc);
	kfree_skb(lc->rx_head);
	kfree_skb(lc->tx_head);
	__skb_queue_purge(&lc->txq);
	kfree(lc);
}

void dect_lc_unbind(struct dect_lc *lc, struct dect_lapc *lapc)
{
	lc_debug(lc, "unbind LLN: %u use: %u\n", lapc->dli.lln, lc->use);
	if (WARN_ON(lc->lapcs[lapc->dli.lln] == NULL))
		return;

	lc->lapcs[lapc->dli.lln] = NULL;
	if (--lc->use > 0)
		return;

	dect_lc_destroy(lc);
}

void dect_lc_bind(struct dect_lc *lc, struct dect_lapc *lapc)
{
	lc_debug(lc, "bind LLN: %u use: %u\n", lapc->dli.lln, lc->use);

	lc->lapcs[lapc->dli.lln] = lapc;
	lc->use++;
}

struct dect_lc *dect_lc_init(struct dect_mac_conn *mc, gfp_t gfp)
{
	struct dect_lc *lc;

	lc = kzalloc(sizeof(*lc), gfp);
	if (lc == NULL)
		return NULL;

	lc->mc = mc;
	dect_dlc_mac_conn_bind(mc);

	lc_debug(lc, "init\n");
	skb_queue_head_init(&lc->txq);
	switch (mc->mci.pmid.type) {
	case DECT_PMID_ASSIGNED:
		lc->lsig = dect_build_pmid(&mc->mci.pmid);
		break;
	default:
		lc->lsig = 0;
		break;
	}

	return lc;
}

static void dect_fa_frame_csum(const struct dect_lc *lc, struct sk_buff *skb)
{
	u8 *data = skb->data;
	unsigned int i;
	u8 c0 = 0, c1 = 0;
	u8 x, y;
	u16 t;

	data[skb->len - 2] = 0;
	data[skb->len - 1] = 0;

	for (i = 0; i < skb->len; i++) {
		t = c0 + data[i];
		c0 = (t & 0xffU) + ((t >> 8) & 0x1U);
		t = c1 + c0;
		c1 = (t & 0xffU) + ((t >> 8) & 0x1U);
	}

	t = c0 + (u8)~c1;
	x = (t & 0xffU) + ((t >> 8) & 0x1U);

	t = (u8)~c0 + (u8)~c0;
	t = (t & 0xffU) + ((t >> 8) & 0x1U);
	t += c1;
	y = (t & 0xffU) + ((t >> 8) & 0x1U);

	data[skb->len - 2] = x ^ (lc->lsig >> 8);
	data[skb->len - 1] = y ^ (lc->lsig & 0xff);
	lc_debug(lc, "checksum: lsig: %.4x x: %.2x y: %.2x\n",
		 lc->lsig, x, y);
}

static bool dect_fa_frame_csum_verify(const struct dect_lc *lc,
				      struct sk_buff *skb)
{
	u8 *data = skb->data;
	unsigned int i;
	u8 c0 = 0, c1 = 0;
	u16 t;

	data[skb->len - 2] ^= lc->lsig >> 8;
	data[skb->len - 1] ^= lc->lsig & 0xff;

	for (i = 0; i < skb->len; i++) {
		t = c0 + data[i];
		c0 = (t & 0xffU) + ((t >> 8) & 0x1U);
		t = c1 + c0;
		c1 = (t & 0xffU) + ((t >> 8) & 0x1U);
	}

	lc_debug(lc, "csum verify: lsig %.4x c0: %.2x c1: %.2x\n",
		 lc->lsig, c0, c1);
	return c0 == (u8)~0 && c1 == (u8)~0;
}

static const u8 channel_sdu_size[] = {
	[DECT_MC_C_S]	= DECT_C_S_SDU_SIZE,
	[DECT_MC_C_F]	= DECT_C_F_SDU_SIZE,
};

/*
 * Prepare a DLC frame for transmission to the MAC layer. This involves
 * checksumming the frame, selecting the logical channel for transmission
 * and fragmenting it into units carried by the logical channel.
 */
static struct sk_buff *dect_lc_tx(struct dect_lc *lc)
{
	struct sk_buff *skb, *frag;
	u8 *fill, fill_len;
	u8 flen;

	skb = lc->tx_head;
	if (skb == NULL) {
		skb = skb_dequeue(&lc->txq);
		if (skb == NULL)
			return NULL;
		lc_debug(lc, "tx: begin new frame len: %u\n", skb->len);

		flen = channel_sdu_size[DECT_MC_C_S];
		fill_len = roundup(skb->len + DECT_FA_CSUM_SIZE, flen) -
			   (skb->len + DECT_FA_CSUM_SIZE);
		fill = skb_put(skb, fill_len);
		memset(fill, DECT_FA_FILL_PATTERN, fill_len);

		skb_put(skb, DECT_FA_CSUM_SIZE);
		dect_fa_frame_csum(lc, skb);

		lc->tx_head = skb;
		lc->tx_len = flen;
	}

	/* Fragment into tx_len sized units */
	if (skb->len > lc->tx_len) {
		frag = skb_copy(skb, GFP_ATOMIC);
		if (frag == NULL)
			return NULL;
		skb_trim(frag, lc->tx_len);
		skb_pull(skb, lc->tx_len);
	} else {
		frag = lc->tx_head;
		lc->tx_head = NULL;
	}

	lc_debug(lc, "tx: %sfragment len: %u\n",
		 lc->tx_head ? "" : "last ", frag->len);
	return frag;
}

static struct sk_buff *dect_lc_reassemble(struct dect_lc *lc,
					  enum dect_data_channels chan,
					  struct sk_buff *skb)
{
	struct dect_fa_len fl;
	u8 flen, len;

	if (lc->rx_head == NULL) {
		dect_fa_parse_len(&fl, skb);
		len = fl.len;
		len += DECT_FA_HDR_SIZE + DECT_FA_CSUM_SIZE;

		flen = channel_sdu_size[chan];
		lc->rx_len = roundup(len, flen);
	}

	lc->rx_head = skb_append_frag(lc->rx_head, skb);
	skb = NULL;

	if (lc->rx_head->len >= lc->rx_len) {
		WARN_ON(lc->rx_head->len != lc->rx_len);
		skb = lc->rx_head;
		lc->rx_head = NULL;

		if (skb_linearize(skb) < 0)
			goto err;
		if (!dect_fa_frame_csum_verify(lc, skb))
			goto err;

		/* Trim checksum and filling */
		dect_fa_parse_len(&fl, skb);
		skb_trim(skb, fl.len + DECT_FA_HDR_SIZE);
		lc_debug(lc, "reassembled SDU len %u\n", skb->len);
	}

	return skb;

err:
	lc_debug(lc, "reassembly failed\n");
	kfree_skb(skb);
	return NULL;
}

static void dect_lc_rcv(struct dect_lc *lc, enum dect_data_channels chan,
			struct sk_buff *skb)
{
	struct dect_fa_hdr *fh;
	struct dect_lapc *lapc;
	struct dect_dli dli;
	enum dect_sapis sapi;

	skb = dect_lc_reassemble(lc, chan, skb);
	if (skb == NULL)
		return;
	fh = (struct dect_fa_hdr *)skb->data;

	dli.lln = (fh->addr & DECT_FA_ADDR_LLN_MASK) >> DECT_FA_ADDR_LLN_SHIFT;
	lc_debug(lc, "receive: LLN %u NLF %u SAPI %u\n",
		 dli.lln, (fh->addr & DECT_FA_ADDR_NLF_FLAG) ? 1 : 0,
		 (fh->addr & DECT_FA_ADDR_SAPI_MASK) >> DECT_FA_ADDR_SAPI_SHIFT);

	if (lc->lapcs[dli.lln] != NULL)
		return dect_lapc_rcv(lc->lapcs[dli.lln], skb);

	/* Link establishment: new requests are only valid while no link
	 * establishment is in progress.
	 */
	if (!(fh->addr & DECT_FA_ADDR_NLF_FLAG))
		goto err;
	if ((fh->ctrl & DECT_FA_CTRL_I_FMT_MASK) != DECT_FA_CTRL_I_FMT_ID)
		goto err;
	if (lc->elapc != NULL)
		goto err;

	sapi = (fh->addr & DECT_FA_ADDR_SAPI_MASK) >> DECT_FA_ADDR_SAPI_SHIFT;
	if (sapi != DECT_SAPI_CO_SIGNALLING && sapi != DECT_SAPI_CL_SIGNALLING)
		goto err;
	memcpy(&dli.mci, &lc->mc->mci, sizeof(dli.mci));

	lapc = dect_ssap_rcv_request(lc, &dli, sapi);
	if (lapc == NULL)
		goto err;
	dect_lc_bind(lc, lapc);

	return dect_lapc_rcv(lapc, skb);

err:
	lc_debug(lc, "packet ignored\n");
	kfree_skb(skb);
}

void dect_cplane_rcv(struct dect_mac_conn *mc, enum dect_data_channels chan,
		     struct sk_buff *skb)
{
	struct dect_lc *lc;

	if (mc->lc == NULL) {
		lc = dect_lc_init(mc, GFP_ATOMIC);
		if (lc == NULL)
			goto err;
		mc->lc = lc;
	}
	return dect_lc_rcv(mc->lc, chan, skb);

err:
	kfree_skb(skb);
}

struct sk_buff *dect_cplane_dtr(struct dect_mac_conn *mc, enum dect_data_channels chan)
{
	struct dect_lc *lc;

	lc = mc->lc;
	if (lc == NULL)
		return NULL;
	lc_debug(lc, "DTR channel %u\n", chan);
	return dect_lc_tx(lc);
}

void dect_cplane_notify_state_change(struct dect_mac_conn *mc)
{
	struct dect_lc *lc = mc->lc;
	unsigned int i;

	if (lc == NULL)
		return;

	lc_debug(lc, "mac conn state change: state: %u\n", mc->state);
	switch (mc->state) {
	// FIXME: this does not make sense for incoming connections
	case DECT_MAC_CONN_OPEN_PENDING:
		break;
	case DECT_MAC_CONN_OPEN:
		for (i = 0; i < ARRAY_SIZE(lc->lapcs); i++) {
			if (lc->lapcs[i] == NULL)
				continue;
			dect_lapc_establish(lc->lapcs[i]);
			break;
		}
		break;
	case DECT_MAC_CONN_CLOSED:
		break;
	}
}

void dect_cplane_mac_dis_indicate(const struct dect_mac_conn *mc,
				  enum dect_release_reasons reason)
{
	struct dect_lc *lc = mc->lc;
	unsigned int i;
	int err;

	if (lc == NULL)
		return;

	/* When no lapcs are bound, destroy immediately since destruction won't
	 * be triggered by unbinding */
	if (lc->use == 0)
		return dect_lc_destroy(lc);

	switch (reason) {
	case DECT_REASON_BEARER_RELEASE:
		err = 0;
		break;
	case DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED:
		err = EHOSTUNREACH;
		break;
	case DECT_REASON_TIMEOUT_LOST_HANDSHAKE:
		err = ETIMEDOUT;
		break;
	default:
		err = EIO;
		break;
	}

	for (i = 0; i < ARRAY_SIZE(lc->lapcs); i++) {
		if (lc->lapcs[i] == NULL)
			continue;
		lc->lapcs[i]->sk->sk_state = DECT_SK_RELEASED;
		dect_lapc_error_report(lc->lapcs[i], err);
		dect_lapc_destroy(lc->lapcs[i]);
	}
}

void dect_cplane_mac_enc_eks_indicate(const struct dect_mac_conn *mc,
				      enum dect_cipher_states status)
{
	struct dect_lc *lc = mc->lc;
	struct dect_dl_encrypt enc;
	struct sk_buff *skb, *nskb;
	unsigned int i;

	if (lc == NULL || lc->use == 0)
		return;

	enc.status = status;
	skb = dect_alloc_notification(DECT_DL_ENCRYPT, &enc, sizeof(enc));

	for (i = 0; i < ARRAY_SIZE(lc->lapcs); i++) {
		if (lc->lapcs[i] == NULL)
			continue;

		nskb = skb ? skb_clone(skb, GFP_ATOMIC) : NULL;
		if (nskb != NULL)
			sock_queue_err_skb(lc->lapcs[i]->sk, nskb);
		else
			dect_lapc_error_report(lc->lapcs[i], ENOMEM);
	}

	kfree_skb(skb);
}
