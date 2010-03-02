/*
 * DECT virtual transceiver
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/hrtimer.h>
#include <linux/skbuff.h>
#include <net/dect/transceiver.h>
#include "vtrx.h"

#define vtrx_debug(vtrx, fmt, args...) \
	pr_debug("vtrx %s: " fmt, (vtrx)->trx->name, ## args)

#define DECT_SLOTS_PER_SECOND	(DECT_FRAMES_PER_SECOND * DECT_FRAME_SIZE)
#define DECT_VTRX_RATE		(NSEC_PER_SEC / DECT_SLOTS_PER_SECOND)
#define DECT_VTRX_DEFAULT_TRX	2

#define DECT_WAVELEN_SCALE	13
#define DECT_WAVELEN		160 /* mm */

struct dect_skb_vtrx_cb {
	struct dect_vtrx	*vtrx;
	u8			rssi;
	u8			carrier;
};

static LIST_HEAD(vtrx_groups);

static inline struct dect_skb_vtrx_cb *DECT_VTRX_CB(const struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct dect_skb_vtrx_cb) > sizeof(skb->cb));
	return (struct dect_skb_vtrx_cb *)skb->cb;
}

static unsigned int dect_vtrx_distance(const struct dect_vtrx *vtrx1,
				       const struct dect_vtrx *vtrx2)
{
	int dx, dy;

	dx = vtrx1->pos_x - vtrx2->pos_x;
	dy = vtrx1->pos_y - vtrx2->pos_y;

	return int_sqrt(dx * dx + dy * dy);
}

static u8 dect_vtrx_receive_rssi(const struct dect_vtrx *rx_vtrx,
				 const struct sk_buff *skb)
{
	const struct dect_vtrx *tx_vtrx = DECT_VTRX_CB(skb)->vtrx;
	unsigned int distance;
	u64 rx_power, tmp;
	int dbm = 0;

	distance = dect_vtrx_distance(rx_vtrx, tx_vtrx);
	if (distance == 0)
		goto out;

	tmp = 1000 * (DECT_WAVELEN << DECT_WAVELEN_SCALE) / (4 * 3141 * distance);
	rx_power = (tx_vtrx->tx_power * tmp * tmp) >> (2 * DECT_WAVELEN_SCALE);
	dbm = dect_mw_to_dbm(rx_power);
out:
	if (dbm > -33)
		dbm = -33;

	return dect_dbm_to_rssi(dbm);
}

static void dect_vtrx_process_slot(struct dect_vtrx_group *group,
				   struct dect_vtrx *vtrx)
{
	struct dect_transceiver_event *event;
	struct dect_transceiver_slot *ts;
	struct dect_transceiver *trx = vtrx->trx;
	struct sk_buff *skb, *best;
	u8 slot = group->slot, rcvslot;
	u8 rssi, best_rssi;

	event = dect_transceiver_event(trx, slot % 12, slot);
	if (event == NULL)
		return;

	if (trx->state == DECT_TRANSCEIVER_UNLOCKED ||
	    trx->state == DECT_TRANSCEIVER_LOCK_PENDING)
		rcvslot = DECT_SCAN_SLOT;
	else
		rcvslot = slot;

	rssi = dect_dbm_to_rssi(-80);
	best = NULL;

	ts = &trx->slots[rcvslot];
	if (ts->state != DECT_SLOT_RX &&
	    ts->state != DECT_SLOT_SCANNING)
		goto queue;

	skb_queue_walk(&group->txq[slot], skb) {
		if (DECT_VTRX_CB(skb)->carrier != ts->chd.carrier)
			continue;

		rssi = dect_vtrx_receive_rssi(vtrx, skb);
		if (best == NULL || rssi > best_rssi) {
			best	  = skb;
			best_rssi = rssi;
		}
	}

	if (best == NULL)
		goto rssi;
	rssi = best_rssi;

	skb = skb_clone(best, GFP_ATOMIC);
	if (skb == NULL)
		goto rssi;

	DECT_TRX_CB(skb)->trx  = trx;
	DECT_TRX_CB(skb)->slot = rcvslot;
	DECT_TRX_CB(skb)->csum = DECT_CHECKSUM_A_CRC_OK | DECT_CHECKSUM_X_CRC_OK;
	DECT_TRX_CB(skb)->rssi = rssi;
	__skb_queue_tail(&event->rx_queue, skb);

	ts->rx_bytes += skb->len;
	ts->rx_packets++;
rssi:
	ts->rssi = dect_average_rssi(ts->rssi, rssi);
	dect_transceiver_record_rssi(event, rcvslot, rssi);
queue:
	if (rcvslot != slot && best == NULL)
		dect_release_transceiver_event(event);
	else
		dect_transceiver_queue_event(trx, event);
}

static enum hrtimer_restart dect_vtrx_timer(struct hrtimer *timer)
{
	struct dect_vtrx_group *group = container_of(timer, struct dect_vtrx_group, timer);
	struct dect_vtrx *vtrx;
	ktime_t time;

	list_for_each_entry(vtrx, &group->act_list, list)
		dect_vtrx_process_slot(group, vtrx);

	skb_queue_purge(&group->txq[group->slot]);
	group->slot = dect_next_slotnum(group->slot);

	time = ktime_set(0, DECT_VTRX_RATE);
	hrtimer_forward(timer, hrtimer_cb_get_time(timer), time);

	return HRTIMER_RESTART;
}

/*
 * Transceiver operations
 */

static void dect_vtrx_enable(const struct dect_transceiver *trx)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);
	struct dect_vtrx_group *group = vtrx->group;
	ktime_t time;

	vtrx_debug(vtrx, "enable");
	if (list_empty(&group->act_list)) {
		time = ktime_set(0, DECT_VTRX_RATE);
		hrtimer_start(&group->timer, time, HRTIMER_MODE_ABS);
	}
	list_move_tail(&vtrx->list, &group->act_list);
}

static void dect_vtrx_disable(const struct dect_transceiver *trx)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);
	struct dect_vtrx_group *group = vtrx->group;

	vtrx_debug(vtrx, "disable");
	list_move_tail(&vtrx->list, &group->trx_list);
	if (list_empty(&group->act_list))
		hrtimer_cancel(&group->timer);
}

static void dect_vtrx_confirm(const struct dect_transceiver *trx)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);

	vtrx_debug(vtrx, "confirm");
}

static void dect_vtrx_unlock(const struct dect_transceiver *trx)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);

	vtrx_debug(vtrx, "unlock");
}

static void dect_vtrx_lock(const struct dect_transceiver *trx, u8 slot)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);

	vtrx_debug(vtrx, "lock");
}

static void dect_vtrx_set_mode(const struct dect_transceiver *trx,
			       const struct dect_channel_desc *chd,
			       enum dect_slot_states mode)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);

	vtrx_debug(vtrx, "set_mode: slot: %u mode: %u",
		   chd->slot, mode);
}

static void dect_vtrx_set_carrier(const struct dect_transceiver *trx,
				  u8 slot, u8 carrier)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);

	vtrx_debug(vtrx, "set carrier: slot: %u carrier: %u\n",
		   slot, carrier);
}

static u64 dect_vtrx_set_band(const struct dect_transceiver *trx,
			      const struct dect_band *band)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);

	vtrx_debug(vtrx, "set band: %u\n", band->band);
	return band->carriers;
}

static void dect_vtrx_tx(const struct dect_transceiver *trx, struct sk_buff *skb)
{
	struct dect_vtrx *vtrx = dect_transceiver_priv(trx);
	struct dect_vtrx_group *group = vtrx->group;
	u8 slot = DECT_TRX_CB(skb)->slot;

	vtrx_debug(vtrx, "vtrx tx: slot: %u skb: %p\n", slot, skb);
	DECT_VTRX_CB(skb)->vtrx    = vtrx;
	DECT_VTRX_CB(skb)->rssi    = vtrx->tx_power;
	DECT_VTRX_CB(skb)->carrier = trx->slots[slot].chd.carrier;
	skb_queue_tail(&group->txq[slot], skb);
}

static const struct dect_transceiver_ops vtrx_transceiver_ops = {
	.name			= "vtrx",
	.slotmask		= 0xffffff,
	.eventrate		= 1,
	.latency		= 1,
	.enable			= dect_vtrx_enable,
	.disable		= dect_vtrx_disable,
	.confirm		= dect_vtrx_confirm,
	.unlock			= dect_vtrx_unlock,
	.lock			= dect_vtrx_lock,
	.set_mode		= dect_vtrx_set_mode,
	.set_carrier		= dect_vtrx_set_carrier,
	.set_band		= dect_vtrx_set_band,
	.tx			= dect_vtrx_tx,
	.destructor		= dect_transceiver_free,
};

int dect_vtrx_init(struct dect_vtrx_group *group)
{
	struct dect_transceiver *trx;
	struct dect_vtrx *vtrx;
	int err;

	trx = dect_transceiver_alloc(&vtrx_transceiver_ops, sizeof(*vtrx));
	if (trx == NULL)
		return -ENOMEM;

	err = dect_register_transceiver(trx);
	if (err < 0)
		goto err1;

	vtrx = dect_transceiver_priv(trx);
	vtrx->group	= group;
	vtrx->trx	= trx;
	vtrx->tx_power	= 2 * DECT_VTRX_POWER_SCALE;
	list_add_tail(&vtrx->list, &group->trx_list);

	dect_vtrx_register_sysfs(vtrx);
	return 0;

err1:
	dect_transceiver_free(trx);
	return err;
}

void dect_vtrx_free(struct dect_vtrx *vtrx)
{
	dect_vtrx_unregister_sysfs(vtrx);
	dect_unregister_transceiver(vtrx->trx);
}

struct dect_vtrx_group *dect_vtrx_group_init(const char *name)
{
	struct dect_vtrx_group *group;
	unsigned int i;
	int err;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (group == NULL)
		goto err1;

	strlcpy(group->name, name, sizeof(group->name));
	INIT_LIST_HEAD(&group->trx_list);
	INIT_LIST_HEAD(&group->act_list);
	hrtimer_init(&group->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	group->timer.function = dect_vtrx_timer;

	for (i = 0; i < ARRAY_SIZE(group->txq); i++)
		skb_queue_head_init(&group->txq[i]);

	err = dect_vtrx_group_register_sysfs(group);
	if (err < 0)
		goto err2;

	list_add_tail(&group->list, &vtrx_groups);
	return group;

err2:
	kfree(group);
err1:
	return NULL;
}

void dect_vtrx_group_free(struct dect_vtrx_group *group)
{
	struct dect_vtrx *vtrx, *next;
	unsigned int i;

	list_for_each_entry_safe(vtrx, next, &group->act_list, list)
		dect_vtrx_free(vtrx);
	list_for_each_entry_safe(vtrx, next, &group->trx_list, list)
		dect_vtrx_free(vtrx);

	dect_vtrx_group_unregister_sysfs(group);

	for (i = 0; i < ARRAY_SIZE(group->txq); i++)
		__skb_queue_purge(&group->txq[i]);

	kfree(group);
}

static int __init vtrx_init(void)
{
	struct dect_vtrx_group *group;
	unsigned int i;
	int err;

	err = dect_vtrx_sysfs_init();
	if (err < 0)
		goto err1;

	group = dect_vtrx_group_init("group-1");
	if (group == NULL) {
		err = -ENOMEM;
		goto err2;
	}

	for (i = 0; i < DECT_VTRX_DEFAULT_TRX; i++) {
		err = dect_vtrx_init(group);
		if (err < 0)
			goto err3;
	}

	return 0;

err3:
	dect_vtrx_group_free(group);
err2:
	dect_vtrx_sysfs_exit();
err1:
	return err;
}

static void __exit vtrx_exit(void)
{
	struct dect_vtrx_group *group, *next;

	list_for_each_entry_safe(group, next, &vtrx_groups, list)
		dect_vtrx_group_free(group);

	dect_vtrx_sysfs_exit();
}

module_init(vtrx_init);
module_exit(vtrx_exit);

MODULE_LICENSE("GPL");
