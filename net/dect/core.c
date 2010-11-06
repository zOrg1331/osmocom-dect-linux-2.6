/*
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
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <net/dect/dect.h>
#include <net/dect/transceiver.h>

static DEFINE_MUTEX(dect_cfg_mutex);

void dect_lock(void)
{
	mutex_lock(&dect_cfg_mutex);
}
EXPORT_SYMBOL_GPL(dect_lock);

void dect_unlock(void)
{
	mutex_unlock(&dect_cfg_mutex);
}
EXPORT_SYMBOL_GPL(dect_unlock);

/*
 * MAC layer timers
 */

#if 1
#define timer_debug(name, base, fmt, args...) \
	pr_debug("%s: %s %u.%.2u.%.2u: " fmt, name, \
		 (base)->base == DECT_TIMER_TX ? "TX" : "RX", \
		 base->mfn, base->framenum, base->slot, ## args)
#else
#define timer_debug(base, fmt, args...)
#endif

void __dect_run_timers(const char *name, struct dect_timer_base *base)
{
	struct dect_timer *t;

	while (!list_empty(&base->timers)) {
		t = list_first_entry(&base->timers, struct dect_timer, list);

		if (dect_mfn_after(t->mfn, base->mfn) ||
		    (t->mfn == base->mfn && t->frame > base->framenum) ||
		    (t->mfn == base->mfn && t->frame == base->framenum &&
		     t->slot > base->slot))
			break;

		timer_debug(name, base, "timer %p: %u.%u.%u\n",
			    t, t->mfn, t->frame, t->slot);
		list_del_init(&t->list);
		t->cb.cb(t->obj, t->data);
	}
}
EXPORT_SYMBOL_GPL(__dect_run_timers);

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
void __dect_timer_add(const char *name, struct dect_timer_base *base,
		      struct dect_timer *timer, u32 frame, u8 slot)
{
	struct dect_timer *t;
	u32 mfn;

	if (frame == 0 && slot < base->slot)
		frame++;
	frame += base->framenum;
	mfn = dect_mfn_add(base->mfn, frame / DECT_FRAMES_PER_MULTIFRAME);
	frame %= DECT_FRAMES_PER_MULTIFRAME;

	timer_debug(name, base, "timer %p: schedule for %u.%u.%u\n",
		    timer, mfn, frame, slot);
	if (!list_empty(&timer->list))
		list_del(&timer->list);
	list_for_each_entry(t, &base->timers, list) {
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
EXPORT_SYMBOL_GPL(__dect_timer_add);

struct sk_buff *skb_append_frag(struct sk_buff *head, struct sk_buff *skb)
{
	struct sk_buff **pprev;

	if (head == NULL)
		return skb;

	pprev = &skb_shinfo(head)->frag_list;
	while (*pprev != NULL)
		pprev = &(*pprev)->next;
	*pprev = skb;

	head->data_len += skb->len;
	head->len += skb->len;
	head->truesize += skb->truesize;
	return head;
}
EXPORT_SYMBOL_GPL(skb_append_frag);

unsigned int skb_queue_pull(struct sk_buff_head *list, unsigned int len)
{
	unsigned int pulled = 0;
	unsigned long flags;
	struct sk_buff *skb;

	spin_lock_irqsave(&list->lock, flags);
	while (len > pulled) {
		skb = skb_peek(list);
		if (skb == NULL)
			break;
		if (skb->len <= len) {
			__skb_unlink(skb, list);
			pulled += skb->len;
			kfree_skb(skb);
		} else {
			__skb_pull(skb, len);
			pulled += len;
		}
	}
	spin_unlock_irqrestore(&list->lock, flags);
	return pulled;
}
EXPORT_SYMBOL_GPL(skb_queue_pull);

static int __init dect_module_init(void)
{
	int err;

	err = dect_netlink_module_init();
	if (err < 0)
		goto err1;
	err = dect_af_module_init();
	if (err < 0)
		goto err2;
	return 0;

err2:
	dect_netlink_module_exit();
err1:
	return err;
}

static void __exit dect_module_exit(void)
{
	dect_af_module_exit();
	dect_netlink_module_exit();
}

module_init(dect_module_init);
module_exit(dect_module_exit);

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("DECT protocol stack");
MODULE_LICENSE("GPL");
