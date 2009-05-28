/*
 * com_on_air - basic driver for the Dosch and Amand "com on air" cards
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * authors:
 * (C) 2008  Andreas Schuler <krater at badterrorist dot com>
 * (C) 2008  Matthias Wenzel <dect at mazzoo dot de>
 * (C) 2009  Patrick McHardy <kaber@trash.net>
 *
 */

#ifndef COM_ON_AIR_H
#define COM_ON_AIR_H

#include <linux/types.h>

struct coa_freq_map_entry {
	struct {
		u8	divisor;
		u8	swcnt;
	} rx, tx;
};

struct coa_freq_map {
	struct coa_freq_map_entry	carrier[DECT_CARRIER_NUM];
};

struct coa_device;
struct coa_radio_ops {
	void		(*rx_init)(const struct coa_device *dev, u16 offset);
	void		(*tx_init)(const struct coa_device *dev, u16 offset);
	void		(*set_carrier)(const struct coa_device *dev, u16 offset,
				       enum dect_slot_states mode, u8 carrier);
	u64		(*map_band)(struct coa_device *dev,
				    const struct dect_band *band);
	const char	*type;
};

extern const struct coa_radio_ops coa_u2785_radio_ops;
extern const struct coa_radio_ops coa_lmx3161_radio_ops;

/**
 * struct sc1442x_phase_state - per-slot phase offset state
 *
 * @framenum:	frame number the information was last updated
 * @tap:	sc1442x internal clock cycle which sampled the data
 * @phase:	offset of number of symbol periods to nominal 11520 symbols per frame
 *
 * This structure is used to store the measured values for one particular
 * frame. The actual phase offset is calculated from the differences of two
 * consequitive frames.
 */
struct sc1442x_phase_state {
	u8	framenum;
	u8	tap;
	s8	phase;
};

enum coa_device_types {
	COA_TYPE_PCI,
	COA_TYPE_PCMCIA,
};

struct coa_device {
	const struct device		*dev;
	unsigned int			irq;

	enum coa_device_types		type;

	const struct coa_radio_ops	*radio_ops;
	struct coa_freq_map		freq_map;
	struct sc1442x_phase_state	phase_state[DECT_FRAME_SIZE / 2];

	spinlock_t			lock;
	uint				config_base;
	u8 __iomem			*sc1442x_base;
	u16				cfg_reg;
	u16				irq_reg;
	u16				code_base;
	u16				data_base;
	u16				data_mask;

	u8				ctrl;
	u8				led;
};

extern irqreturn_t sc1442x_interrupt(int irq, void *dev_id);
extern const struct dect_transceiver_ops sc1442x_transceiver_ops;

extern int sc1442x_init_device(struct coa_device *dev);
extern void sc1442x_shutdown_device(struct coa_device *dev);

extern void sc1442x_rfdesc_write(const struct coa_device *dev, u16 offset,
				 const u8 *src, u16 length);

#endif
