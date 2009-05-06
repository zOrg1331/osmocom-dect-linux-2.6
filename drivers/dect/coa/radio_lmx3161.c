/*
 * radio_lmx3161 - NSC LMX3161 Single Chip Radio Transceiver radio operations
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dect.h>
#include <net/dect/dect.h>
#include <net/dect/transceiver.h>

#include "com_on_air.h"

/* Intermediate frequency */
#define RADIO_LMX3161_FREQ_IF	110592	/* kHz */

/*
 * Control Bits
 */

/* N-counter */
#define RADIO_LMX3161_CTRL_N	0x0
/* R-counter */
#define RADIO_LMX3161_CTRL_R	0x2
/* F-latch */
#define RADIO_LMX3161_CTRL_F	0x1

/*
 * Function Register (18 bit F-latch)
 */

/* Prescaler modules select */
#define RADIO_LMX3161_PRESCALER_32_33
#define RADIO_LMX3161_PRESCALER_64_65
/* Phase detector polarity: 0 = negative, 1 = positive */
#define RADIO_LMX3161_PD		(1 << 3)
/* Charge pump current gain select: 0 = LOW (1*I_cpo), 1 = high (4*I_cpo) */
#define RADIO_LMX3161_CP		(1 << 4)
/* tri-state charge pump output: 0 = normal, 1 = tri-state */
#define RADIO_LMX3161_CP_TRISTATE	(1 << 5)
/* Receive chain power down control: 0 = power up, 1 = power down */
#define RADIO_LMX3161_RX_POWER		(1 << 7)
/* Transmit chain power down control: 0 = power up, 1 = power down */
#define RADIO_LMX3161_TX_POWER		(1 << 8)
/* Out 0 CMOS output: 0 = low, 1 = high */
#define RADIO_LMX3161_CMOS0A		(1 << 9)
/* Out 1 CMOS output: 0 = low, 1 = high */
#define RADIO_LMX3161_CMOS1		(1 << 10)
/* Out 2 CMOS output: 0 = low, 1 = high */
#define RADIO_LMX3161_CMOS2		(1 << 11)
/* Power down mode select: */
#define RADIO_LMX3161_POWER_DOWN_MASK		(0x3 << 12)
#define RADIO_LMX3161_POWER_DOWN_SW		0
#define RADIO_LMX3161_POWER_DOWN_HARDWIRE	(0x3 << 12)
/* Demodulator gain select */
/* Demodulator DC level shifting polarity */
/* Demodulator DC level shift */

static u64 lmx3161_map_band(struct coa_device *dev, const struct dect_band *band)
{
	struct coa_freq_map_entry *fe;
	u32 frequency;
	u8 carrier;

	for (carrier = 0; carrier < band->carriers; carrier++) {
		frequency = band->frequency[carrier];
		fe = &dev->freq_map.carrier[carrier];
	}
	return 0;
}

const struct coa_radio_ops coa_lmx3161_radio_ops = {
	.type		= "LMX3161",
	.rx_init	= NULL,
	.tx_init	= NULL,
	.set_carrier	= NULL,
	.map_band	= lmx3161_map_band,
};
EXPORT_SYMBOL_GPL(coa_lmx3161_radio_ops);
