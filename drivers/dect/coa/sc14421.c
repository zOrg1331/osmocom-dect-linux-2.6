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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/dect.h>
#include <net/dect/dect.h>
#include <net/dect/mac_csf.h>
#include <net/dect/transceiver.h>
#include <asm/io.h>

#include "com_on_air.h"
#include "sc14421_firmware.h"
#include "dip_opcodes.h"

/*
 * The com-on-air devices contain a 2k data RAM and 512b code RAM. The address
 * space is layed out as follows:
 *
 * PCI - size 8k:
 *
 * 0x0a00 - 0x11ff:	data memory
 * 0x1a00 - 0x1bff:	code memory
 * 0x1f00 - 0x1fff:	DIP control and status registers
 *
 * PCMCIA - size 1k:
 *
 * 0x0000 - 0x01ff:	256 bytes memory
 * 0x0200 - 0x02ff:	DIP control and status registers
 *
 * Memory of the PCMCIA device is addressed in 16 bit little endian quantities.
 * To access data or code memory, the corresponding bank needs to be mapped
 * into the memory window.
 *
 * The first bank of the data memory contains DIP specific control data,
 * the remaining banks are used to store packet and slot configuration data.
 */

#define SC14421_DIPSTOPPED		0x80
#define SC14421_RAMBANK0		0x00
#define SC14421_RAMBANK1		0x04
#define SC14421_RAMBANK2		0x08
#define SC14421_RAMBANK3		0x0c
#define SC14421_RAMBANK4		0x10
#define SC14421_RAMBANK5		0x14
#define SC14421_RAMBANK6		0x18
#define SC14421_RAMBANK7		0x1c
#define SC14421_CODEBANK		0x20
#define SC14421_BANKSIZE		0x100

/* Interrupts 0-3 */
#define SC14421_IRQ_SLOT_0_5		0x01
#define SC14421_IRQ_SLOT_6_11		0x02
#define SC14421_IRQ_SLOT_12_17		0x04
#define SC14421_IRQ_SLOT_18_23		0x08
#define SC14421_IRQ_MASK		0x0f

/*
 * Burst Mode Controller control information
 */

/* Maximum number of unmasked errors in S-field bits 8 to 31 */
#define SC14421_BC0_S_ERR_SHIFT		4
/* Invert incoming data (RDI) */
#define SC14421_BC0_INV_RDI		0x08
/* Invert outgoing data (TDO) */
#define SC14421_BC0_INV_TDO		0x04
/* Disable writing B-field on A-field CRC error */
#define SC14421_BC0_SENS_A		0x02
/* PP/FP mode */
#define SC14421_BC0_PP_MODE		0x01

/* Error test mask for S-field bits 15-8 */
#define SC14421_BC1_MASK_MASK		0xff

/* Sliding error test mask for S-field bits 15-8 */
#define SC14421_BC2_SLIDE_MASK		0xff

/* DAC output value when BCM is active (for frequency control?) */
#define SC14421_BC3_DAC_MASK		0x1f

/* Only perform phase jump for correct A-field CRC + SL_EN_ADJ command */
#define SC14421_BC4_ADP			0x10
/* Window in which S-field is accepted */
#define SC14421_BC4_WIN_MASK		0x0f

/* Amplitude-trimming of gaussian shape */
#define SC14421_BC5_VOL_SHIFT		4
/* Disable scrambling */
#define SC14421_BC5_SC_OFF		0x08
/* PD1 synchronization pattern:
 * 0 = S-field received, 1 = preamble + first 2 bits of synchronization word */
#define SC14421_BC5_DO_FR		0x04
/* TDO output shape */
#define SC14421_BC5_TDO_DIGITAL		0x00
#define SC14421_BC5_TDO_GAUSIAN		0x01
#define SC14421_BC5_TDO_POWER_DOWN	0x02
#define SC14421_BC5_TDO_MID_LEVEL	0x03

/* Low 4 bits of multiframe number */
#define SC14421_BC6_MFR_SHIFT		4
#define SC14421_BC6_MFR_MASK		0xf0
/* Frame number */
#define SC14421_BC6_FR_MASK		0x0f

/*
 * Burst Mode Controller status information
 */

/* Peak binary value of ADC (RSSI) */
#define SC14421_ST0_ADC_MASK		0x3f

/* S-pattern recognized according to BMC configuration */
#define SC14421_ST1_IN_SYNC		0x80

/* A-field R-CRC correct */
#define SC14421_ST1_A_CRC		0x40

/* Protected Bn-subfield R-CRC correct */
#define SC14421_ST1_B_CRC_MASK		0x3c
#define SC14421_ST1_B1_CRC		0x20
#define SC14421_ST1_B2_CRC		0x10
#define SC14421_ST1_B3_CRC		0x08
#define SC14421_ST1_B4_CRC		0x04

/* B-field X-CRC correct */
#define SC14421_ST1_X_CRC		0x02

/* Z-field equals X-CRC */
#define SC14421_ST1_Z_CRC		0x01

/* Phase offset of received S-field: which of the nine internal clock cycles
 * per symbol sampled the incoming data. The frequency deviation can be
 * calculated from the difference of the offsets of two consequitive frames as:
 *
 * K * (T / 9) / 10m = K * 96ns / 10m = K * 9.6ppm
 */
#define SC14421_ST2_TAP_SHIFT		4
#define SC14421_ST2_TAP_MASK		0xf0

/* Number of unmasked S-field errors according to BMC configuration */
#define SC14421_ST2_S_ERR_SHIFT		0
#define SC14421_ST2_S_ERR_MASK		0x0f

/* Phase offset of received S-field. */
#define SC14421_ST3_PHASE_MASK		0xff

/* DC offset of received data to comparator reference input (DAC) */
#define SC14421_ST4_DC_MASK		0x3f


static const u8 banktable[] = {
	SC14421_RAMBANK1, 0,
	SC14421_RAMBANK1, 0,
	SC14421_RAMBANK2, 0,
	SC14421_RAMBANK2, 0,
	SC14421_RAMBANK3, 0,
	SC14421_RAMBANK3, 0,
	SC14421_RAMBANK4, 0,
	SC14421_RAMBANK4, 0,
	SC14421_RAMBANK5, 0,
	SC14421_RAMBANK5, 0,
	SC14421_RAMBANK6, 0,
	SC14421_RAMBANK6, 0,
};

static const u8 jumptable[] = {
	JP0, 0,
	JP2, 0,
	JP4, 0,
	JP6, 0,
	JP8, 0,
	JP10, 0,
	JP12, 0,
	JP14, 0,
	JP16, 0,
	JP18, 0,
	JP20, 0,
	JP22, 0
};

static const u8 patchtable[] = {
	PP0, 0,
	PP2, 0,
	PP4, 0,
	PP6, 0,
	PP8, 0,
	PP10, 0,
	PP12, 0,
	PP14, 0,
	PP16, 0,
	PP18, 0,
	PP20, 0,
	PP22, 0
};

static const u8 sc14421_rx_funcs[DECT_PACKET_MAX + 1][DECT_B_MAX + 1] = {
	[DECT_PACKET_P00][DECT_B_NONE]		= RecvP32U,
	[DECT_PACKET_P32][DECT_B_UNPROTECTED]	= RecvP32U,
	[DECT_PACKET_P32][DECT_B_PROTECTED]	= RecvP32P,
};

static const u8 sc14421_tx_funcs[DECT_PACKET_MAX + 1][DECT_B_MAX + 1] = {
	[DECT_PACKET_P00][DECT_B_NONE]		= TransmitP00,
	[DECT_PACKET_P32][DECT_B_UNPROTECTED]	= TransmitP32U,
	[DECT_PACKET_P32][DECT_B_PROTECTED]	= TransmitP32P,
};

/*
 * Raw IO functions
 */
static u8 sc14421_read(const struct coa_device *dev, u16 offset)
{
	switch (dev->type) {
	case COA_TYPE_PCI:
		return readb(dev->sc14421_base + offset);
	case COA_TYPE_PCMCIA:
		return le16_to_cpu(readw(dev->sc14421_base + 2 * offset));
	default:
		BUG();
	}
}

static void sc14421_write(const struct coa_device *dev, u16 offset, u8 value)
{
	switch (dev->type) {
	case COA_TYPE_PCI:
		writeb(value, dev->sc14421_base + offset);
		break;
	case COA_TYPE_PCMCIA:
		writew(cpu_to_le16(value), dev->sc14421_base + 2 * offset);
		break;
	}
}

static void sc14421_stop_dip(struct coa_device *dev)
{
	/* Prevent the interrupt handler from restarting the DIP */
	dev->ctrl = SC14421_DIPSTOPPED;

	/* Stop the DIP and wait for interrupt handler to complete */
	sc14421_write(dev, dev->cfg_reg, SC14421_DIPSTOPPED);
	synchronize_irq(dev->irq);
}

static void sc14421_start_dip(struct coa_device *dev)
{
	dev->ctrl = 0;
	sc14421_write(dev, dev->cfg_reg, 0x00);
}

static void sc14421_switch_to_bank(const struct coa_device *dev, u8 bank)
{
	if (dev->type != COA_TYPE_PCMCIA)
		return;
	sc14421_write(dev, dev->cfg_reg, bank | dev->ctrl);
	/* need to wait for 4 IO cycles */
	inb_p(dev->config_base);
	inb_p(dev->config_base);
	inb_p(dev->config_base);
	inb_p(dev->config_base);
}

/*
 * Code memory IO functions
 */
static void sc14421_write_cmd(const struct coa_device *dev, u16 label,
			      u8 opcode, u8 operand)
{
	sc14421_write(dev, dev->code_base + 2 * label + 0, opcode);
	sc14421_write(dev, dev->code_base + 2 * label + 1, operand);
}

static void sc14421_to_cmem(const struct coa_device *dev,
			    const u8 *src, u16 length)
{
	u16 i;

	for (i = 0; i < length; i++)
		sc14421_write(dev, dev->code_base + i, src[i]);
}

/*
 * Data memory IO functions
 */
static inline u8 sc14421_dread(const struct coa_device *dev, u16 offset)
{
	return sc14421_read(dev, dev->data_base + (offset & dev->data_mask));
}

static inline void sc14421_dwrite(const struct coa_device *dev,
				  u16 offset, u8 value)
{
	sc14421_write(dev, dev->data_base + (offset & dev->data_mask), value);
}

static void sc14421_to_dmem(const struct coa_device *dev, u16 offset,
			    const u8 *src, u16 length)
{
	u16 i;

	for (i = 0; i < length; i++)
		sc14421_dwrite(dev, offset + i, src[i]);
}

static void sc14421_from_dmem(const struct coa_device *dev, u8 *dst,
			      u16 offset, u16 length)
{
	u16 i;

	for (i = 0; i < length; i++)
		dst[i] = sc14421_dread(dev, offset + i);
}

static u16 sc14421_slot_offset(u8 slot)
{
	u16 offset;

	offset = SC14421_BANKSIZE + slot / 4 * SC14421_BANKSIZE;
	if (slot & 0x2)
		offset += SC14421_BANKSIZE / 2;
	return offset;
}

void sc14421_rfdesc_write(const struct coa_device *dev, u16 offset,
			  const u8 *src, u16 length)
{
	sc14421_to_dmem(dev, offset + RF_DESC, src, length);
}

/*
 * Transceiver operations
 */

static void sc14421_disable(const struct dect_transceiver *trx)
{
	sc14421_stop_dip(dect_transceiver_priv(trx));
}

static void sc14421_enable(const struct dect_transceiver *trx)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);
	u8 slot;

	/* Restore slot table to a pristine state */
	sc14421_switch_to_bank(dev, SC14421_CODEBANK);
	for (slot = 0; slot < DECT_FRAME_SIZE; slot += 2)
		sc14421_write_cmd(dev, patchtable[slot], WNT, 2);

	if (trx->mode == DECT_TRANSCEIVER_MASTER)
		sc14421_write_cmd(dev, RFStart, BR, SlotTable);
	else {
		sc14421_write_cmd(dev, RFStart, BR, SyncInit);
		sc14421_write_cmd(dev, SyncLoop, BR, Sync);
	}

	sc14421_start_dip(dect_transceiver_priv(trx));
}

static void sc14421_confirm(const struct dect_transceiver *trx)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);

	/*
	 * This locks the firmware into a cycle where it will receive every
	 * 24th slot. This must happen within the time it takes to transmit
	 * 22 slots after the interrupt to lock to the correct signal.
	 */
	sc14421_switch_to_bank(dev, SC14421_CODEBANK);
	sc14421_write_cmd(dev, SyncLoop, BR, SyncLock);
}

static void sc14421_unlock(const struct dect_transceiver *trx)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);

	/* Restore jump into Sync loop */
	sc14421_switch_to_bank(dev, SC14421_CODEBANK);
	sc14421_write_cmd(dev, SyncLoop, BR, Sync);
}

static void sc14421_lock(const struct dect_transceiver *trx, u8 slot)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);

	/*
	 * We're receiving the single slot "slot". Adjust the firmware so it
	 * will jump into the correct slottable position on the next receive
	 * event. This will automagically establish the correct slot numbers
	 * and thereby interrupt timing for all slots.
	 */
	sc14421_switch_to_bank(dev, SC14421_CODEBANK);
	sc14421_write_cmd(dev, SyncLoop, BR, jumptable[slot]);
}

static void sc14421_set_mode(const struct dect_transceiver *trx,
			     const struct dect_channel_desc *chd,
			     enum dect_slot_states mode)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);
	u8 slot = chd->slot;
	u16 off;

	switch (mode) {
	case DECT_SLOT_IDLE:
		sc14421_switch_to_bank(dev, SC14421_CODEBANK);
		sc14421_write_cmd(dev, patchtable[slot], WNT, 2);
		break;
	case DECT_SLOT_SCANNING:
	case DECT_SLOT_RX:
		sc14421_switch_to_bank(dev, banktable[slot]);
		off = sc14421_slot_offset(slot);
		dev->radio_ops->rx_init(dev, off);

		sc14421_switch_to_bank(dev, SC14421_CODEBANK);
		sc14421_write_cmd(dev, patchtable[slot], JMP,
				  sc14421_rx_funcs[chd->pkt][chd->b_fmt]);
		break;
	case DECT_SLOT_TX:
		sc14421_switch_to_bank(dev, banktable[slot]);
		off = sc14421_slot_offset(slot);
		dev->radio_ops->tx_init(dev, off);

		sc14421_switch_to_bank(dev, SC14421_CODEBANK);
		sc14421_write_cmd(dev, patchtable[slot], JMP,
				  sc14421_tx_funcs[chd->pkt][chd->b_fmt]);
		break;
	}
}

static void sc14421_set_carrier(const struct dect_transceiver *trx,
				u8 slot, u8 carrier)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);
	const struct dect_transceiver_slot *ts = &trx->slots[slot];
	u16 off;

	WARN_ON(ts->state == DECT_SLOT_IDLE);

	sc14421_switch_to_bank(dev, banktable[slot]);
	off = sc14421_slot_offset(slot);
	dev->radio_ops->set_carrier(dev, off, ts->state, carrier);
}

static u64 sc14421_set_band(const struct dect_transceiver *trx,
			    const struct dect_band *band)
{
	struct coa_device *dev = dect_transceiver_priv(trx);

	return dev->radio_ops->map_band(dev, band);
}

static void sc14421_tx(const struct dect_transceiver *trx, struct sk_buff *skb)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);
	u8 slot = DECT_TRX_CB(skb)->slot;
	u16 off;

	sc14421_switch_to_bank(dev, banktable[slot]);
	off = sc14421_slot_offset(slot);

	sc14421_to_dmem(dev, off + SD_PREAMBLE_OFF,
			skb_mac_header(skb), skb->mac_len);
	sc14421_to_dmem(dev, off + SD_DATA_OFF, skb->data, skb->len);
	sc14421_dwrite(dev, off + TX_DESC + TRX_DESC_FN,
		       DECT_TRX_CB(skb)->frame);

	kfree_skb(skb);
}

const struct dect_transceiver_ops sc14421_transceiver_ops = {
	.name			= "sc14421",
	.slotmask		= 0x555555,
	.eventrate		= 6,
	.latency		= 6,
	.disable		= sc14421_disable,
	.enable			= sc14421_enable,
	.confirm		= sc14421_confirm,
	.unlock			= sc14421_unlock,
	.lock			= sc14421_lock,
	.set_mode		= sc14421_set_mode,
	.set_carrier		= sc14421_set_carrier,
	.set_band		= sc14421_set_band,
	.tx			= sc14421_tx,
	.destructor		= dect_transceiver_free,
};
EXPORT_SYMBOL_GPL(sc14421_transceiver_ops);

static u8 sc14421_clear_interrupt(const struct coa_device *dev)
{
	u8 int1, int2, cnt = 0;

	int1 = sc14421_read(dev, dev->cfg_reg);
	/* is the card still plugged? */
	if (int1 == 0xff)
		return 0;

	int2 = int1 & SC14421_IRQ_MASK;

	/* Clear interrupt status before checking for any remaining events */
	if (int2 && dev->type == COA_TYPE_PCI)
		sc14421_write(dev, 0x1f02, 0x80);

	while (int1) {
		cnt++;
		if (cnt > 254) {
			int2 = 0;
			break;
		}

		int1 = sc14421_read(dev, dev->cfg_reg) & SC14421_IRQ_MASK;
		int2 |= int1;
	}

	return int2 & SC14421_IRQ_MASK;
}

static void sc14421_process_slot(const struct coa_device *dev,
				 struct dect_transceiver *trx,
				 struct dect_transceiver_event *event,
				 u8 slot)
{
	struct dect_transceiver_slot *ts = &trx->slots[slot];
	struct sk_buff *skb;
	u16 off;
	u8 rssi;

	if (ts->state == DECT_SLOT_IDLE || ts->state == DECT_SLOT_TX)
		return;

	sc14421_switch_to_bank(dev, banktable[slot]);
	off = sc14421_slot_offset(slot);

	/*
	 * The SC14421 contains a 6 bit ADC for RSSI measurement, convert to
	 * units used by the stack.
	 */
	rssi = sc14421_dread(dev, off + SD_RSSI_OFF) * DECT_RSSI_RANGE / 63;

	/* validate and clear checksum */
	if ((sc14421_dread(dev, off + SD_CSUM_OFF) & 0xc0) != 0xc0)
		goto out;
	sc14421_dwrite(dev, off + SD_CSUM_OFF, 0);

	skb = dect_transceiver_alloc_skb(trx, slot);
	if (skb == NULL)
		goto out;
	sc14421_from_dmem(dev, skb->data, off + SD_DATA_OFF, skb->len);
	DECT_TRX_CB(skb)->rssi = rssi;
	__skb_queue_tail(&event->rx_queue, skb);

	ts->rx_bytes += skb->len;
	ts->rx_packets++;
out:
	ts->rssi = dect_average_rssi(ts->rssi, rssi);
	dect_transceiver_record_rssi(event, slot, rssi);

	/* Update frame number for next reception */
	sc14421_dwrite(dev, off + RX_DESC + TRX_DESC_FN,
	       dect_next_framenum(trx->cell->timer_base[DECT_TIMER_RX].framenum));
}

irqreturn_t sc14421_interrupt(int irq, void *dev_id)
{
	struct dect_transceiver *trx = dev_id;
	struct coa_device *dev = dect_transceiver_priv(trx);
	struct dect_transceiver_event *event;
	u8 slot, i;

	irq = sc14421_clear_interrupt(dev);
	if (!irq)
		return IRQ_NONE;

	if (unlikely(hweight8(irq) != 1))
		dev_info(dev->dev, "lost some interrupts\n");

	for (i = 0; i < 4; i++) {
		if (!(irq & (1 << i)))
			continue;

		event = dect_transceiver_event(trx, i % 2, i * 6);
		if (event == NULL)
			goto out;

		for (slot = 6 * i; slot < 6 * (i + 1); slot += 2)
			sc14421_process_slot(dev, trx, event, slot);

		dect_transceiver_queue_event(trx, event);
	}
out:
	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(sc14421_interrupt);

static void sc14421_write_bmc_config(const struct coa_device *dev,
				     u16 off, bool pp, bool tx)
{
	u8 cfg;

	cfg  = 2 << SC14421_BC0_S_ERR_SHIFT;
	cfg |= SC14421_BC0_INV_TDO;
	cfg |= SC14421_BC0_SENS_A;
	if (pp && !tx)
		cfg |= SC14421_BC0_PP_MODE;
	sc14421_dwrite(dev, off + 0, cfg);

	/* S-field error mask */
	sc14421_dwrite(dev, off + 1, 0);
	/* S-field sliding window error mask */
	sc14421_dwrite(dev, off + 2, 0x3f);

	/* DAC output */
	sc14421_dwrite(dev, off + 3, 0);

	cfg  = SC14421_BC4_ADP;
	cfg |= 0xf;
	cfg |= 0x80;
	sc14421_dwrite(dev, off + 4, cfg);

	cfg  = SC14421_BC5_DO_FR;
	cfg |= tx ? SC14421_BC5_TDO_DIGITAL : SC14421_BC5_TDO_POWER_DOWN;
	sc14421_dwrite(dev, off + 5, cfg);

	/* Frame number */
	sc14421_dwrite(dev, off + 6, 0);
}

static void sc14421_init_slot(const struct coa_device *dev, u8 slot)
{
	u16 off;

	sc14421_switch_to_bank(dev, banktable[slot]);
	off = sc14421_slot_offset(slot);
	sc14421_write_bmc_config(dev, off + TX_DESC, slot < 12, true);
	sc14421_write_bmc_config(dev, off + RX_DESC, slot < 12, false);
	dev->radio_ops->rx_init(dev, off);
}

static int sc14421_check_dram(const struct coa_device *dev)
{
	unsigned int bank, i;
	unsigned int cnt;
	u16 off;
	u8 val;

	for (bank = 0; bank < 8; bank++) {
		sc14421_switch_to_bank(dev, 4 * bank);

		off = bank * SC14421_BANKSIZE;
		for (i = 0; i < SC14421_BANKSIZE - 2; i++)
			sc14421_dwrite(dev, off + i, bank + i);
	}

	cnt = 0;
	for (bank = 0; bank < 8; bank++) {
		sc14421_switch_to_bank(dev, 4 * bank);

		off = bank * SC14421_BANKSIZE;
		for (i = 0; i < SC14421_BANKSIZE - 2; i++) {
			val = sc14421_dread(dev, off + i);
			if (val != ((bank + i) & 0xff)) {
				dev_err(dev->dev,
					"memory error bank %.2x offset %.2x: "
					"%.2x != %.2x\n", bank, i,
					val, (bank + i) & 0xff);
				cnt++;
			}
			sc14421_dwrite(dev, off + i, 0);
		}
	}

	if (cnt > 0)
		dev_err(dev->dev, "found %u memory r/w errors\n", cnt);
	return cnt ? -1 : 0;
}

int sc14421_init_device(struct coa_device *dev)
{
	u8 slot;

	dev->ctrl = SC14421_DIPSTOPPED;

	if (sc14421_check_dram(dev) < 0)
		return -EIO;

	dev_info(dev->dev, "Loading firmware ...\n");
	sc14421_switch_to_bank(dev, SC14421_CODEBANK);
	sc14421_to_cmem(dev, sc14421_firmware, sizeof(sc14421_firmware));

	sc14421_clear_interrupt(dev);

	/* Init DIP */
	sc14421_switch_to_bank(dev, SC14421_RAMBANK0);
	sc14421_write_bmc_config(dev, DIP_RF_INIT, false, false);
	for (slot = 0; slot < DECT_FRAME_SIZE; slot += 2)
		sc14421_init_slot(dev, slot);

	/* Enable interrupts */
	if (dev->type == COA_TYPE_PCI)
		sc14421_write(dev, 0x1f06, 0x70);

	return 0;
}
EXPORT_SYMBOL_GPL(sc14421_init_device);

void sc14421_shutdown_device(struct coa_device *dev)
{
	sc14421_stop_dip(dev);
}
EXPORT_SYMBOL_GPL(sc14421_shutdown_device);

MODULE_LICENSE("GPL");
