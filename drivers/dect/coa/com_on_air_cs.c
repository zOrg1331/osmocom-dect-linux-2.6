/*
 * com_on_air_cs - basic driver for the Dosch and Amand "com on air" cards
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
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/crc32.h>
#include <net/dect/transceiver.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ciscode.h>
#include <pcmcia/ds.h>
#include <pcmcia/cisreg.h>

#include "com_on_air.h"

MODULE_AUTHOR("Matthias Wenzel comonair<a>mazzoo.de;"
              "Andreas Schuler dect<a>badterrorist.com");
MODULE_DESCRIPTION("Dosch&Amand COM-ON-AIR PCMCIA driver");
MODULE_LICENSE("GPL");

static int get_card_id(const struct pcmcia_device *link);

static int com_on_air_probe(struct pcmcia_device *link)
{
	struct dect_transceiver *trx;
	struct coa_device *dev;
	win_req_t req;
	int err;

	trx = dect_transceiver_alloc(&sc1442x_transceiver_ops, sizeof(*dev));
	if (!trx) {
		err = -ENOMEM;
		goto err1;
	}

	link->priv = trx;
	dev = dect_transceiver_priv(trx);
	dev->type      = COA_TYPE_PCMCIA;
	dev->code_base = 0x0;
	dev->data_base = 0x0;
	dev->data_mask = 0x0ff;
	dev->cfg_reg   = 0x1ff;
	dev->irq_reg   = 0x0;
	dev->dev       = &link->dev;

	dev_info(dev->dev, "%s %s %s %s\n", link->prod_id[0], link->prod_id[1],
		 link->prod_id[2] ? : "", link->prod_id[3] ? : "");

	link->io.Attributes1	= IO_DATA_PATH_WIDTH_AUTO;
	link->io.NumPorts1	= 16;
	link->io.Attributes2	= 0;

	link->conf.Attributes	= CONF_ENABLE_IRQ;
	link->conf.IntType	= INT_MEMORY_AND_IO;
	link->conf.ConfigIndex	= 1;
	link->conf.Present	= PRESENT_OPTION;
	link->conf.ConfigBase	= 0x1020;

	req.Attributes		= WIN_DATA_WIDTH_16 | WIN_ENABLE;
	req.Base		= 0;
	req.Size		= 0x1000;
	req.AccessSpeed		= 500;

	err = pcmcia_request_window(link, &req, &link->win);
	if (err < 0) {
		dev_err(dev->dev, "failed to obtain PCMCIA window\n");
		goto err2;
	}

	dev->sc1442x_base = ioremap_nocache(req.Base, req.Size);
	if (!dev->sc1442x_base) {
		dev_err(dev->dev, "failed to remap PCMCIA resource\n");
		err = -EIO;
		goto err3;
	}

	link->conf.Present      = PRESENT_OPTION;
	link->socket->functions = 0;

	err = pcmcia_request_irq(link, sc1442x_interrupt);
	if (err < 0) {
		dev_err(dev->dev, "failed to request IRQ%d\n", link->irq);
		goto err4;
	}

	err = pcmcia_request_configuration(link, &link->conf);
	if (err < 0) {
		dev_err(dev->dev, "failed to obtain PCMCIA configuration\n");
		goto err5;
	}

	dev_dbg(dev->dev, "%svalid client.\n", (link->conf.Attributes) ? "":"in");
	dev_dbg(dev->dev, "Type          0x%x\n", link->socket->state);
	dev_dbg(dev->dev, "Function      0x%x\n", link->func);
	dev_dbg(dev->dev, "Attributes    %d\n", link->conf.Attributes);
	dev_dbg(dev->dev, "IntType       %d\n", link->conf.IntType);
	dev_dbg(dev->dev, "ConfigBase    0x%x\n", link->conf.ConfigBase);
	dev_dbg(dev->dev, "Status %u, Pin %u, Copy %u, ExtStatus %u\n",
		link->conf.Status, link->conf.Pin,
		link->conf.Copy, link->conf.ExtStatus);

	dev_dbg(dev->dev, "Present       %d\n", link->conf.Present);
	dev_dbg(dev->dev, "IRQ           0x%x\n", link->irq);
	dev_dbg(dev->dev, "BasePort1     0x%x\n", link->io.BasePort1);
	dev_dbg(dev->dev, "NumPorts1     0x%x\n", link->io.NumPorts1);
	dev_dbg(dev->dev, "Attributes1   0x%x\n", link->io.Attributes1);
	dev_dbg(dev->dev, "BasePort2     0x%x\n", link->io.BasePort2);
	dev_dbg(dev->dev, "NumPorts2     0x%x\n", link->io.NumPorts2);
	dev_dbg(dev->dev, "Attributes2   0x%x\n", link->io.Attributes2);
	dev_dbg(dev->dev, "IOAddrLines   0x%x\n", link->io.IOAddrLines);
	dev_dbg(dev->dev, "has%s function_config\n",
		link->function_config ? "":" no");

	switch (get_card_id(link)) {
	case 0:
	case 3:
		dev->radio_ops = &coa_u2785_radio_ops;
		break;
	case 1:
	case 2:
		dev->radio_ops = &coa_lmx3161_radio_ops;
		break;
	default:
		dev_err(dev->dev, "unknown radio type\n");
		err = -EINVAL;
		goto err5;
	}

	dev_info(dev->dev, "Radio type %s\n", dev->radio_ops->type);

	dev->irq	 = link->irq;
	dev->config_base = link->conf.ConfigBase;
	err = sc1442x_init_device(dev);
	if (err < 0)
		goto err5;

	err = dect_register_transceiver(trx);
	if (err < 0)
		goto err6;

	return 0;

err6:
	sc1442x_shutdown_device(dev);
err5:
	pcmcia_disable_device(link);
err4:
	iounmap(dev->sc1442x_base);
err3:
	pcmcia_release_window(link, link->win);
err2:
	dect_transceiver_free(trx);
err1:
	return err;
}

static void com_on_air_remove(struct pcmcia_device *link)
{
	struct dect_transceiver *trx = link->priv;
	struct coa_device *dev = dect_transceiver_priv(trx);

	sc1442x_shutdown_device(dev);
	iounmap(dev->sc1442x_base);
	pcmcia_disable_device(link);
	dect_unregister_transceiver(trx);
}

static int com_on_air_suspend(struct pcmcia_device *link)
{
	struct dect_transceiver *trx = link->priv;
	struct coa_device *dev = dect_transceiver_priv(trx);

	sc1442x_shutdown_device(dev);
	return 0;
}

static int com_on_air_resume(struct pcmcia_device *link)
{
	struct dect_transceiver *trx = link->priv;
	struct coa_device *dev = dect_transceiver_priv(trx);

	return sc1442x_init_device(dev);
}

static struct pcmcia_device_id com_on_air_ids[] = {
	/*
	 * The crc32 hashes below are generated by the tool in
	 * Documentation/pcmcia/devicetable.txt
	 */
	PCMCIA_DEVICE_PROD_ID12  ("DECTDataDevice", "PCMCIA F22",
			           0x11fe69e9,       0x253670b2),
	PCMCIA_DEVICE_PROD_ID12  ("DECTDataDevice", "PCMCIA",
			           0x11fe69e9,       0x281f1c5d),
	PCMCIA_DEVICE_PROD_ID1234("DOSCH-AMAND",    "MMAP PCMCIA",
			          "MXM500",         "V1.00",
				   0x4bc552e7,       0x0df519bb,
				   0x09e43c7c,       0x3488c81a),
	PCMCIA_DEVICE_PROD_ID12  ("DECTVoIPDevice", "PCMCIA DA099",
				   0xeabb0be4,       0xd7b915fe),
#if 0
	There are more devices out there, I only own the above three.
	an excerpt from win32 dna.inf:

%String1%=pcmcia.install,PCMCIA\DOSCH-AMAND-MMAP_PCMCIA-C7D7
%String1%=pcmcia.install,PCMCIA\Dosch-Amand-DECT_MultiMedia-BD0D
%String1%=pcmcia.install,PCMCIA\DOSCH_&_AMAND-DECT_MULTIMEDIA-1A9F
%String1%=pcmcia.install,PCMCIA\DECTDataDevice-F13-6433
%String1%=pcmcia.install,PCMCIA\DECTDataDevice-PCMCIA-0EF8
%String4%=pci.install,PCI\VEN_11E3&DEV_0001&SUBSYS_000111E3&REV_00
%String4%=pci.install,PCI\VEN_11E3&DEV_0001&SUBSYS_00011786&REV_32
%String4%=pci.install,PCI\VEN_1786&DEV_0001&SUBSYS_000111E3&REV_00
%String5%=freekey2.install,PCMCIA\DECTDataDevice-PCMCIA-FEF2
%String6%=freekey2.install,PCMCIA\DECTDataDevice-PCMCIA_F22-4BD3
%String6%=freekey2.install,PCMCIA\DECTDataDevice-PCMCIA_F22-BBD9

#endif
	PCMCIA_DEVICE_NULL
};

MODULE_DEVICE_TABLE(pcmcia, com_on_air_ids);

/* returns an index into com_on_air_ids[] */
static int get_card_id(const struct pcmcia_device *link)
{
	u32 hash[4] = {};
	unsigned int i;

	for (i = 0; i < 4; i++) {
		if (link->prod_id[i] == NULL)
			continue;
		hash[i] = crc32(0, link->prod_id[i], strlen(link->prod_id[i]));
	}

	for (i = 0; i < ARRAY_SIZE(com_on_air_ids) - 1; i++) {
		if ((hash[0] == com_on_air_ids[i].prod_id_hash[0]) &&
		    (hash[1] == com_on_air_ids[i].prod_id_hash[1]) &&
		    (hash[2] == com_on_air_ids[i].prod_id_hash[2]) &&
		    (hash[3] == com_on_air_ids[i].prod_id_hash[3]))
			return i;
	}
	return -1;
}

static struct pcmcia_driver coa_driver = {
	.owner		= THIS_MODULE,
	.drv.name	= KBUILD_MODNAME,
	.probe		= com_on_air_probe,
	.remove		= com_on_air_remove,
	.suspend	= com_on_air_suspend,
	.resume		= com_on_air_resume,
	.id_table	= com_on_air_ids,
};

static int __init init_com_on_air_cs(void)
{
	return pcmcia_register_driver(&coa_driver);
}

static void __exit exit_com_on_air_cs(void)
{
	pcmcia_unregister_driver(&coa_driver);
}

module_init(init_com_on_air_cs);
module_exit(exit_com_on_air_cs);
