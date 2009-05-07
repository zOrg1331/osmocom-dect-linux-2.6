/*
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <net/dect/transceiver.h>

#include "com_on_air.h"

#define PCI_VENDOR_ID_QUICKLOGIC	0x11e3
#define PCI_DEVICE_ID_COA		0x0001

static int __devinit coa_probe(struct pci_dev *pdev,
			       const struct pci_device_id *ent)
{
	struct dect_transceiver *trx;
	struct coa_device *dev;
	void __iomem *base;
	int err;

	err = pci_enable_device(pdev);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to enable PCI device\n");
		goto err1;
	}
	pci_set_master(pdev);

	err = pci_request_regions(pdev, KBUILD_MODNAME);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to obtain PCI resources\n");
		goto err2;
	}

	base = ioremap_nocache(pci_resource_start(pdev, 0),
			       pci_resource_len(pdev, 0));
	if (base == NULL) {
		dev_err(&pdev->dev, "failed to remap PCI resource\n");
		err = -EIO;
		goto err3;
	}

	trx = dect_transceiver_alloc(&sc1442x_transceiver_ops, sizeof(*dev));
	if (trx == NULL) {
		err = -ENOMEM;
		goto err4;
	}
	pci_set_drvdata(pdev, trx);

	dev = dect_transceiver_priv(trx);
	dev->type	  = COA_TYPE_PCI;
	dev->dev	  = &pdev->dev;
	dev->sc1442x_base = base;
	dev->radio_ops    = &coa_u2785_radio_ops;
	dev->data_base	  = 0x0a00;
	dev->data_mask	  = 0x7ff;
	dev->cfg_reg	  = 0x1fe2;
	dev->code_base	  = 0x1a00;

	err = sc1442x_init_device(dev);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to initialize chip\n");
		goto err5;
	}

	err = request_irq(pdev->irq, sc1442x_interrupt, IRQF_SHARED,
			  KBUILD_MODNAME, trx);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to request IRQ%d\n", pdev->irq);
		goto err6;
	}

	dev->irq = pdev->irq;
	err = dect_register_transceiver(trx);
	if (err < 0)
		goto err7;

	return 0;

err7:
	free_irq(pdev->irq, trx);
err6:
	sc1442x_shutdown_device(dev);
err5:
	dect_transceiver_free(trx);
err4:
	iounmap(base);
err3:
	pci_release_regions(pdev);
err2:
	pci_disable_device(pdev);
err1:
	return err;
}

static void __devexit coa_remove(struct pci_dev *pdev)
{
	struct dect_transceiver *trx = pci_get_drvdata(pdev);
	struct coa_device *dev = dect_transceiver_priv(trx);

	sc1442x_shutdown_device(dev);
	free_irq(pdev->irq, trx);
	iounmap(dev->sc1442x_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	dect_unregister_transceiver(trx);
}

static int coa_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct dect_transceiver *trx = pci_get_drvdata(pdev);
	struct coa_device *dev = dect_transceiver_priv(trx);

	sc1442x_shutdown_device(dev);
	pci_save_state(pdev);
	return 0;
}

static int coa_resume(struct pci_dev *pdev)
{
	struct dect_transceiver *trx = pci_get_drvdata(pdev);
	struct coa_device *dev = dect_transceiver_priv(trx);

	pci_restore_state(pdev);
	return sc1442x_init_device(dev);
}

static DEFINE_PCI_DEVICE_TABLE(coa_pci_tbl) = {
	{PCI_DEVICE(PCI_VENDOR_ID_QUICKLOGIC, PCI_DEVICE_ID_COA)},
	{}
};

static struct pci_driver coa_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= coa_pci_tbl,
	.probe		= coa_probe,
	.remove		= __devexit_p(coa_remove),
	.suspend	= coa_suspend,
	.resume		= coa_resume,
};

static int __init coa_pci_init(void)
{
	return pci_register_driver(&coa_driver);
}

static void __exit coa_pci_exit(void)
{
	pci_unregister_driver(&coa_driver);
}

module_init(coa_pci_init);
module_exit(coa_pci_exit);

MODULE_DESCRIPTION("Dosch&Amand COM-ON-AIR PCI driver");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, coa_pci_tbl);
