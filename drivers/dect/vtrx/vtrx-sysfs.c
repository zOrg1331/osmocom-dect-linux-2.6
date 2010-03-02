/*
 * DECT virtual transceiver
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <net/dect/transceiver.h>
#include "vtrx.h"

static struct class *dect_class;

/*
 * Transceivers
 */

#define VTRX_ATTR(_name, _mode, _show, _store)						\
	struct device_attribute vtrx_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define VTRX_NUMERIC_ATTR(name, field, scale)						\
static ssize_t vtrx_show_##name(struct device *dev, struct device_attribute *attr,	\
				char *buf)						\
{											\
	struct dect_vtrx *vtrx = dev_get_drvdata(dev);					\
	return sprintf(buf, "%llu\n",							\
		       (unsigned long long)div64_u64(vtrx->field, scale));		\
}											\
											\
static ssize_t vtrx_store_##name(struct device *dev, struct device_attribute *attr,	\
				 const char *buf, size_t count)				\
{											\
	struct dect_vtrx *vtrx = dev_get_drvdata(dev);					\
	char *ptr;									\
	u32 val;									\
											\
	val = simple_strtoul(buf, &ptr, 10);						\
	if (ptr == buf)									\
		return -EINVAL;								\
	vtrx->field = val * scale;							\
	return count;									\
}											\
static VTRX_ATTR(name, S_IRUGO | S_IWUSR, vtrx_show_##name, vtrx_store_##name)

VTRX_NUMERIC_ATTR(tx_power, tx_power, DECT_VTRX_POWER_SCALE);
VTRX_NUMERIC_ATTR(pos_x, pos_x, 1000);
VTRX_NUMERIC_ATTR(pos_y, pos_y, 1000);

static ssize_t vtrx_store_remove(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct dect_vtrx *vtrx = dev_get_drvdata(dev);

	dect_vtrx_free(vtrx);
	return count;
}

static VTRX_ATTR(remove, S_IWUSR, NULL, vtrx_store_remove);

static struct attribute *vtrx_attrs[] = {
	&vtrx_attr_tx_power.attr,
	&vtrx_attr_pos_x.attr,
	&vtrx_attr_pos_y.attr,
	&vtrx_attr_remove.attr,
	NULL
};

static struct attribute_group vtrx_attr_group = {
	.attrs		= vtrx_attrs,
};

static const struct attribute_group *vtrx_attr_groups[] = {
	&vtrx_attr_group,
	NULL,
};

static void dect_vtrx_release(struct device *dev)
{
	printk("%s\n", __func__);
}

static struct device_type dect_vtrx_group = {
	.name		= "vtrx",
	.groups		= vtrx_attr_groups,
	.release	= dect_vtrx_release,
};

int dect_vtrx_register_sysfs(struct dect_vtrx *vtrx)
{
	struct device *dev = &vtrx->dev;

	dev->type   = &dect_vtrx_group;
	dev->class  = dect_class;
	dev->parent = &vtrx->group->dev;

	dev_set_name(dev, "%s", vtrx->trx->name);
	dev_set_drvdata(dev, vtrx);

	return device_register(dev);
}

void dect_vtrx_unregister_sysfs(struct dect_vtrx *vtrx)
{
	device_del(&vtrx->dev);
}

/*
 * Groups
 */

#define GROUP_ATTR(_name, _mode, _show, _store)						\
	struct device_attribute group_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define GROUP_SHOW(name, field, fmt)							\
static ssize_t group_show_##name(struct device *dev, struct device_attribute *attr,	\
				 char *buf)						\
{											\
	struct dect_vtrx_group *group = dev_get_drvdata(dev);				\
	return sprintf(buf, fmt, group->field);						\
}											\
											\
static ssize_t group_store_##name(struct device *dev, struct device_attribute *attr,	\
				  const char *buf, size_t count)			\
{											\
	struct dect_vtrx_group *group = dev_get_drvdata(dev);				\
	char *ptr;									\
	u32 val;									\
											\
	val = simple_strtoul(buf, &ptr, 10);						\
	if (ptr == buf)									\
		return -EINVAL;								\
	group->field = val;								\
	return count;									\
}											\
static GROUP_ATTR(name, S_IRUGO | S_IWUSR, group_show_##name, group_store_##name)

static ssize_t group_store_new(struct device *dev, struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct dect_vtrx_group *group = dev_get_drvdata(dev);
	int err;

	err = dect_vtrx_init(group);
	return err ? err : count;
}

static GROUP_ATTR(new_trx, S_IWUSR, NULL, group_store_new);

static struct attribute *group_attrs[] = {
	&group_attr_new_trx.attr,
	NULL
};

static struct attribute_group group_attr_group = {
	.attrs		= group_attrs,
};

static const struct attribute_group *group_attr_groups[] = {
	&group_attr_group,
	NULL,
};

static void dect_vtrx_group_release(struct device *dev)
{
	printk("%s\n", __func__);
}

static struct device_type dect_vtrx_group_group = {
	.name		= "vtrx-group",
	.groups		= group_attr_groups,
	.release	= dect_vtrx_group_release,
};

int dect_vtrx_group_register_sysfs(struct dect_vtrx_group *group)
{
	struct device *dev = &group->dev;

	dev->type   = &dect_vtrx_group_group;
	dev->class  = dect_class;
	dev->parent = 0;

	dev_set_name(dev, "%s", group->name);
	dev_set_drvdata(dev, group);

	return device_register(dev);
}

static ssize_t store_new_group(struct class *dev, struct class_attribute *attr,
			       const char *buf, size_t count)
{
	char name[16];

	sscanf(buf, "%16s", name);
	if (!dect_vtrx_group_init(name))
		return -ENOMEM;
	return count;
}

static CLASS_ATTR(new_group, S_IWUSR, NULL, store_new_group);

void dect_vtrx_group_unregister_sysfs(struct dect_vtrx_group *group)
{
	device_del(&group->dev);
}

int dect_vtrx_sysfs_init(void)
{
	int err;

	dect_class = class_create(THIS_MODULE, "dect");
	if (dect_class == NULL)
		return -ENOMEM;

	err = class_create_file(dect_class, &class_attr_new_group);
	if (err < 0)
		class_destroy(dect_class);

	return err;
}

void dect_vtrx_sysfs_exit(void)
{
	class_remove_file(dect_class, &class_attr_new_group);
	class_destroy(dect_class);
}
