/*
 * RAM Oops/Panic logger
 *
 * Copyright (C) 2010 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright (C) 2011 Kees Cook <keescook@chromium.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/pstore.h>
#include <linux/time.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/pstore_ram.h>

#define RAMOOPS_KERNMSG_HDR "===="
#define MIN_MEM_SIZE 4096UL

static ulong record_size = MIN_MEM_SIZE;
module_param(record_size, ulong, 0400);
MODULE_PARM_DESC(record_size,
		"size of each dump done on oops/panic");

static ulong ramoops_console_size = MIN_MEM_SIZE;
module_param_named(console_size, ramoops_console_size, ulong, 0400);
MODULE_PARM_DESC(console_size, "size of kernel console log");

static ulong mem_address;
module_param(mem_address, ulong, 0400);
MODULE_PARM_DESC(mem_address,
		"start of reserved RAM used to store oops/panic logs");

static ulong mem_size;
module_param(mem_size, ulong, 0400);
MODULE_PARM_DESC(mem_size,
		"size of reserved RAM used to store oops/panic logs");

static int dump_oops = 1;
module_param(dump_oops, int, 0600);
MODULE_PARM_DESC(dump_oops,
		"set to 1 to dump oopses, 0 to only dump panics (default 1)");

static int ramoops_ecc;
module_param_named(ecc, ramoops_ecc, int, 0600);
MODULE_PARM_DESC(ramoops_ecc,
		"set to 1 to enable ECC support");

struct ramoops_context {
	struct persistent_ram_zone **przs;
	struct persistent_ram_zone *cprz;
	phys_addr_t phys_addr;
	unsigned long size;
	size_t record_size;
	size_t console_size;
	int dump_oops;
	bool ecc;
	unsigned int max_dump_cnt;
	unsigned int dump_write_cnt;
	unsigned int dump_read_cnt;
	unsigned int console_read_cnt;
	struct pstore_info pstore;
};

static struct platform_device *dummy;
static struct ramoops_platform_data *dummy_data;

static int ramoops_pstore_open(struct pstore_info *psi)
{
	struct ramoops_context *cxt = psi->data;

	cxt->dump_read_cnt = 0;
	cxt->console_read_cnt = 0;
	return 0;
}

static struct persistent_ram_zone *
ramoops_get_next_prz(struct persistent_ram_zone *przs[], uint *c, uint max,
		     u64 *id,
		     enum pstore_type_id *typep, enum pstore_type_id type,
		     bool update)
{
	struct persistent_ram_zone *prz;
	int i = (*c)++;

	if (i >= max)
		return NULL;

	prz = przs[i];

	if (update) {
		/* Update old/shadowed buffer. */
		persistent_ram_save_old(prz);
		if (!persistent_ram_old_size(prz))
			return NULL;
	}

	*typep = type;
	*id = i;

	return prz;
}

static ssize_t ramoops_pstore_read(u64 *id, enum pstore_type_id *type,
				   struct timespec *time,
				   char **buf,
				   struct pstore_info *psi)
{
	ssize_t size;
	struct ramoops_context *cxt = psi->data;
	struct persistent_ram_zone *prz;

	prz = ramoops_get_next_prz(cxt->przs, &cxt->dump_read_cnt,
				   cxt->max_dump_cnt, id, type,
				   PSTORE_TYPE_DMESG, 1);
	if (!prz)
		prz = ramoops_get_next_prz(&cxt->cprz, &cxt->console_read_cnt,
					   1, id, type, PSTORE_TYPE_CONSOLE, 0);
	if (!prz)
		return 0;

	/* TODO(kees): Bogus time for the moment. */
	time->tv_sec = 0;
	time->tv_nsec = 0;

	size = persistent_ram_old_size(prz);
	*buf = kmalloc(size, GFP_KERNEL);
	if (*buf == NULL)
		return -ENOMEM;
	memcpy(*buf, persistent_ram_old(prz), size);

	return size;
}

static size_t ramoops_write_kmsg_hdr(struct persistent_ram_zone *prz)
{
	char *hdr;
	struct timeval timestamp;
	size_t len;

	do_gettimeofday(&timestamp);
	hdr = kasprintf(GFP_ATOMIC, RAMOOPS_KERNMSG_HDR "%lu.%lu\n",
		(long)timestamp.tv_sec, (long)timestamp.tv_usec);
	WARN_ON_ONCE(!hdr);
	len = hdr ? strlen(hdr) : 0;
	persistent_ram_write(prz, hdr, len);
	kfree(hdr);

	return len;
}

static int ramoops_pstore_write(enum pstore_type_id type,
				enum kmsg_dump_reason reason,
				u64 *id,
				unsigned int part,
				size_t size, struct pstore_info *psi)
{
	struct ramoops_context *cxt = psi->data;
	struct persistent_ram_zone *prz = cxt->przs[cxt->dump_write_cnt];
	size_t hlen;

	if (type == PSTORE_TYPE_CONSOLE) {
		if (!cxt->cprz)
			return -ENOMEM;
		persistent_ram_write(cxt->cprz, cxt->pstore.buf, size);
		return 0;
	}

	if (type != PSTORE_TYPE_DMESG)
		return -EINVAL;

	/* Out of the various dmesg dump types, ramoops is currently designed
	 * to only store crash logs, rather than storing general kernel logs.
	 */
	if (reason != KMSG_DUMP_OOPS &&
	    reason != KMSG_DUMP_PANIC)
		return -EINVAL;

	/* Skip Oopes when configured to do so. */
	if (reason == KMSG_DUMP_OOPS && !cxt->dump_oops)
		return -EINVAL;

	/* Explicitly only take the first part of any new crash.
	 * If our buffer is larger than kmsg_bytes, this can never happen,
	 * and if our buffer is smaller than kmsg_bytes, we don't want the
	 * report split across multiple records.
	 */
	if (part != 1)
		return -ENOSPC;

	hlen = ramoops_write_kmsg_hdr(prz);
	if (size + hlen > prz->buffer_size)
		size = prz->buffer_size - hlen;
	persistent_ram_write(prz, cxt->pstore.buf, size);

	cxt->dump_write_cnt = (cxt->dump_write_cnt + 1) % cxt->max_dump_cnt;

	return 0;
}

static int ramoops_pstore_erase(enum pstore_type_id type, u64 id,
				struct pstore_info *psi)
{
	struct ramoops_context *cxt = psi->data;
	struct persistent_ram_zone *prz;

	switch (type) {
	case PSTORE_TYPE_DMESG:
		if (id >= cxt->max_dump_cnt)
			return -EINVAL;
		prz = cxt->przs[id];
		break;
	case PSTORE_TYPE_CONSOLE:
		prz = cxt->cprz;
		break;
	default:
		return -EINVAL;
	}

	persistent_ram_free_old(prz);
	persistent_ram_zap(prz);

	return 0;
}

static struct ramoops_context oops_cxt = {
	.pstore = {
		.owner	= THIS_MODULE,
		.name	= "ramoops",
		.open	= ramoops_pstore_open,
		.read	= ramoops_pstore_read,
		.write	= ramoops_pstore_write,
		.erase	= ramoops_pstore_erase,
	},
};

static void ramoops_free_przs(struct ramoops_context *cxt)
{
	int i;

	if (!cxt->przs)
		return;

	for (i = 0; cxt->przs[i]; i++)
		persistent_ram_free(cxt->przs[i]);
	kfree(cxt->przs);
}

static int ramoops_init_przs(struct device *dev, struct ramoops_context *cxt,
			      phys_addr_t *paddr, size_t dump_mem_sz)
{
	int err = -ENOMEM;
	int i;

	if (!cxt->record_size)
		return 0;

	cxt->max_dump_cnt = dump_mem_sz / cxt->record_size;
	if (!cxt->max_dump_cnt)
		return -ENOMEM;

	cxt->przs = kzalloc(sizeof(*cxt->przs) * cxt->max_dump_cnt,
			     GFP_KERNEL);
	if (!cxt->przs) {
		dev_err(dev, "failed to initialize a prz array for dumps\n");
		return -ENOMEM;
	}

	for (i = 0; i < cxt->max_dump_cnt; i++) {
		size_t sz = cxt->record_size;

		cxt->przs[i] = persistent_ram_new(*paddr, sz, cxt->ecc);
		if (IS_ERR(cxt->przs[i])) {
			err = PTR_ERR(cxt->przs[i]);
			dev_err(dev, "failed to request mem region (0x%zx@0x%llx): %d\n",
				sz, (unsigned long long)*paddr, err);
			goto fail_prz;
		}
		*paddr += sz;
	}

	return 0;
fail_prz:
	ramoops_free_przs(cxt);
	return err;
}

static int ramoops_init_prz(struct device *dev, struct ramoops_context *cxt,
			    struct persistent_ram_zone **prz,
			    phys_addr_t *paddr, size_t sz)
{
	if (!sz)
		return 0;

	if (*paddr + sz > *paddr + cxt->size)
		return -ENOMEM;

	*prz = persistent_ram_new(*paddr, sz, cxt->ecc);
	if (IS_ERR(*prz)) {
		int err = PTR_ERR(*prz);

		dev_err(dev, "failed to request mem region (0x%zx@0x%llx): %d\n",
			sz, (unsigned long long)*paddr, err);
		return err;
	}

	persistent_ram_zap(*prz);

	*paddr += sz;

	return 0;
}

static int __init ramoops_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ramoops_platform_data *pdata = pdev->dev.platform_data;
	struct ramoops_context *cxt = &oops_cxt;
	size_t dump_mem_sz;
	phys_addr_t paddr;
	int err = -EINVAL;

	/* Only a single ramoops area allowed at a time, so fail extra
	 * probes.
	 */
	if (cxt->max_dump_cnt)
		goto fail_out;

	if (!pdata->mem_size || (!pdata->record_size && !pdata->console_size)) {
		pr_err("The memory size and the record/console size must be "
			"non-zero\n");
		goto fail_out;
	}

	pdata->mem_size = rounddown_pow_of_two(pdata->mem_size);
	pdata->record_size = rounddown_pow_of_two(pdata->record_size);
	pdata->console_size = rounddown_pow_of_two(pdata->console_size);

	cxt->dump_read_cnt = 0;
	cxt->size = pdata->mem_size;
	cxt->phys_addr = pdata->mem_address;
	cxt->record_size = pdata->record_size;
	cxt->console_size = pdata->console_size;
	cxt->dump_oops = pdata->dump_oops;
	cxt->ecc = pdata->ecc;

	paddr = cxt->phys_addr;

	dump_mem_sz = cxt->size - cxt->console_size;
	err = ramoops_init_przs(dev, cxt, &paddr, dump_mem_sz);
	if (err)
		goto fail_out;

	err = ramoops_init_prz(dev, cxt, &cxt->cprz, &paddr, cxt->console_size);
	if (err)
		goto fail_init_cprz;

	if (!cxt->przs && !cxt->cprz) {
		pr_err("memory size too small, minimum is %lu\n",
			cxt->console_size + cxt->record_size);
		goto fail_cnt;
	}

	cxt->pstore.data = cxt;
	/*
	 * Console can handle any buffer size, so prefer dumps buffer
	 * size since usually it is smaller.
	 */
	if (cxt->przs)
		cxt->pstore.bufsize = cxt->przs[0]->buffer_size;
	else
		cxt->pstore.bufsize = cxt->cprz->buffer_size;
	cxt->pstore.buf = kmalloc(cxt->pstore.bufsize, GFP_KERNEL);
	spin_lock_init(&cxt->pstore.buf_lock);
	if (!cxt->pstore.buf) {
		pr_err("cannot allocate pstore buffer\n");
		goto fail_clear;
	}

	err = pstore_register(&cxt->pstore);
	if (err) {
		pr_err("registering with pstore failed\n");
		goto fail_buf;
	}

	/*
	 * Update the module parameter variables as well so they are visible
	 * through /sys/module/ramoops/parameters/
	 */
	mem_size = pdata->mem_size;
	mem_address = pdata->mem_address;
	record_size = pdata->record_size;
	dump_oops = pdata->dump_oops;

	pr_info("attached 0x%lx@0x%llx, ecc: %s\n",
		cxt->size, (unsigned long long)cxt->phys_addr,
		ramoops_ecc ? "on" : "off");

	return 0;

fail_buf:
	kfree(cxt->pstore.buf);
fail_clear:
	cxt->pstore.bufsize = 0;
	cxt->max_dump_cnt = 0;
fail_cnt:
	kfree(cxt->cprz);
fail_init_cprz:
	ramoops_free_przs(cxt);
fail_out:
	return err;
}

static int __exit ramoops_remove(struct platform_device *pdev)
{
#if 0
	/* TODO(kees): We cannot unload ramoops since pstore doesn't support
	 * unregistering yet.
	 */
	struct ramoops_context *cxt = &oops_cxt;

	iounmap(cxt->virt_addr);
	release_mem_region(cxt->phys_addr, cxt->size);
	cxt->max_dump_cnt = 0;

	/* TODO(kees): When pstore supports unregistering, call it here. */
	kfree(cxt->pstore.buf);
	cxt->pstore.bufsize = 0;

	return 0;
#endif
	return -EBUSY;
}

static struct platform_driver ramoops_driver = {
	.remove		= __exit_p(ramoops_remove),
	.driver		= {
		.name	= "ramoops",
		.owner	= THIS_MODULE,
	},
};

static int __init ramoops_init(void)
{
	int ret;
	ret = platform_driver_probe(&ramoops_driver, ramoops_probe);
	if (ret == -ENODEV) {
		/*
		 * If we didn't find a platform device, we use module parameters
		 * building platform data on the fly.
		 */
		pr_info("platform device not found, using module parameters\n");
		dummy_data = kzalloc(sizeof(struct ramoops_platform_data),
				     GFP_KERNEL);
		if (!dummy_data)
			return -ENOMEM;
		dummy_data->mem_size = mem_size;
		dummy_data->mem_address = mem_address;
		dummy_data->record_size = record_size;
		dummy_data->console_size = ramoops_console_size;
		dummy_data->dump_oops = dump_oops;
		dummy_data->ecc = ramoops_ecc;
		dummy = platform_create_bundle(&ramoops_driver, ramoops_probe,
			NULL, 0, dummy_data,
			sizeof(struct ramoops_platform_data));

		if (IS_ERR(dummy))
			ret = PTR_ERR(dummy);
		else
			ret = 0;
	}

	return ret;
}

static void __exit ramoops_exit(void)
{
	platform_driver_unregister(&ramoops_driver);
	kfree(dummy_data);
}

module_init(ramoops_init);
module_exit(ramoops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Stornelli <marco.stornelli@gmail.com>");
MODULE_DESCRIPTION("RAM Oops/Panic logger/driver");
