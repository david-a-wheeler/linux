/*
 * Squelch Linux Security Module
 *
 * Author: David A. Wheeler <dwheeler@dwheeler.com>
 *
 * Copyright (C) 2016- David A. Wheeler
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/lsm_hooks.h>


/* TODO: Handle all other cases of dentry creation.
 * Report to log with: printk_ratelimited(KERN_NOTICE "message", ...);
 * See discussion about getting dentry name (d_name) and %pd here:
 * thread.gmane.org/gmane.linux-file-systems/37940
 */

/**
 * squelch_inode_create - Check squelch rules when it tries to create inode.
 *
 */
static int squelch_inode_create(struct inode *dir, struct dentry *dentry,
                                umode_t mode)
{
	return 0;
}

/**
 * squelch_inode_link - Check squelch rules when it tries to create link.
 *
 */
static int squelch_inode_link(struct dentry *old_dentry, struct inode *dir,
                                struct dentry *new_dentry)
{
	return 0;
}

static struct security_hook_list squelch_hooks[] = {
	LSM_HOOK_INIT(inode_create, squelch_inode_create),
	LSM_HOOK_INIT(inode_link, squelch_inode_link),
};


void __init squelch_add_hooks(void)
{
	pr_info("Squelch: Preventing the creation of malicious filenames.\n");
	security_add_hooks(squelch_hooks, ARRAY_SIZE(squelch_hooks));
}
