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
#include <linux/sysctl.h>

/* TODO: Handle all other cases of dentry creation.
 * Report to log with: printk_ratelimited(KERN_NOTICE "message", ...);
 * See discussion about getting dentry name (d_name) and %pd here:
 * thread.gmane.org/gmane.linux-file-systems/37940
 * See example of "LoadPin":
 *   https://github.com/david-a-wheeler/squelch.git
 * Make 'enabled' do something, and start with "off" as default.
 * Allow control of various factors, e.g., does it control root or those
 * with privileged capabilities?
 * What's allowed/forbidden?
 * Add sysctl to control it at run-time.
 */

static int enabled; /* Disabled by default */
static int zero = 0;
static int one = 1;

#ifdef CONFIG_SYSCTL
struct ctl_path squelch_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "squelch", },
	{ }
};

static struct ctl_table squelch_sysctl_table[] = {
	{
		.procname       = "enabled",
		.data           = &enabled,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{ }
};

static void __init squelch_init_sysctl(void)
{
	if (!register_sysctl_paths(squelch_sysctl_path, squelch_sysctl_table))
		panic("Squelch: sysctl registration failed.\n");
}
#else
static inline void squelch_init_sysctl(void) { }
#endif /* CONFIG_SYSCTL */

/**
 * squelch_name_okay - Return 0 if given filename okay
 */
static int squelch_name_okay(char *name)
{
	if (!enabled) {
		return 0;
	}
	/* TODO: Do real checking.  For now, stub out a test. */
	if (name[0] == '-') {
		printk(KERN_ALERT "DEBUG: Squelch found name begins with '-': %s\n", name);
	}
	return 0;
}

/**
 * squelch_dentry_okay - Return 0 if dentry's name is okay.
 */
static int squelch_dentry_okay(struct dentry *dentry)
{
	/* TODO: Check - Do we need to lock the dentry, using
	 * spin_lock(&dentry->d_lock) .. spin_unlock(&dentry->d_lock) ?
	 * I believe the answer is "no", since the dentries haven't been
	 * added to the filesystem yet (that's what we're checking for!).
	 */
	return squelch_name_okay(dentry->d_name.name);
}

/**
 * squelch_inode_create - Check squelch rules when it tries to create inode.
 *
 */
static int squelch_inode_create(struct inode *dir, struct dentry *dentry,
                                umode_t mode)
{
	return squelch_dentry_okay(dentry);
}

/**
 * squelch_inode_link - Check squelch rules when it tries to create link.
 *
 */
static int squelch_inode_link(struct dentry *old_dentry, struct inode *dir,
                                struct dentry *new_dentry)
{
	return squelch_dentry_okay(new_dentry);
}

static struct security_hook_list squelch_hooks[] = {
	LSM_HOOK_INIT(inode_create, squelch_inode_create),
	LSM_HOOK_INIT(inode_link, squelch_inode_link),
};


void __init squelch_add_hooks(void)
{
	pr_info("Squelch: Preventing the creation of malicious filenames.\n");
	printk(KERN_ALERT "DEBUG: Squelch starting up\n");
	security_add_hooks(squelch_hooks, ARRAY_SIZE(squelch_hooks));
	squelch_init_sysctl();
}

