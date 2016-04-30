/*
 * Squelch Linux Security Module
 *
 * Author: David A. Wheeler <dwheeler@dwheeler.com>
 *
 * Copyright (C) 2016 David A. Wheeler
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/types.h>
#include <linux/bitmap.h>

/* For stub auditing */
#include <linux/ratelimit.h>

/* TODO:
 * Do we actually need the path_... hooks?
 * Do we need to lock the dentry (I don't think so).
 * Full docstrings for functions
 * Byte checks: Optimize loop for common cases.
 * Future: Optionally check filenames on mount.
 * Better reporting mechanism than printk_ratelimited.
 * Namespace - allow per-container control.
 * Optimize filename byte checking loop for common cases?
 */

/* Mode used for unprivileged tasks.  We consider tasks without
 * CAP_SYS_ADMIN as unprivileged.  The mode values are:
 * 0 = not enforced, no audit reports on failed requests
 * 1 = enforced, no audit reports on failed requests
 * 2 = not enforced, audit reports made on failed requests
 * 3 = enforced, audit reports made on failed requests.
 * Default is 0: no enforcement, no audit.
 */
static int mode_for_unprivileged;

/* Mode used for privileged tasks.  We consider tasks with
 * CAP_SYS_ADMIN as privileged.  The mode values the same as
 * mode_for_unprivileged.
 * Default is 0: no enforcement, no audit.
 */
static int mode_for_privileged;

/* If true, includes a check to see if newly-created filenames are valid UTF-8.
 * Default is 0: Disabled by default. */
static int utf8;

/* The following are bitmaps that determine which byte values are permitted.
 * An 'on' bit means that the corresponding byte is permitted in a filename.
 * A filename's initial byte must be permitted by permitted_bytes_initial,
 * its final byte must be permitted by permitted_bytes_final,
 * and all bytes (including first and final) must be permitted
 * by permitted_bytes.
 */
static DECLARE_BITMAP(permitted_bytes_initial, 256);
static DECLARE_BITMAP(permitted_bytes_final, 256);
static DECLARE_BITMAP(permitted_bytes, 256);

/**
 * ut8_check - Returns NULL if string is entirely valid utf8, else returns
 *             pointer to where it fails.
 * @s - string to check.
 * From https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
 * by Markus Kuhn, released under many licenses incluidng the GPL. See:
 * http://www.cl.cam.ac.uk/~mgk25/short-license.html
 */
static const char *utf8_check(const char *s)
{
	while (*s) {
		if (*s < 0x80)
			/* 0xxxxxxx */
			s++;
		else if ((s[0] & 0xe0) == 0xc0) {
			/* 110XXXXx 10xxxxxx */
			if ((s[1] & 0xc0) != 0x80 ||
			    (s[0] & 0xfe) == 0xc0) /* overlong? */
				return s;
			else
				s += 2;
		} else if ((s[0] & 0xf0) == 0xe0) {
			/* 1110XXXX 10Xxxxxx 10xxxxxx */
			if ((s[1] & 0xc0) != 0x80 ||
			    (s[2] & 0xc0) != 0x80 ||
			    (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80) ||
			    (s[0] == 0xed && (s[1] & 0xe0) == 0xa0) ||
			    (s[0] == 0xef && s[1] == 0xbf &&
			     (s[2] & 0xfe) == 0xbe)) /* U+FFFE or U+FFFF? */
				return s;
			else
				s += 3;
			} else if ((s[0] & 0xf8) == 0xf0) {
				/* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
				if ((s[1] & 0xc0) != 0x80 ||
				    (s[2] & 0xc0) != 0x80 ||
				    (s[3] & 0xc0) != 0x80 ||
				    (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) ||
				    (s[0] == 0xf4 && s[1] > 0x8f) ||
				    (s[0] > 0xf4))
					return s;
				 else
					s += 4;
			} else
				 return s;
	}
	return NULL;
}

/**
 * squelch_name_check_details - Return 0 iff given filename okay
 * @name - filename to check (this is not the entire pathname)
 */
static int squelch_name_check_details(const char *name)
{
	char c;
	const char *p;
	if (!name) {
		// Handle null name; shouldn't happen.
		printk(KERN_ALERT "DEBUG: Squelch got name==NULL\n");
		return -EPERM;
	}
	c = name[0];
	if (!c) {
		printk(KERN_ALERT "DEBUG: Squelch got 0-length name\n");
		return -EPERM;
	}
	if (!test_bit(c, permitted_bytes_initial))
		return -EPERM;
	/* Check all characters. TODO: Optimize common cases? */
	p = name;
        while ((c = *p++) != '\0')
		if (!test_bit(c, permitted_bytes))
			return -EPERM;
	/* Check final character - can't be space. */
        c = *(p - 1);
	if (!test_bit(c, permitted_bytes_final))
		return -EPERM;
	if (utf8)
		return (utf8_check(name) == NULL) ? 0 : -EPERM;
	/* Should we check specially for UTF-8 chars, e.g., UTF-8 spaces? */
	/* All checks passed, return "no error" */
	return 0;
}

/**
 * squelch_report - Report that a filename doesn't meet the creteria.
 * @name - filename to check (this is not the entire pathname)
 * @enforcing - if nonzero, we're going to prevent its creation.
 * TODO: Should we use a different reporting mechanism?
 */
static void squelch_report(const char *name, int enforcing)
{
	printk_ratelimited(KERN_INFO "Squelch: Invalid filename %s%*pE\n",
	  enforcing ? "(creation rejected) " : "",
	  (int) strlen(name), name);
}

/**
 * squelch_name_check - Return 0 iff given filename okay,
 *                      checking and handling the mode bits.
 * @name - filename to check (this is not the entire pathname)
 */
static int squelch_name_check(const char *name)
{
	int mode;
	int err;
	if (capable(CAP_SYS_ADMIN))
		mode = mode_for_privileged;
	else
		mode = mode_for_unprivileged;
	/* Don't do any work if it's not needed. */
	if (!mode)
		return 0;
	err = squelch_name_check_details(name);
	/* TODO: Better audit reporting. Be sure to escape name on output. */
	if (err && (mode & 0x02))
		squelch_report(name, mode & 0x01);
	if (mode & 0x01)
		return err;
	return 0;
}

/**
 * squelch_dentry_check - Return 0 if dentry's name is okay.
 * @dentry - the dentry to check.
 */
static int squelch_dentry_check(const struct dentry *dentry)
{
	/* TODO: Check - Do we need to lock the dentry, using
	 * spin_lock(&dentry->d_lock) .. spin_unlock(&dentry->d_lock) ?
	 * I believe the answer is "no", since the dentries haven't been
	 * added to the filesystem yet (that's what we're checking for!).
         * See discussion about getting dentry name (d_name) and %pd here:
         * thread.gmane.org/gmane.linux-file-systems/37940
	 */
	return squelch_name_check(dentry->d_name.name);
}

/**
 * squelch_inode_create - Check squelch rules when it tries to create inode.
 */
static int squelch_inode_create(struct inode *dir, struct dentry *dentry,
                                umode_t mode)
{
	return squelch_dentry_check(dentry);
}

/**
 * squelch_inode_link - Check squelch rules when it tries to create link.
 */
static int squelch_inode_link(struct dentry *old_dentry, struct inode *dir,
                              struct dentry *new_dentry)
{
	return squelch_dentry_check(new_dentry);
}

static int squelch_path_link(struct dentry *old_dentry, struct path *new_dir,
                             struct dentry *new_dentry)
{
	return squelch_dentry_check(new_dentry);
}

static int squelch_inode_symlink(struct inode *dir, struct dentry *dentry,
                                 const char *old_name)
{
	return squelch_dentry_check(dentry);
}

static int squelch_path_symlink(struct path *dir, struct dentry *dentry,
                                const char *old_name)
{
	return squelch_dentry_check(dentry);
}

static int squelch_inode_mkdir(struct inode *dir, struct dentry *dentry,
                               umode_t mode)
{
	return squelch_dentry_check(dentry);
}

static int squelch_path_mkdir(struct path *dir, struct dentry *dentry,
                              umode_t mode)
{
	return squelch_dentry_check(dentry);
}

static int squelch_inode_mknod(struct inode *dir, struct dentry *dentry,
                                umode_t mode, dev_t dev)
{
	return squelch_dentry_check(dentry);
}

static int squelch_path_mknod(struct path *dir, struct dentry *dentry,
                              umode_t mode, unsigned int dev)
{
	return squelch_dentry_check(dentry);
}



static int squelch_inode_rename(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry)
{
	return squelch_dentry_check(new_dentry);
}

static int squelch_path_rename(struct path *old_dir, struct dentry *old_dentry,
			       struct path *new_dir,
			       struct dentry *new_dentry)
{
	return squelch_dentry_check(new_dentry);
}

#ifdef CONFIG_SYSCTL
static int zero = 0;
static int one = 1;
static int three = 3;

struct ctl_path squelch_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "squelch", },
	{ }
};

static struct ctl_table squelch_sysctl_table[] = {
	{
		.procname       = "mode_for_unprivileged",
		.data           = &mode_for_unprivileged,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &three,
	},
	{
		.procname       = "mode_for_privileged",
		.data           = &mode_for_privileged,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &three,
	},
	{
		.procname       = "utf8",
		.data           = &utf8,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{
		.procname       = "permitted_bytes_initial",
		.data           = &permitted_bytes_initial,
		.maxlen         = sizeof(permitted_bytes_initial),
		.mode           = 0644,
		.proc_handler   = proc_do_large_bitmap,
	},
	{
		.procname       = "permitted_bytes_final",
		.data           = &permitted_bytes_final,
		.maxlen         = sizeof(permitted_bytes_final),
		.mode           = 0644,
		.proc_handler   = proc_do_large_bitmap,
	},
	{
		.procname       = "permitted_bytes",
		.data           = &permitted_bytes,
		.maxlen         = sizeof(permitted_bytes),
		.mode           = 0644,
		.proc_handler   = proc_do_large_bitmap,
	},
	/* TODO: TEMPORARY: Let us access the bitvec structure differently */
	{
		.procname       = "permitted_bytes_initial_as_intvec",
		.data           = &permitted_bytes_initial,
		.maxlen         = sizeof(permitted_bytes_initial),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "permitted_bytes_final_as_intvec",
		.data           = &permitted_bytes_final,
		.maxlen         = sizeof(permitted_bytes_final),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "permitted_bytes_as_intvec",
		.data           = &permitted_bytes,
		.maxlen         = sizeof(permitted_bytes),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
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

/* squelch_init_bitmasks - initialize
 *   permitted_bytes_initial, permitted_bytes_final, and permitted_bytes.
 *   We do this at run-time for clarity; these bit manipulations are quick,
 *   so there's not a great advantage in doing this at compile time.
 */
static void squelch_init_bitmasks(void)
{
     /* Permitted bytes allows ' '..0x7e and 0x80..0xfe. This
      * omits control chars, 0x7f (DEL), and 0xff. */
     bitmap_set(permitted_bytes, (int) ' ', 0x7e - (int) ' ');
     bitmap_set(permitted_bytes_initial, (int) ' ', 0x7e - (int) ' ');
     bitmap_set(permitted_bytes_final, (int) ' ', 0x7e - (int) ' ');
     bitmap_set(permitted_bytes, 0x80, 0xfe - 0x80);
     bitmap_set(permitted_bytes_initial, 0x80, 0xfe - 0x80);
     bitmap_set(permitted_bytes_final, 0x80, 0xfe - 0x80);
     /* Forbid '-', ' ', and '~' as initial values. */
     bitmap_clear(permitted_bytes_initial, (int) '-', 1);
     bitmap_clear(permitted_bytes_initial, (int) ' ', 1);
     bitmap_clear(permitted_bytes_initial, (int) '~', 1);
     /* Forbid ' ' as final value. */
     bitmap_clear(permitted_bytes_final, (int) ' ', 1);
}

/* NOTE: Many hooks have both an inode_... and path_... version.
 * For the moment, to be sure we get all cases, we intercept both.
 * I suspect we only need the inode_... versions.
 * Comments to confirm/deny this would be welcome!
 * If we don't need *any* of the path_... hooks, we could drop
 * SECURITY_PATH from the Kconfig file for this module. */

static struct security_hook_list squelch_hooks[] = {
	LSM_HOOK_INIT(inode_create, squelch_inode_create),
	LSM_HOOK_INIT(inode_link, squelch_inode_link),
	LSM_HOOK_INIT(path_link, squelch_path_link),
	LSM_HOOK_INIT(inode_symlink, squelch_inode_symlink),
	LSM_HOOK_INIT(path_symlink, squelch_path_symlink),
	LSM_HOOK_INIT(inode_mkdir, squelch_inode_mkdir),
	LSM_HOOK_INIT(path_mkdir, squelch_path_mkdir),
	LSM_HOOK_INIT(inode_mknod, squelch_inode_mknod),
	LSM_HOOK_INIT(path_mknod, squelch_path_mknod),
	LSM_HOOK_INIT(inode_rename, squelch_inode_rename),
	LSM_HOOK_INIT(path_rename, squelch_path_rename),
};


void __init squelch_add_hooks(void)
{
	pr_info("Squelch: Preventing the creation of malicious filenames.\n");
	printk(KERN_ALERT "DEBUG: Squelch starting up\n");
        squelch_init_bitmasks();
	security_add_hooks(squelch_hooks, ARRAY_SIZE(squelch_hooks));
	squelch_init_sysctl();
}
