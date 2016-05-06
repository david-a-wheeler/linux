/*
 * Safename Linux Security Module
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

/* For reporting */
#include <linux/ratelimit.h>

/* Questions:
 * - Do we need to lock the dentry (I don't think so)?
 * - Should we change the reporting mechanism from printk_ratelimited?
 *
 * Possible future directions:
 * - Optionally check filenames on mount.
 * - Possibly optimize byte check loop for common cases.
 * - Namespace this to allow per-container control.
 */

/* Mode used for unprivileged tasks.  We consider tasks without
 * CAP_MAC_ADMIN as unprivileged.  The mode values are:
 * 0 = not enforced, no reports on failed requests.
 * 1 = enforced, no reports on failed requests.
 * 2 = not enforced, reports made on failed requests.
 * 3 = enforced, reports made on failed requests.
 * Default is 0: no enforcement, no reports.
 */
static int mode_for_unprivileged;

/* Mode used for privileged tasks.  We consider tasks with
 * CAP_MAC_ADMIN as privileged.  The mode values the same as
 * mode_for_unprivileged.
 * Default is 0: no enforcement, no report.
 */
static int mode_for_privileged;

/* If true, includes a check to see if newly-created filenames are valid UTF-8.
 * Default is 0: Disabled by default.
 */
static int utf8;

/* Number of possible values in a char */
#define POSSIBLE_CHAR 256

/* The following are bitmaps that determine which byte values are permitted.
 * An 'on' bit means that the corresponding byte is permitted in a filename.
 * A filename's initial byte must be permitted by permitted_bytes_initial,
 * its final byte must be permitted by permitted_bytes_final,
 * and all other bytes must be permitted by permitted_bytes_middle.
 *
 * DECLARE_BITMAP is defined in linux/types.h as an array of unsigned longs.
 */

static DECLARE_BITMAP(permitted_bytes_initial, POSSIBLE_CHAR);
static DECLARE_BITMAP(permitted_bytes_middle, POSSIBLE_CHAR);
static DECLARE_BITMAP(permitted_bytes_final, POSSIBLE_CHAR);

/* Need these for proc_do_large_bitmap */
unsigned long *permitted_bytes_initial_ptr = permitted_bytes_initial;
unsigned long *permitted_bytes_middle_ptr = permitted_bytes_middle;
unsigned long *permitted_bytes_final_ptr = permitted_bytes_final;

/**
 * ut8_check - Returns NULL if string is utf8, else returns pointer to failure.
 * @s - string to check.
 *
 * Description:
 * This function is from https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
 * by Markus Kuhn, released as public domain *and* GPL.
 * See: http://www.cl.cam.ac.uk/~mgk25/short-license.html
 * checkpatch.pl warns "else is not generally useful after a break or return",
 * but in this case there's no problem; the return halts processing once we've
 * found a failure (and thus we don't need to examine anything further).
 */
const unsigned char *utf8_check(const unsigned char *s)
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
 * safename_name_check_valid - Return 0 iff given filename is valid.
 * @name - filename to check (this is not the entire pathname)
 *
 * Description:
 * Compare filename to all active rules.
 * This function only checks the name; mode bits are handled elsewhere.
 */
static int safename_name_check_valid(const char *name)
{
	unsigned char c, next; /* Unsigned because we index in a bitmask */
	const unsigned char *p;

	if (!name) { /* Handle null name; shouldn't happen. */
		pr_alert("Error - safename got name==NULL\n");
		return -EPERM;
	}
	/* Check first character */
	c = (const unsigned char) name[0];
	if (!c) { /* Handle 0-length name; shouldn't happen. */
		pr_alert("Error - safename got 0-length name\n");
		return -EPERM;
	}
	if (!test_bit(c, permitted_bytes_initial))
		return -EPERM;
	if (utf8 && utf8_check((const unsigned char *) name))
		return -EPERM;
	p = ((const unsigned char *) name) + 1;
	while (1) {
		/* At start of loop, p points one *past* current char c */
		next = *p++;
		if (!next)
			break;
		if (!test_bit(c, permitted_bytes_middle))
			return -EPERM;
		c = next;
	}
	if (!test_bit(c, permitted_bytes_final))
		return -EPERM;
	return 0;
}

/**
 * safename_report - Report that a filename doesn't meet the criteria.
 * @name - filename to check (this is not the entire pathname)
 * @enforcing - if nonzero, we're going to prevent its creation.
 *
 * Description:
 * Report when filename doesn't meet criteria.  If you change this,
 * be sure to escape its name on output since \n, ESC, etc. could be in name.
 */
static void safename_report(const char *name, int enforcing)
{
	printk_ratelimited(KERN_INFO "Safename: Invalid filename%s:%*pE\n",
	  enforcing ? " (creation rejected)" : "",
	  (int) strlen(name), name);
}

/**
 * safename_name_check - Depending on mode, check name and report if not okay.
 * @name - filename to check (this is NOT the entire pathname)
 *
 * Description:
 * This function checks the mode bits; if we're supposed to enforce or
 * check, it checks the filename (using safename_name_check_valid)
 * This returns 0 iff given name is acceptable as a filename.
 * This function is separate from safename_dentry_check so that
 * in the future we could check names without a dentry
 * (e.g., if we're checking a filesystem before mounting it
 * and don't want to create dentries while traversing it).
 */
static int safename_name_check(const char *name)
{
	int mode, err;

	if (capable(CAP_MAC_ADMIN))
		mode = mode_for_privileged;
	else
		mode = mode_for_unprivileged;
	/* Don't do any work if it's not needed. */
	if (!mode)
		return 0;
	err = safename_name_check_valid(name);
	if (err && (mode & 0x02))
		safename_report(name, mode & 0x01);
	if (mode & 0x01)
		return err;
	return 0;
}

/**
 * safename_dentry_check - Check dentry name; return 0 if okay.
 * @dentry - the dentry to check.
 */
static int safename_dentry_check(const struct dentry *dentry)
{
	/* Do we need to lock the dentry, using
	 * spin_lock(&dentry->d_lock) .. spin_unlock(&dentry->d_lock) ?
	 * I believe the answer is "no", since the dentries haven't been
	 * added to the filesystem yet (that's what we're checking for!).
	 * See discussion about getting dentry name (d_name) and %pd here:
	 * thread.gmane.org/gmane.linux-file-systems/37940
	 */
	return safename_name_check(dentry->d_name.name);
}

/**
 * safename_inode_create - Check safename rules when it tries to create inode.
 */
static int safename_inode_create(struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	return safename_dentry_check(dentry);
}

static int safename_inode_link(struct dentry *old_dentry, struct inode *dir,
			      struct dentry *new_dentry)
{
	return safename_dentry_check(new_dentry);
}

static int safename_inode_symlink(struct inode *dir, struct dentry *dentry,
				 const char *old_name)
{
	return safename_dentry_check(dentry);
}

static int safename_inode_mkdir(struct inode *dir, struct dentry *dentry,
			       umode_t mode)
{
	return safename_dentry_check(dentry);
}

static int safename_inode_mknod(struct inode *dir, struct dentry *dentry,
			       umode_t mode, dev_t dev)
{
	return safename_dentry_check(dentry);
}

static int safename_inode_rename(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry)
{
	return safename_dentry_check(new_dentry);
}

#ifdef CONFIG_SYSCTL
static int zero;
static int one = 1;
static int three = 3;

struct ctl_path safename_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "safename", },
	{ }
};

static struct ctl_table safename_sysctl_table[] = {
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
		.data           = &permitted_bytes_initial_ptr,
		/* proc_do_large_bitmap maxlen is in bits, NOT in bytes. */
		.maxlen         = POSSIBLE_CHAR,
		.mode           = 0644,
		.proc_handler   = proc_do_large_bitmap,
	},
	{
		.procname       = "permitted_bytes_middle",
		.data           = &permitted_bytes_middle_ptr,
		.maxlen         = POSSIBLE_CHAR,
		.mode           = 0644,
		.proc_handler   = proc_do_large_bitmap,
	},
	{
		.procname       = "permitted_bytes_final",
		.data           = &permitted_bytes_final_ptr,
		.maxlen         = POSSIBLE_CHAR,
		.mode           = 0644,
		.proc_handler   = proc_do_large_bitmap,
	},
	{ }
};

static void __init safename_init_sysctl(void)
{
	if (!register_sysctl_paths(safename_sysctl_path, safename_sysctl_table))
		panic("Safename: sysctl registration failed.\n");
}
#else
static inline void safename_init_sysctl(void) { }
#endif /* CONFIG_SYSCTL */

/**
 * safename_init_bitmasks - initialize bitmasks needed by safename.
 *
 * Description:
 * Initialize permitted_bytes_initial, permitted_bytes_middle,
 * and permitted_bytes_final.
 * We do this at run-time for clarity; these bit manipulations are quick,
 * and take little space in code, so there's no great advantage
 * in doing this at compile time.
 */
static void safename_init_bitmasks(void)
{
	bitmap_set(permitted_bytes_middle, (int) ' ', 0x7e - (int) ' ' + 1);
	bitmap_set(permitted_bytes_initial, (int) ' ', 0x7e - (int) ' ' + 1);
	bitmap_set(permitted_bytes_final, (int) ' ', 0x7e - (int) ' ' + 1);

	bitmap_set(permitted_bytes_middle, 0x80, 0xfe - 0x80 + 1);
	bitmap_set(permitted_bytes_initial, 0x80, 0xfe - 0x80 + 1);
	bitmap_set(permitted_bytes_final, 0x80, 0xfe - 0x80 + 1);

	/* Forbid '-', ' ', and '~' as initial values. */
	bitmap_clear(permitted_bytes_initial, (int) '-', 1);
	bitmap_clear(permitted_bytes_initial, (int) ' ', 1);
	bitmap_clear(permitted_bytes_initial, (int) '~', 1);

	/* Forbid ' ' as final value. */
	bitmap_clear(permitted_bytes_final, (int) ' ', 1);
}

static struct security_hook_list safename_hooks[] = {
	LSM_HOOK_INIT(inode_create, safename_inode_create),
	LSM_HOOK_INIT(inode_link, safename_inode_link),
	LSM_HOOK_INIT(inode_symlink, safename_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, safename_inode_mkdir),
	LSM_HOOK_INIT(inode_mknod, safename_inode_mknod),
	LSM_HOOK_INIT(inode_rename, safename_inode_rename),
};


/**
 * safename_add_hooks - initialize safename
 */
void __init safename_add_hooks(void)
{
	pr_info("Safename: Preventing the creation of malicious filenames.\n");
	safename_init_bitmasks();
	security_add_hooks(safename_hooks, ARRAY_SIZE(safename_hooks));
	safename_init_sysctl();
}
