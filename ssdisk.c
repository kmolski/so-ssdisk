/*
 * ssdisk device - example for Operating System course
 *
 * Copyright (C) 2016..2020  Krzysztof Mazur <krzysiek@podlesie.net>
 *
 * Copyright (C) 2021 Krzysztof Molski
 *
 * Add your copyright here and change MODULE_AUTHOR.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "ssdisk: " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/tty.h>

#define N_SSDISK 29

static void ssdisk_receive_buf(struct tty_struct *tty, const unsigned char *cp,
		char *fp, int count);

static ssize_t ssdisk_ldisc_write(struct tty_struct *tty, struct file *file,
		const unsigned char *buf, size_t nr);

/*
 * mutex used for access synchronization to buffer (ssdisk_buf and ssdisk_len)
 */
static struct mutex ssdisk_lock;

/*
 * buffer and number of written bytes in the buffer
 */
static char ssdisk_buf[4096];
static size_t ssdisk_len;

struct tty_struct *serial_device = NULL;

static int ssdisk_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t ssdisk_read(struct file *filp, char __user *buf, size_t count,
		loff_t *off)
{
	ssize_t ret = 0, rem = 0, cmd_length = 0, written_count = 0, chunk_length = 0;
	char command[17] = {0};

	pr_info("reading %zu bytes\n", count);

	/*
	 * access to ssdisk_buf i ssdisk_len is protected by ssdisk_lock,
	 * take that lock
	 */
	mutex_lock(&ssdisk_lock);

	ret = -ENXIO;
	if (serial_device == NULL)
		goto out_unlock;
	else if (*off > ssdisk_len)
		goto out_unlock;

	if (count >= 1000 - *off)
		count = 1000 - *off;

	pr_info("count: %zu\n", count);
	for (rem = count; rem > 0; rem -= 64) {
		chunk_length = rem < 64 ? rem : 64;
		cmd_length = snprintf(command, 17, ":0001%04lx%08llx\n",
				chunk_length, *off + count - rem);
		pr_info("command: %s", command);

		ret = -EFAULT;
		written_count = ssdisk_ldisc_write(serial_device, NULL, command, cmd_length);
		if (written_count != cmd_length)
			goto out_unlock;

		//ssdisk_ldisc_read(serial_device, NULL, buf + count - rem, 16);
		pr_info("response: %16s\n", ssdisk_buf + count - rem);
		
		sscanf(ssdisk_buf + count - rem, ":0001%04lx%*08x\n", &ret);
		if (ret < 0)
			goto out_unlock;

		//ssdisk_ldisc_read(serial_device, NULL, buf + count - rem, chunk_length * 2);
		pr_info("response: %16s\n", ssdisk_buf + count - rem);
	}

	/*
	 * for access to user memory special functions must be used,
	 * to copy to user memory copy_to_user must be used.
	 */
	ret = -EFAULT;
	if (copy_to_user(buf, ssdisk_buf, 2 * count))
		goto out_unlock;
	ret = count;
	*off += ret;

	pr_info("read %zu bytes\n", count);
out_unlock:
	mutex_unlock(&ssdisk_lock);
	return ret;
}

static ssize_t ssdisk_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *off)
{
	ssize_t ret = 0, rem = 0, cmd_len = 0, write_ct = 0, chunk_len = 0, i = 0;
	char command[1 + 8 * 2 + 64 * 2 + 1] = {0};

	pr_info("writing %zu bytes\n", count);

	/*
	 * access to ssdisk_buf i ssdisk_len is protected by ssdisk_lock,
	 * take that lock
	 */
	mutex_lock(&ssdisk_lock);

	ret = -ENXIO;
	if (serial_device == NULL)
		goto out_unlock;
	else if (*off > ssdisk_len)
		goto out_unlock;

	if (count >= 1000 - *off)
		count = 1000 - *off;
	pr_info("count: %zu\n", count);

	/*
	 * for access to user memory special functions must be used,
	 * to copy to user memory copy_to_user must be used.
	 */
	ret = -EFAULT;
	if (copy_from_user(ssdisk_buf, buf, count))
		goto out_unlock;

	for (rem = count; rem > 0; rem -= 64) {
		chunk_len = rem < 64 ? rem : 64;

		cmd_len = snprintf(command, 18, ":0002%04lx%08llx",
				chunk_len, *off + count - rem);

		for (i = 0; i < chunk_len; ++i) {
			cmd_len += snprintf(command + cmd_len, 3, "%02x", 
					ssdisk_buf[i + count - rem]);
		} 
		cmd_len += snprintf(command + cmd_len, 2, "\n");

		pr_info("command: %s", command);

		ret = -EFAULT;
		write_ct = ssdisk_ldisc_write(serial_device, NULL, command, cmd_len);
		if (write_ct != cmd_len)
			goto out_unlock;
	}

	ret = count;
	*off += ret;

	pr_info("wrote %zu bytes\n", count);
out_unlock:
	mutex_unlock(&ssdisk_lock);
	return ret;
}

static int ssdisk_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations ssdisk_fops = {
	.owner = THIS_MODULE,
	.open = ssdisk_open,
	.read = ssdisk_read,
	.write = ssdisk_write,
	.release = ssdisk_release,
};

static struct miscdevice ssdisk_miscdevice = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ssdisk",
	.fops = &ssdisk_fops
};

static int ssdisk_ldisc_open(struct tty_struct *tty)
{
	pr_info("new ssdisk device at tty %s\n", tty->name);
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!tty->ops->write)
		return -EOPNOTSUPP;

	tty->receive_room = 65536; /* flow control not supported */
	serial_device = tty;
	return 0;
}

static void ssdisk_ldisc_close(struct tty_struct *tty)
{
}

static int ssdisk_ldisc_hangup(struct tty_struct *tty)
{
	return 0;
}

static void ssdisk_receive_buf(struct tty_struct *tty, const unsigned char *cp,
		char *fp, int count)
{
	int c;

	pr_info("receiving %d bytes\n", count);

	while (count--) {
		if (fp && *fp++) {
			pr_info("error %02x\n", *fp);
			cp++;
			continue;
		}
		c = *cp++;
		pr_info("received %02x (%c)\n", c, (c >= 32 && c < 128) ? c : '?');
	}
}

static ssize_t ssdisk_ldisc_write(struct tty_struct *tty, struct file *file,
		const unsigned char *buf, size_t nr)
{
	pr_info("ldisc writing %zu bytes\n", nr);
	return tty->ops->write(tty, buf, nr);
}

static void ssdisk_write_wakeup(struct tty_struct *tty)
{
}

static struct tty_ldisc_ops ssdisk_ldisc = {
	.owner 		= THIS_MODULE,
	.magic 		= TTY_LDISC_MAGIC,
	.name 		= "ssdisk",
	.open 		= ssdisk_ldisc_open,
	.write		= ssdisk_ldisc_write,
	.hangup	 	= ssdisk_ldisc_hangup,
	.close	 	= ssdisk_ldisc_close,
	.ioctl		= tty_mode_ioctl,
	.receive_buf	= ssdisk_receive_buf,
	.write_wakeup	= ssdisk_write_wakeup,
};

static int __init ssdisk_init(void)
{
	int ret;

	mutex_init(&ssdisk_lock);
	//ssdisk_len = snprintf(ssdisk_buf, sizeof(ssdisk_buf),
	//		"Hello world!\n");
	ret = misc_register(&ssdisk_miscdevice);
	if (ret < 0) {
		pr_err("can't register miscdevice.\n");
		return ret;
	}
	ret = tty_register_ldisc(N_SSDISK, &ssdisk_ldisc);
	if (ret) {
		pr_err("can't register line discipline (err = %d)\n", ret);
		return ret;
	}

	pr_info("minor %d\n", ssdisk_miscdevice.minor);

	return 0;
}

static void __exit ssdisk_exit(void)
{
	misc_deregister(&ssdisk_miscdevice);
	mutex_destroy(&ssdisk_lock);
}

module_init(ssdisk_init);
module_exit(ssdisk_exit);

MODULE_DESCRIPTION("Secure Serial Disk");
MODULE_AUTHOR("Krzysztof Molski");
MODULE_LICENSE("GPL");
