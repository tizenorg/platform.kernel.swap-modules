////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           device_driver.c
//
//      DESCRIPTION:
//      This file is C source for SWAP driver.
//
//      SEE ALSO:       device_driver.h
//      AUTHOR:         L.Komkov, S.Dianov, S.Grekhov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include "module.h"
#include "device_driver.h"	// device driver
#include "CProfile.h"
#include <linux/notifier.h>

static BLOCKING_NOTIFIER_HEAD(inperfa_notifier_list);
pid_t gl_nNotifyTgid;
EXPORT_SYMBOL_GPL(gl_nNotifyTgid);

DECLARE_WAIT_QUEUE_HEAD (notification_waiters_queue);
volatile unsigned notification_count;

static int device_mmap (struct file *filp, struct vm_area_struct *vma);
static int device_ioctl (struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int gl_nDeviceOpened = 0;
static struct file_operations device_fops = {
	.owner = THIS_MODULE,
	.mmap = device_mmap,
	.ioctl = device_ioctl,
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

int device_init (void)
{
	int nReserved = 0;
	int nRetVal = register_chrdev(device_major, device_name, &device_fops);
	if (nRetVal < 0) {
		EPRINTF("Cannot register character device! [%s, %d]", device_name, device_major);
		nReserved = register_chrdev(0, device_name, &device_fops);
		if(nReserved >= 0)
			EPRINTF("Please, create a new device node with major number [%d],\n\tand pass it as module parameter!", nReserved);
		return -1;
	} else if(nRetVal > 0) {
		EPRINTF("Cannot register this device major number! [%d]\n\tTrying a new one. [%d]", device_major, nRetVal);
		device_major = nRetVal;
	}
	return 0;
}

void device_down (void)
{
	unregister_chrdev(device_major, device_name);
}

void inperfa_register_notify (struct notifier_block *nb)
{
	blocking_notifier_chain_register(&inperfa_notifier_list, nb);
}
EXPORT_SYMBOL_GPL(inperfa_register_notify);

void inperfa_unregister_notify (struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&inperfa_notifier_list, nb);
}
EXPORT_SYMBOL_GPL(inperfa_unregister_notify);

void notify_user (event_id_t event_id)
{
	ec_info.events_counters[event_id] += 1;

	if (EVENT_EC_PROBE_RECORD == event_id)
	{
		// EC_PROBE_RECORD events happen to often. To reduce overhead user
		// space will be notified only once per each EVENTS_AGGREGATION_USEC
		static uint64_t timestamp_usec = 0;

		uint64_t current_usec;
		uint64_t delta_usec;

		struct timeval tv;

		do_gettimeofday (&tv);
		current_usec = 1000000ULL * (unsigned) tv.tv_sec + (unsigned) tv.tv_usec;

		if (current_usec < timestamp_usec)
		{
			// Note: time from do_gettimeofday() may go backward
			EPRINTF ("current_usec=%llu timestamp_usec=%llu", current_usec, timestamp_usec);
		}
		else
		{
			delta_usec = current_usec - timestamp_usec;
			if (EVENTS_AGGREGATION_USEC > delta_usec)
			{
				// wait the time left
#if defined(__DEBUG)
				unsigned UNUSED left_usec = EVENTS_AGGREGATION_USEC - delta_usec;
#endif /* defined(__DEBUG) */
				return;	// supress notification
			}
		}
		timestamp_usec = current_usec;	// remember new time for the future use
	} else if (EVENT_EC_START_CONDITION_SEEN == event_id) {
		return;		// supress notification
	} else if (EVENT_EC_STOP_CONDITION_SEEN == event_id) {
		return;		// supress notification
	}

	++notification_count;
	wake_up_interruptible (&notification_waiters_queue);
}

static int device_mmap (struct file *filp UNUSED, struct vm_area_struct *vma)
{
	if(!p_buffer) {
		EPRINTF("Null pointer to buffer!");
		return -1;
	}
	return remap_vmalloc_range (vma, p_buffer, 0);
}

static int device_open(struct inode *inode, struct file *file)
{
	/*if (gl_nDeviceOpened)
		return -EBUSY;*/
	gl_nDeviceOpened++;
	// TODO
	try_module_get(THIS_MODULE);
	return 0;
}
 
static int device_release(struct inode *inode, struct file *file)
{
	gl_nDeviceOpened--;
	module_put(THIS_MODULE);
	return 0;
}
 
static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t * offset)
{
	EPRINTF("Operation <<read>> not supported!");
	return -1;
}
 
static ssize_t device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	EPRINTF("Operation <<write>> not supported!");
	return -1;
}
static int device_ioctl (struct inode *inode UNUSED, struct file *file UNUSED, unsigned int cmd, unsigned long arg)
{
	unsigned long spinlock_flags = 0L;
	int result = -1;
//	DPRINTF("Command=%d", cmd);
	switch (cmd)
	{
	case EC_IOCTL_SET_EC_MODE:
		{
			ioctl_general_t param;
			unsigned long nIgnoredBytes = 0;
			memset(&param, '0', sizeof(ioctl_general_t));
			nIgnoredBytes = copy_from_user (&param, (void*)arg, sizeof(ioctl_general_t));
			if (nIgnoredBytes > 0) {
				result = -1;
				break;
			}
			if(SetECMode(param.m_unsignedLong) == -1) {
				result = -1;
				break;
			}
			result = 0;
			DPRINTF("Set EC Mode = %lu", param.m_unsignedLong);
			break;
		}
	case EC_IOCTL_GET_EC_MODE:
		{
			ioctl_general_t param;
			unsigned long nIgnoredBytes = 0;
			memset(&param, '0', sizeof(ioctl_general_t));
			param.m_unsignedLong = GetECMode();
			nIgnoredBytes = copy_to_user ((void*)arg, &param, sizeof (ioctl_general_t));
			if (nIgnoredBytes > 0) {
				result = -1;
				break;
			}
			result = 0;
//			DPRINTF("Get EC Mode = %lu", param.m_unsignedLong);  // Frequent call
			break;
		}
	case EC_IOCTL_SET_BUFFER_SIZE:
		{
			ioctl_general_t param;
			unsigned long nIgnoredBytes = 0;
			memset(&param, '0', sizeof(ioctl_general_t));
			nIgnoredBytes = copy_from_user (&param, (void*)arg, sizeof(ioctl_general_t));
			if (nIgnoredBytes > 0) {
				result = -1;
				break;
			}
			if (SetBufferSize(param.m_unsignedLong) == -1) {
				result = -1;
				break;
			}
			result = 0;
			DPRINTF("Set Buffer Size = %lu", param.m_unsignedLong);
			break;
		}
	case EC_IOCTL_GET_BUFFER_SIZE:
		{
			ioctl_general_t param;
			unsigned long nIgnoredBytes = 0;
			memset(&param, '0', sizeof(ioctl_general_t));
			param.m_unsignedLong = GetBufferSize();
			nIgnoredBytes = copy_to_user ((void*)arg, &param, sizeof (ioctl_general_t));
			if (nIgnoredBytes > 0) {
				result = -1;
				break;
			}
			result = 0;
			DPRINTF("Get Buffer Size = %lu", param.m_unsignedLong);
			break;
		}
	case EC_IOCTL_RESET_BUFFER:
		{
			if (ResetBuffer() == -1) {
				result = -1;
				break;
			}
			result = 0;
			DPRINTF("Reset Buffer");
			break;
		}
	case EC_IOCTL_GET_EC_INFO:
		{
			if (copy_ec_info_to_user_space ((ec_info_t *) arg) != 0) {
				result = -1;
				break;
			}
			result = 0;
//			DPRINTF("Get Buffer Status"); // Frequent call
			break;
		}
	case EC_IOCTL_CONSUME_BUFFER:
		{
			static ec_info_t ec_info_copy;
			int nIgnoredBytes = 0;
#ifndef __DISABLE_RELAYFS
			struct rchan* pRelayChannel = NULL;
			struct rchan_buf *buf = NULL;
			unsigned int nNumOfSubbufs = 0;
			void* pConsume = NULL;
			unsigned int nPaddingLength = 0;
			unsigned int nSubbufSize = 0;
			unsigned int nDataSize = 0;
			unsigned int nEffectSize = 0;
			unsigned int nSubbufDiscardedCount = 0;
#endif
			nIgnoredBytes = copy_from_user (&ec_info_copy, (ec_info_t *) arg, sizeof (ec_info_t));
			if(nIgnoredBytes > 0)
			{
				EPRINTF ("copy_from_user(%08X,%08X)=%d", (unsigned) arg, (unsigned) &ec_info_copy, nIgnoredBytes);
				result = -1;
				break;
			}

			spin_lock_irqsave (&ec_spinlock, spinlock_flags);
			if((ec_info_copy.m_nMode & MODEMASK_MULTIPLE_BUFFER) == 0) {
				// Original buffer
				if(ec_info.after_last < ec_info.first) {
					ec_info.buffer_effect = ec_info.buffer_size;
				}
				ec_info.first = ec_info_copy.after_last;
				ec_info.trace_size = ec_info.trace_size - ec_info_copy.trace_size;
			} else {
				// Relay FS buffer
#ifndef __DISABLE_RELAYFS
				pRelayChannel = GetRelayChannel();
				if(pRelayChannel == NULL) {
					EPRINTF("Null pointer to relay channel!");
					result = -1;
					break;
				}
				buf = pRelayChannel->buf[0];
				nNumOfSubbufs = pRelayChannel->n_subbufs;

				nSubbufSize = pRelayChannel->subbuf_size;
				pConsume = buf->start + buf->subbufs_consumed % nNumOfSubbufs * nSubbufSize;
				memcpy(&nPaddingLength, pConsume, sizeof(unsigned int));
				memcpy(&nSubbufDiscardedCount, pConsume + sizeof(unsigned int), sizeof(unsigned int));
				nEffectSize = nSubbufSize - nPaddingLength;
				nDataSize = nEffectSize - RELAY_SUBBUF_HEADER_SIZE;
				relay_subbufs_consumed(pRelayChannel, 0, 1);
				ec_info.m_nBeginSubbufNum = buf->subbufs_consumed % nNumOfSubbufs;
				ec_info.m_nEndSubbufNum = buf->subbufs_produced % nNumOfSubbufs;
				ec_info.buffer_effect -= nEffectSize;
				ec_info.trace_size -= nDataSize;
				buf->dentry->d_inode->i_size = ec_info.trace_size;
#endif
			}
			spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
			result = 0;
//			DPRINTF("Consume Buffer"); // Frequent call
			break;
		}
	case EC_IOCTL_ADD_PROBE:
		{
			unsigned long addr = arg;
			result = add_probe(addr);

			break;
		}
	//@AGv: remove_probe expects probe address instead of name
	/*case EC_IOCTL_REMOVE_PROBE:
		{
			char *probe_name = (char *) arg;
			result = remove_probe (probe_name);

			break;
		}*/
	case EC_IOCTL_SET_APPDEPS:
	{
		size_t size;
		result = copy_from_user(&size, (void *)arg, sizeof(size_t));
		if (result) {
			EPRINTF("Cannot copy deps size!\n");
			result = -1;
			break;
		}
		DPRINTF("Deps size has been copied (%d)\n", size);

		deps = vmalloc(size);
		if (deps == NULL) {
			EPRINTF("Cannot alloc mem for deps!\n");
			result = -1;
			break;
		}
		DPRINTF("Mem for deps has been alloced\n");

		result = copy_from_user(deps, (void *)arg, size);
		if (result) {
			EPRINTF("Cannot copy deps!\n");
			result = -1;
			break;
		}
		DPRINTF("Deps has been copied successfully\n");

		break;
	}
	case EC_IOCTL_SET_PROFILEBUNDLE:
	{
		size_t size;

		result = copy_from_user(&size, (void *)arg, sizeof(size_t));
		if (result) {
			EPRINTF("Cannot copy bundle size!\n");
			result = -1;
			break;
		}
		DPRINTF("Bundle size has been copied\n");

		bundle = vmalloc(size);
		if (bundle == NULL) {
			EPRINTF("Cannot alloc mem for bundle!\n");
			result = -1;
			break;
		}
		DPRINTF("Mem for bundle has been alloced\n");

		result = copy_from_user(bundle, (void *)arg, size);
		if (result) {
			EPRINTF("Cannot copy bundle!\n");
			result = -1;
			break;
		}
		DPRINTF("Bundle has been copied successfully\n");

		if (link_bundle() == -1) {
			EPRINTF("Cannot link profile bundle!\n");
			result = -1;
			break;
		}

		break;
	}
	case EC_IOCTL_RESET_PROBES:
		{
			result = reset_probes();

			break;
		}
	case EC_IOCTL_UPDATE_CONDS:
		{
			int args_cnt, i;
			struct cond *c, *c_tmp, *p_cond;
			unsigned char *p_data;
			int err;
			result = 0;
			err = copy_from_user(&args_cnt, (void *)arg, sizeof(int));
			if (err) {
				result = -1;
				break;
			}
			/* first, delete all the conds */
			list_for_each_entry_safe(c, c_tmp, &cond_list.list, list) {
				list_del(&c->list);
				kfree(c);
			}
			/* second, add new conds */
			p_data = (unsigned char *)(arg + sizeof(int));
			for (i = 0; i < args_cnt; i++) {
				p_cond = kmalloc(sizeof(struct cond), GFP_KERNEL);
				if (!p_cond) {
					DPRINTF("Cannot alloc cond!\n");
					result = -1;
					break;
				}
				err = copy_from_user(&p_cond->tmpl, p_data, sizeof(struct event_tmpl));
				if (err) {
					DPRINTF("Cannot copy cond from user!\n");
					result = -1;
					break;
				}
				p_cond->applied = 0;
				list_add(&(p_cond->list), &(cond_list.list));
				p_data += sizeof(struct event_tmpl);
			}
			break;
		}
	case EC_IOCTL_ATTACH:
		result = ec_user_attach ();
		blocking_notifier_call_chain(&inperfa_notifier_list, EC_IOCTL_ATTACH, (void*)NULL);
		DPRINTF("Attach Probes");
		break;
	case EC_IOCTL_ACTIVATE:
		result = ec_user_activate ();
		DPRINTF("Activate Probes");
		break;
	case EC_IOCTL_STOP_AND_DETACH:
	{
		unsigned long nIgnoredBytes = 0;
		if(ec_user_stop() != 0) {
			result = -1;
			break;
		}
		nIgnoredBytes = copy_ec_info_to_user_space ((ec_info_t*)arg);
		if(nIgnoredBytes > 0) {
			result = -1;
			break;
		}
		vfree(bundle);
		result = 0;
		DPRINTF("Stop and Detach Probes");
		blocking_notifier_call_chain(&inperfa_notifier_list, EC_IOCTL_STOP_AND_DETACH, (void*)&gl_nNotifyTgid);
		break;
	}
	case EC_IOCTL_WAIT_NOTIFICATION:
		{
			static ec_info_t ec_info_copy;

			ioctl_wait_notification_t ioctl_args;

			result = copy_from_user (&ioctl_args, (void *) arg, sizeof (ioctl_args));
			if (result)
			{
				result = -1;
				break;
			}

			result = wait_event_interruptible (notification_waiters_queue, ioctl_args.notification_count != notification_count);
			if (result)
			{
				result = -EINTR;	// woken by signal (ERESTARTSYS 512)
				break;
			}

			ioctl_args.notification_count = notification_count;

			result = copy_to_user ((void *) arg, &ioctl_args, sizeof (ioctl_args));
			if (result)
			{
				result = -1;
				break;
			}

			// FIXME: synchronization is necessary here (ec_info must be locked).
			// ENTER_CRITICAL_SECTION
			memcpy (&ec_info_copy, &ec_info, sizeof (ec_info_copy));
			// LEAVE_CRITICAL_SECTION

			result = copy_to_user ((void *) ioctl_args.p_ec_info, &ec_info_copy, sizeof (ec_info_t));
			if (result)
			{
				EPRINTF ("copy_to_user(%08X,%08X)=%d", (unsigned) ioctl_args.p_ec_info, (unsigned) &ec_info_copy, result);
				result = -1;
				break;
			}
			DPRINTF("Wake up");
			break;
		}
	case EC_IOCTL_INST_USR_SPACE_PROC:
		{
			ioctl_inst_usr_space_proc_t ioctl_args;
			result = copy_from_user (&ioctl_args, (void *) arg, sizeof (ioctl_args));
			if (result)
			{
				result = -1;
				EPRINTF ("copy_from_user() failure");
			}
			else
			{
				result = set_us_proc_inst_info (&ioctl_args);
			}
			DPRINTF("Instrument User Space Procedures");
			break;
		}
	case EC_IOCTL_DEINST_USR_SPACE_PROC:
		{
			release_us_proc_inst_info ();
			result = 0;
			DPRINTF("Deinstrument User Space Procedures");
			break;
		}
	case EC_IOCTL_US_EVENT:
		{
			ioctl_us_event_t ioctl_args;
			result = copy_from_user (&ioctl_args, (void *) arg, sizeof (ioctl_args));
			if (result)
			{
				result = -1;
				EPRINTF ("copy_from_user() failure");
			}
			else
			{
				if(ioctl_args.len == 0){
					result = -EINVAL;
					EPRINTF ("invalid event length!");					
				}
				else {
					char *buf = kmalloc(ioctl_args.len, GFP_KERNEL);
					if(!buf){
						result = -ENOMEM;
						EPRINTF ("failed to alloc mem for event!");					
					}
					else {
						result = copy_from_user (buf, (void *) ioctl_args.data, ioctl_args.len);
						if (result){
							result = -1;
							EPRINTF ("failed to copy event from user space!");
						}
						else
							result = put_us_event(buf, ioctl_args.len);
						kfree(buf);
					}
				}
			}
//			DPRINTF("User Space Event"); // Frequent call
			break;
		}
		
	case EC_IOCTL_SET_EVENT_MASK:
		{
			int mask;
			result = copy_from_user (&mask, (void *) arg, sizeof (mask));
			if (result)
			{
				result = -EFAULT;
				break;
			}

			result = set_event_mask (mask);
			if (result)
			{
				break;
			}
			DPRINTF("Set Event Mask = %d", mask);
			break;
		}

	case EC_IOCTL_GET_EVENT_MASK:
		{
			int mask = 0;
			result = get_event_mask(&mask);
			if (result)
			{
				result = -EFAULT;
			}
			result = copy_to_user ((void *) arg, &mask, sizeof (mask));
			if (result)
			{
				result = -EFAULT;
			}
			DPRINTF("Get Event Mask = %d", mask);
			break;
		}

	case EC_IOCTL_SET_PREDEF_UPROBES:
		{
			ioctl_predef_uprobes_info_t data;
			result = copy_from_user (&data, (void *) arg, sizeof (data));
			if (result)
			{
				result = -EFAULT;
				break;
			}

			result = set_predef_uprobes (&data);
			if (result)
			{
				break;
			}
			DPRINTF("Set Predefined User Space Probes");
			break;
		}
		
	case EC_IOCTL_GET_PREDEF_UPROBES:
		{
			result = get_predef_uprobes((ioctl_predef_uprobes_info_t *)arg);
			if (result)
			{
				result = -EFAULT;
			}
			DPRINTF("Get Predefined User Space Probes");
			break;
		}
		
	case EC_IOCTL_GET_PREDEF_UPROBES_SIZE:
		{
			int size = 0;
			result = get_predef_uprobes_size(&size);
			if (result)
			{
				result = -EFAULT;
			}
			result = copy_to_user ((void *) arg, &size, sizeof (size));
			if (result)
			{
				result = -EFAULT;
			}
			DPRINTF("Get Size of Predefined User Space Probes");
			break;
		}
	
	default:
		EPRINTF ("Unknown driver command = %u", cmd);
		result = -EINVAL;
		break;
	}

	return result;
}
