////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           storage.c
//
//      DESCRIPTION:
//      This file is C source for SWAP.
//
//      SEE ALSO:       storage.h
//      AUTHOR:         L.Komkov, S.Dianov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include <linux/types.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/unistd.h>
#include "module.h"
#include "storage.h"
#include "CProfile.h"

#define after_buffer ec_info.buffer_size


char *p_buffer = NULL;
inst_us_proc_t us_proc_info;
char *deps;
char *bundle;
unsigned int inst_pid = 0;
struct hlist_head kernel_probes;
int event_mask = 0L;
struct cond cond_list;
int paused = 0; /* a state after a stop condition (events are not collected) */
struct timeval last_attach_time = {0, 0};

EXPORT_SYMBOL_GPL(us_proc_info);
int (*mec_post_event)(char *data, unsigned long len) = NULL;

unsigned copy_into_cyclic_buffer (char *buffer, unsigned dst_offset, char *src, unsigned size)
{
	unsigned nOffset = dst_offset;
	char* pSource = src;
	while (size--)
		buffer[nOffset++] = *pSource++;
	return nOffset;
}

unsigned copy_from_cyclic_buffer (char *dst, char *buffer, unsigned src_offset, unsigned size)
{
	unsigned nOffset = src_offset;
	char* pDestination = dst;
	while (size--)
		*pDestination++ = buffer[nOffset++];
	return nOffset;
}

int CheckBufferSize (unsigned int nSize)
{
	if (nSize < EC_BUFFER_SIZE_MIN) {
		EPRINTF("Too small buffer size! [Size=%u KB]", nSize / 1024);
		return -1;
	}
	if (nSize > EC_BUFFER_SIZE_MAX) {
		EPRINTF("Too big buffer size! [Size=%u KB]", nSize / 1024);
		return -1;
	}
	return 0;
}

int AllocateSingleBuffer(unsigned int nSize)
{
	unsigned long spinlock_flags = 0L;

	unsigned int nSubbufferSize = ec_info.m_nSubbufSize;
	unsigned int nNumOfSubbufers = GetNumOfSubbuffers(nSize);
	unsigned long nAllocatedSize = nSubbufferSize * nNumOfSubbufers;

	p_buffer = vmalloc_user(nAllocatedSize);
	if(!p_buffer) {
		EPRINTF("Memory allocation error! [Size=%lu KB]", nAllocatedSize / 1024);
		return -1;
	}

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nNumOfSubbuffers = nNumOfSubbufers;
	ec_info.buffer_effect = ec_info.buffer_size = nAllocatedSize;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

void FreeSingleBuffer (void)
{
	VFREE_USER(p_buffer, ec_info.buffer_size);
	CleanECInfo();
}

//////////////////////////////////////////////////////////////////////////////////////////////////

int EnableContinuousRetrieval() {
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode |= MODEMASK_CONTINUOUS_RETRIEVAL;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

int DisableContinuousRetrieval() {
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode &= ~MODEMASK_CONTINUOUS_RETRIEVAL;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __DISABLE_RELAYFS

struct rchan* gl_pRelayChannel = NULL;
struct rchan* GetRelayChannel(void) { return gl_pRelayChannel; };

struct dentry* gl_pdirRelay = NULL;
struct dentry* GetRelayDir(void) { return gl_pdirRelay; };

#ifdef __USE_PROCFS

struct proc_dir_entry* alt_pde = NULL;

static inline struct dentry *_dir_create (const char *dirname, struct dentry *parent, struct proc_dir_entry **p2pde)
{
    struct dentry *dir;
    struct proc_dir_entry *pde;

    pde = proc_mkdir (dirname, PDE (parent->d_inode));
    if (pde == NULL)
    {
        dir = NULL;
    }
    else
    {
        mutex_lock (&parent->d_inode->i_mutex);
        dir = lookup_one_len (dirname, parent, strlen (dirname));
        mutex_unlock (&parent->d_inode->i_mutex);

        if (IS_ERR (dir))
        {
            dir = NULL;
            remove_proc_entry (dirname, PDE (parent->d_inode));
        }

        *p2pde = pde;
    }

    return dir;
}

static inline struct dentry *_get_proc_root (void)
{
    struct file_system_type *procfs_type;
    struct super_block *procfs_sb;

    procfs_type = get_fs_type ("proc");

    if (!procfs_type || list_empty (&procfs_type->fs_supers))
        return NULL;

    procfs_sb = list_entry (procfs_type->fs_supers.next, \
        struct super_block, s_instances);

    return procfs_sb->s_root;

}

static struct dentry *create_buf (const char *filename, struct dentry *parent, int mode, struct rchan_buf *buf, int *is_global)
{
    struct proc_dir_entry *pde;
    struct proc_dir_entry *parent_pde = NULL;
    struct dentry *dentry;

    if (parent)
        parent_pde = PDE (parent->d_inode);
    else
        parent = _get_proc_root ();

    pde = create_proc_entry (filename, S_IFREG|S_IRUSR, parent_pde);

    if(unlikely(!pde))
        return NULL;

    pde->proc_fops = &relay_file_operations;

    mutex_lock (&parent->d_inode->i_mutex);
    dentry = lookup_one_len (filename, parent, strlen (filename));
    mutex_unlock (&parent->d_inode->i_mutex);

    if (IS_ERR(dentry)) {
        remove_proc_entry (filename, parent_pde);
	}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
	dentry->d_inode->i_private = buf;
#else
	dentry->d_inode->u.generic_ip = buf;
#endif

    return dentry;

}

static int remove_buf (struct dentry *dentry)
{
    if (dentry != NULL)
    {
        struct proc_dir_entry *pde = PDE (dentry->d_inode);
        dput (dentry);
        remove_proc_entry (pde->name, pde->parent);
    }
    
    return 0;
}

#endif // __USE_PROCFS
	/*
          * subbuf_start - called on buffer-switch to a new sub-buffer
          * @buf: the channel buffer containing the new sub-buffer
          * @subbuf: the start of the new sub-buffer
          * @prev_subbuf: the start of the previous sub-buffer
          * @prev_padding: unused space at the end of previous sub-buffer
          *
          * The client should return 1 to continue logging, 0 to stop
          * logging.
          *
          * NOTE: subbuf_start will also be invoked when the buffer is
          *       created, so that the first sub-buffer can be initialized
          *       if necessary.  In this case, prev_subbuf will be NULL.
          *
          * NOTE: the client can reserve bytes at the beginning of the new
          *       sub-buffer by calling subbuf_start_reserve() in this callback.
          */
int RelayCallbackSubbufStart(struct rchan_buf *buf,
                              void *subbuf,
                              void *prev_subbuf,
                              size_t prev_padding)
{
	struct rchan* pRelayChannel = NULL;
	unsigned int nNumOfSubbufs = 0;

	unsigned long spinlock_flags = 0L;
	spin_lock_irqsave (&ec_spinlock, spinlock_flags);

	subbuf_start_reserve(buf, RELAY_SUBBUF_HEADER_SIZE);
	ec_info.buffer_effect += RELAY_SUBBUF_HEADER_SIZE;
	ec_info.m_nEndOffset = RELAY_SUBBUF_HEADER_SIZE;

	if(prev_subbuf == NULL) {
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
		return 1;
	}
	memcpy(prev_subbuf, &prev_padding, sizeof(unsigned int));
	memcpy(prev_subbuf + sizeof(unsigned int), &ec_info.m_nSubbufSavedEvents, sizeof(unsigned int));
	ec_info.m_nSubbufSavedEvents = 0;
	pRelayChannel = GetRelayChannel();
	if(pRelayChannel == NULL) {
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
		EPRINTF("Null pointer to relay channel!");
		return 0;
	}
	nNumOfSubbufs = pRelayChannel->n_subbufs;
	ec_info.m_nBeginSubbufNum = buf->subbufs_consumed % nNumOfSubbufs;
	ec_info.m_nEndSubbufNum = buf->subbufs_produced % nNumOfSubbufs;
	if(relay_buf_full(buf)) {
		void* pConsume = NULL;
		unsigned int nPaddingLength = 0;
		unsigned int nSubbufSize = 0;
		unsigned int nDataSize = 0;
		unsigned int nEffectSize = 0;
		unsigned int nSubbufDiscardedCount = 0;
		nSubbufSize = pRelayChannel->subbuf_size;
		pConsume = buf->start + buf->subbufs_consumed % nNumOfSubbufs * nSubbufSize;
		memcpy(&nPaddingLength, pConsume, sizeof(unsigned int));
		memcpy(&nSubbufDiscardedCount, pConsume + sizeof(unsigned int), sizeof(unsigned int));
		nEffectSize = nSubbufSize - nPaddingLength;
		nDataSize = nEffectSize - RELAY_SUBBUF_HEADER_SIZE;
		ec_info.discarded_events_count += nSubbufDiscardedCount;
		relay_subbufs_consumed(pRelayChannel, 0, 1);
		ec_info.m_nBeginSubbufNum = buf->subbufs_consumed % nNumOfSubbufs;
		ec_info.m_nEndSubbufNum = buf->subbufs_produced % nNumOfSubbufs;
		ec_info.buffer_effect -= nEffectSize;
		ec_info.trace_size -= nDataSize;
		buf->dentry->d_inode->i_size = ec_info.trace_size;
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
		return 1; // Overwrite mode
	}
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
	return 1;
}
 
	/*
          * buf_mapped - relay buffer mmap notification
          * @buf: the channel buffer
          * @filp: relay file pointer
          *
          * Called when a relay file is successfully mmapped
          */
void RelayCallbackBufMapped(struct rchan_buf *buf,
                            struct file *filp)
{
}

	/*
          * buf_unmapped - relay buffer unmap notification
          * @buf: the channel buffer
          * @filp: relay file pointer
          *
          * Called when a relay file is successfully unmapped
          */
void RelayCallbackBufUnmapped(struct rchan_buf *buf,
                             struct file *filp)
{
}
	/*
          * create_buf_file - create file to represent a relay channel buffer
          * @filename: the name of the file to create
          * @parent: the parent of the file to create
          * @mode: the mode of the file to create
          * @buf: the channel buffer
          * @is_global: outparam - set non-zero if the buffer should be global
          *
          * Called during relay_open(), once for each per-cpu buffer,
          * to allow the client to create a file to be used to
          * represent the corresponding channel buffer.  If the file is
          * created outside of relay, the parent must also exist in
          * that filesystem.
          *
          * The callback should return the dentry of the file created
          * to represent the relay buffer.
          *
          * Setting the is_global outparam to a non-zero value will
          * cause relay_open() to create a single global buffer rather
          * than the default set of per-cpu buffers.
          *
          * See Documentation/filesystems/relayfs.txt for more info.
          */
struct dentry * RelayCallbackCreateBufFile(const char *filename,
                                           struct dentry *parent,
                                           int mode,
                                           struct rchan_buf *buf,
                                           int *is_global)
{
	*is_global = 1;
#ifdef __USE_PROCFS
	DPRINTF("\"%s\" is creating in procfs...!", filename);
	return create_buf(filename, parent, mode, buf, is_global);
#else
	DPRINTF("\"%s\" is creating in debugfs...!", filename);
	return debugfs_create_file(filename, (mode_t)mode, parent, buf, &relay_file_operations);
#endif // __USE_PROCFS
}
 
	/*
          * remove_buf_file - remove file representing a relay channel buffer
          * @dentry: the dentry of the file to remove
          *
          * Called during relay_close(), once for each per-cpu buffer,
          * to allow the client to remove a file used to represent a
          * channel buffer.
          *
          * The callback should return 0 if successful, negative if not.
          */
int RelayCallbackRemoveBufFile(struct dentry *dentry)
{
#ifdef __USE_PROCFS
	remove_buf(dentry);
#else
	debugfs_remove(dentry);
#endif // __USE_PROCFS
	return 0;
}

struct rchan_callbacks gl_RelayCallbacks = {
	.subbuf_start = RelayCallbackSubbufStart,
	.buf_mapped = RelayCallbackBufMapped,
	.buf_unmapped = RelayCallbackBufUnmapped,
	.create_buf_file = RelayCallbackCreateBufFile,
	.remove_buf_file = RelayCallbackRemoveBufFile
};
#endif //__DISABLE_RELAYFS

int AllocateMultipleBuffer(unsigned int nSize) {
#ifndef __DISABLE_RELAYFS
	unsigned long spinlock_flags = 0L;

	unsigned int nSubbufferSize = ec_info.m_nSubbufSize;
	unsigned int nNumOfSubbufers = GetNumOfSubbuffers(nSize);

	gl_pRelayChannel = relay_open(DEFAULT_RELAY_BASE_FILENAME,
					GetRelayDir(),
					nSubbufferSize,
					nNumOfSubbufers,
					&gl_RelayCallbacks
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
					,NULL
#endif
					);
	if(gl_pRelayChannel == NULL) {
		EPRINTF("Cannot create relay buffer channel! [%d subbufers by %u Kb = %u Kb]",
			nNumOfSubbufers, nSubbufferSize / 1024, nSize / 1024);
		return -1;
	}

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nNumOfSubbuffers = nNumOfSubbufers;
	ec_info.buffer_effect = ec_info.buffer_size = nSubbufferSize * nNumOfSubbufers;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
#else
	EPRINTF("RelayFS not supported!");
	return -1;
#endif //__DISABLE_RELAYFS
}

void FreeMultipleBuffer(void) {
#ifndef __DISABLE_RELAYFS
	relay_close(gl_pRelayChannel);
	CleanECInfo();
#else
	EPRINTF("RelayFS not supported!");
#endif //__DISABLE_RELAYFS
}

int InitializeBuffer(unsigned int nSize) {
	if(IsMultipleBuffer())
		return AllocateMultipleBuffer(nSize);
	return AllocateSingleBuffer(nSize);
}

int UninitializeBuffer(void) {
	if(IsMultipleBuffer())
		FreeMultipleBuffer();
	FreeSingleBuffer();
	return 0;
}

int EnableMultipleBuffer() {
	unsigned long spinlock_flags = 0L;

	if(IsMultipleBuffer())
		return 0;

	if(UninitializeBuffer() == -1)
		EPRINTF("Cannot uninitialize buffer!");

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode |= MODEMASK_MULTIPLE_BUFFER;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	if(InitializeBuffer(GetBufferSize()) == -1) {
		EPRINTF("Cannot initialize buffer!");
		return -1;
	}
	return 0;
}

int DisableMultipleBuffer() {
	unsigned long spinlock_flags = 0L;

	if(!IsMultipleBuffer())
		return 0;

	if(UninitializeBuffer() == -1)
		EPRINTF("Cannot uninitialize buffer!");

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode &= ~MODEMASK_MULTIPLE_BUFFER;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	if(InitializeBuffer(GetBufferSize()) == -1) {
		EPRINTF("Cannot initialize buffer!");
		return -1;
	}
	return 0;
}

unsigned int GetBufferSize(void) { return ec_info.buffer_size; };

int SetBufferSize(unsigned int nSize) {
	if (GetECState() != EC_STATE_IDLE) {
		EPRINTF("Buffer changes are allowed in IDLE state only (%d)!", GetECState());
		return -1;
	}
	if(GetBufferSize() == nSize)
		return 0;
	if(CheckBufferSize(nSize) == -1) {
		EPRINTF("Invalid buffer size!");
		return -1;
	}
	detach_selected_probes ();
	if(UninitializeBuffer() == -1)
		EPRINTF("Cannot uninitialize buffer!");
	if(InitializeBuffer(nSize) == -1) {
		EPRINTF("Cannot initialize buffer! [Size=%u KB]", nSize / 1024);
		return -1;
	}
	return 0;
}

int SetPid(unsigned int pid)
{
	if (GetECState() != EC_STATE_IDLE)
	{
		EPRINTF("PID changes are allowed in IDLE state only (%d)!", GetECState());
		return -1;
	}

	inst_pid = pid;
	DPRINTF("SetPid pid:%d\n", pid);
	return 0;
}

void ResetSingleBuffer(void) {
}

void ResetMultipleBuffer(void) {
#ifndef __DISABLE_RELAYFS
	relay_reset(gl_pRelayChannel);
#else
	EPRINTF("RelayFS not supported!");
#endif //__DISABLE_RELAYFS
}

int ResetBuffer(void) {
	unsigned long spinlock_flags = 0L;

	if (GetECState() != EC_STATE_IDLE) {
		EPRINTF("Buffer changes are allowed in IDLE state only!");
		return -1;
	}

	if(IsMultipleBuffer())
		ResetMultipleBuffer();
	else
		ResetSingleBuffer();

	detach_selected_probes ();

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.buffer_effect = ec_info.buffer_size;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	ResetECInfo();

	return 0;
}

int WriteEventIntoSingleBuffer(char* pEvent, unsigned long nEventSize) {
	unsigned long spinlock_flags = 0L;
	int bCopied = 0;

	if(!p_buffer) {
		EPRINTF("Invalid pointer to buffer!");
		++ec_info.lost_events_count;
		return -1;
	}
	unsigned int unused_space;
	if (ec_info.trace_size == 0 || ec_info.after_last > ec_info.first) {
		unused_space = ec_info.buffer_size - ec_info.after_last;
		if (unused_space > nEventSize) {
			ec_info.after_last = copy_into_cyclic_buffer(p_buffer,
														 ec_info.after_last,
														 pEvent,
														 nEventSize);
			ec_info.saved_events_count++;
			ec_info.buffer_effect = ec_info.buffer_size;
			ec_info.trace_size = ec_info.after_last - ec_info.first;
		} else {
			if (ec_info.first > nEventSize) {
				ec_info.buffer_effect = ec_info.after_last;
				ec_info.after_last = copy_into_cyclic_buffer(p_buffer,
															 0,
															 pEvent,
															 nEventSize);
				ec_info.saved_events_count++;
				ec_info.trace_size = ec_info.buffer_effect
					- ec_info.first
					+ ec_info.after_last;
			} else {
				// TODO: consider two variants!
				// Do nothing
				ec_info.discarded_events_count++;
			}
		}
	} else {
		unused_space = ec_info.first - ec_info.after_last;
		if (unused_space > nEventSize) {
			ec_info.after_last = copy_into_cyclic_buffer(p_buffer,
														 ec_info.after_last,
														 pEvent,
														 nEventSize);
			ec_info.saved_events_count++;
			ec_info.trace_size = ec_info.buffer_effect
				- ec_info.first
				+ ec_info.after_last;
		} else {
			// Do nothing
			ec_info.discarded_events_count++;
		}
	}
	return 0;
}

int WriteEventIntoMultipleBuffer(char* pEvent, unsigned long nEventSize) {
#ifndef __DISABLE_RELAYFS
	unsigned long spinlock_flags = 0L;
	__relay_write(GetRelayChannel(), pEvent, nEventSize);
	ec_info.buffer_effect += nEventSize;
	ec_info.trace_size += nEventSize;
	ec_info.saved_events_count++;
	ec_info.m_nEndOffset += nEventSize;
	ec_info.m_nSubbufSavedEvents++;
	return 0;
#else
	EPRINTF("RelayFS not supported!");
	return -1;
#endif //__DISABLE_RELAYFS
}

int WriteEventIntoBuffer(char* pEvent, unsigned long nEventSize) {

	/*unsigned long i;
	for(i = 0; i < nEventSize; i++)
		printk("%02X ", pEvent[i]);
	printk("\n");*/

	if(IsMultipleBuffer())
		return WriteEventIntoMultipleBuffer(pEvent, nEventSize);
	return WriteEventIntoSingleBuffer(pEvent, nEventSize);
}

//////////////////////////////////////////////////////////////////////////////////////////////////

int set_event_mask (int new_mask)
{
	unsigned long spinlock_flags = 0L;
	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	event_mask = new_mask;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
	return 0;
}

int
get_event_mask (int *mask)
{
	*mask = event_mask;
	return 0;
}

static void
generic_swap (void *a, void *b, int size)
{
	char t;
	do {
		t = *(char *) a;
		*(char *) a++ = *(char *) b;
		*(char *) b++ = t;
	} while (--size > 0);
}

static void sort (void *base, size_t num, size_t size, int (*cmp) (const void *, const void *), void (*fswap) (void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num / 2) * size, n = num * size, c, r;

	/* heapify */
	for (; i >= 0; i -= size)
	{
		for (r = i; r * 2 < n; r = c)
		{
			c = r * 2;
			if (c < n - size && cmp (base + c, base + c + size) < 0)
				c += size;
			if (cmp (base + r, base + c) >= 0)
				break;
			fswap (base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i >= 0; i -= size)
	{
		fswap (base, base + i, size);
		for (r = 0; r * 2 < i; r = c)
		{
			c = r * 2;
			if (c < i - size && cmp (base + c, base + c + size) < 0)
				c += size;
			if (cmp (base + r, base + c) >= 0)
				break;
			fswap (base + r, base + c, size);
		}
	}
}

static int addr_cmp (const void *a, const void *b)
{
	return *(unsigned long *) a > *(unsigned long *) b ? -1 : 1;
}

char *find_lib_path(const char *lib_name)
{
	char *p = deps + sizeof(size_t);
	char *match;
	size_t len;

	while (*p != '\0') {
		DPRINTF("p is at %s", p);
		len = strlen(p) + 1;
		match = strstr(p, lib_name);
		p += len;
		len = strlen(p) + 1; /* we are at path now */
		if (!match) {
			p += len;
		} else {
			DPRINTF("Found match: %s", match);
			return p;
		}
	}

	return p;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 27)
#define list_for_each_rcu(pos, head) __list_for_each_rcu(pos, head)
#endif

void unlink_bundle(void)
{
	int i, k;
	us_proc_lib_t *d_lib;
	char *path;
	struct list_head *pos;	//, *tmp;

	path = us_proc_info.path;
	us_proc_info.path = 0;

	// first make sure "d_lib" is not used any more and only
	// then release storage
	if (us_proc_info.p_libs)
	{
		int count1 = us_proc_info.libs_count;
		us_proc_info.libs_count = 0;
		for (i = 0; i < count1; i++)
		{
			d_lib = &us_proc_info.p_libs[i];
			if (d_lib->p_ips)
			{
				// first make sure "d_lib->p_ips" is not used any more and only
				// then release storage
				//int count2 = d_lib->ips_count;
				d_lib->ips_count = 0;
				/*for (k = 0; k < count2; k++)
					kfree ((void *) d_lib->p_ips[k].name);*/
				vfree ((void *) d_lib->p_ips);
			}
			if (d_lib->p_vtps)
			{
				// first make sure "d_lib->p_vtps" is not used any more and only
				// then release storage
				int count2 = d_lib->vtps_count;
				d_lib->vtps_count = 0;
				for (k = 0; k < count2; k++)
				{
					//list_for_each_safe_rcu(pos, tmp, &d_lib->p_vtps[k].list) {
					list_for_each_rcu (pos, &d_lib->p_vtps[k].list)
					{
						us_proc_vtp_data_t *vtp = list_entry (pos, us_proc_vtp_data_t, list);
						list_del_rcu (pos);
						//kfree (vtp->name);
						kfree (vtp);
					}
				}
				kfree ((void *) d_lib->p_vtps);
			}
		}
		kfree ((void *) us_proc_info.p_libs);
		us_proc_info.p_libs = 0;
	}
	/* if (path) */
	/* { */
	/* 	kfree ((void *) path); */
	/* 	//putname(path); */
	/* } */

	us_proc_info.tgid = 0;
}

int link_bundle()
{
	inst_us_proc_t *my_uprobes_info;
	inst_us_proc_t empty_uprobes_info =
	{
		.libs_count = 0,
		.p_libs = NULL,
	};
	char *p = bundle; /* read pointer for bundle */
	int nr_kern_probes;
	int i, j, l, k;
	int len;
	us_proc_lib_t *d_lib, *pd_lib;
	ioctl_usr_space_lib_t s_lib;
	ioctl_usr_space_vtp_t *s_vtp;
	us_proc_vtp_t *mvtp;
	struct nameidata nd;
	int is_app = 0;
	char *ptr;
	us_proc_ip_t *d_ip;
	struct cond *c, *c_tmp, *p_cond;
	size_t nr_conds;
	int lib_name_len;
	int handler_index;

	/* Get user-defined us handlers (if they are provided) */
	my_uprobes_info = (inst_us_proc_t *)lookup_name("my_uprobes_info");
	if (my_uprobes_info == 0)
		my_uprobes_info = &empty_uprobes_info;

	DPRINTF("Going to release us_proc_info");
	if (us_proc_info.path)
		unlink_bundle();

	/* Skip size - it has been used before */
	p += sizeof(u_int32_t);

	/* Set mode */
	if (SetECMode(*(u_int32_t *)p) == -1) {
		EPRINTF("Cannot set mode!\n");
		return -1;
	}
	p += sizeof(u_int32_t);

	/* Buffer size */
	if (SetBufferSize(*(u_int32_t *)p) == -1) {
		EPRINTF("Cannot set buffer size!\n");
		return -1;
	}
	p += sizeof(u_int32_t);

	/* Pid */
	if (SetPid(*(u_int32_t *)p) == -1) {
		EPRINTF("Cannot set pid!\n");
		return -1;
	}
	p += sizeof(u_int32_t);

	/* Kernel probes */
	nr_kern_probes = *(u_int32_t *)p;
	p += sizeof(u_int32_t);
	for (i = 0; i < nr_kern_probes; i++) {
		if (add_probe(*(u_int32_t *)p)) {
			EPRINTF("Cannot add kernel probe at 0x%x!\n", *(u_int32_t *)p);
			return -1;
		}
		p += sizeof(u_int32_t);
	}

	/* Us probes */
	len = *(u_int32_t *)p; /* App path len */
	p += sizeof(u_int32_t);
	if ( len == 0 ) {
	    us_proc_info.path = NULL;
	}
	else {
	us_proc_info.path = (char *)p;
	DPRINTF("app path = %s", us_proc_info.path);
	p += len;
	if (strcmp(us_proc_info.path, "*")) {
	    if (path_lookup(us_proc_info.path, LOOKUP_FOLLOW, &nd) != 0) {
			EPRINTF("failed to lookup dentry for path %s!", us_proc_info.path);
			return -1;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	    us_proc_info.m_f_dentry = nd.dentry;
	    path_release(&nd);
#else
	    us_proc_info.m_f_dentry = nd.path.dentry;
	    path_put(&nd.path);
#endif
	} else {
	    us_proc_info.m_f_dentry = NULL;
	}
	us_proc_info.libs_count = *(u_int32_t *)p;
	DPRINTF("nr of libs = %d", us_proc_info.libs_count);
	p += sizeof(u_int32_t);
	us_proc_info.p_libs =
		kmalloc(us_proc_info.libs_count * sizeof(us_proc_lib_t), GFP_KERNEL);
	if (!us_proc_info.p_libs) {
		EPRINTF("Cannot alloc p_libs!");
		return -1;
	}
	memset(us_proc_info.p_libs, 0,
		   us_proc_info.libs_count * sizeof(us_proc_lib_t));

	for (i = 0; i < us_proc_info.libs_count; i++) {
		d_lib = &us_proc_info.p_libs[i];
		lib_name_len = *(u_int32_t *)p;
		p += sizeof(u_int32_t);
		d_lib->path = (char *)p;
		DPRINTF("d_lib->path = %s", d_lib->path);

		p += lib_name_len;
		d_lib->ips_count = *(u_int32_t *)p;
		DPRINTF("d_lib->ips_count = %d", d_lib->ips_count);
		p += sizeof(u_int32_t);

		/* If there are any probes for "*" app we have to drop them */
		if (strcmp(d_lib->path, "*") == 0) {
			p += d_lib->ips_count * 3 * sizeof(u_int32_t);
			d_lib->ips_count = 0;
			continue;
		}

		if (strcmp(us_proc_info.path, d_lib->path) == 0)
			is_app = 1;
		else {
			is_app = 0;
			DPRINTF("Searching path for lib %s", d_lib->path);
			d_lib->path = find_lib_path(d_lib->path);
			if (!d_lib->path) {
				EPRINTF("Cannot find path!");
				return -1;
			}
		}

		if (path_lookup(d_lib->path, LOOKUP_FOLLOW, &nd) != 0) {
			EPRINTF ("failed to lookup dentry for path %s!", d_lib->path);
			p += lib_name_len;
			p += sizeof(u_int32_t);
			continue;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
		d_lib->m_f_dentry = nd.dentry;
		path_release(&nd);
#else
		d_lib->m_f_dentry = nd.path.dentry;
		d_lib->m_vfs_mount = nd.path.mnt;
		path_put(&nd.path);
#endif

		pd_lib = NULL;
		ptr = strrchr(d_lib->path, '/');
		if (ptr)
			ptr++;
		else
			ptr = d_lib->path;
		for (l = 0; l < my_uprobes_info->libs_count; l++) {
			if ((strcmp(ptr, my_uprobes_info->p_libs[l].path) == 0) ||
				(is_app && *(my_uprobes_info->p_libs[l].path) == '\0')) {
				pd_lib = &my_uprobes_info->p_libs[l];
				break;
			}
		}

		if (d_lib->ips_count > 0) {
			us_proc_info.unres_ips_count += d_lib->ips_count;
			d_lib->p_ips = vmalloc(d_lib->ips_count * sizeof(us_proc_ip_t));
			DPRINTF("d_lib[%i]->p_ips=%p/%u [%s]", i, d_lib->p_ips,
					us_proc_info.unres_ips_count, d_lib->path);
			if (!d_lib->p_ips) {
				EPRINTF("Cannot alloc p_ips!\n");
				return -1;
			}
			memset (d_lib->p_ips, 0, d_lib->ips_count * sizeof(us_proc_ip_t));
			for (k = 0; k < d_lib->ips_count; k++) {
				d_ip = &d_lib->p_ips[k];
				d_ip->offset = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				p += sizeof(u_int32_t); /* Skip inst type */
				handler_index = *(u_int32_t *)p;
				p += sizeof(u_int32_t);

				DPRINTF("pd_lib = 0x%x", pd_lib);
				if (pd_lib) {
					DPRINTF("pd_lib->ips_count = 0x%x", pd_lib->ips_count);
					if (handler_index != -1) {
						DPRINTF("found handler for 0x%x", d_ip->offset);
						d_ip->jprobe.pre_entry =
							pd_lib->p_ips[handler_index].jprobe.pre_entry;
						d_ip->jprobe.entry =
							pd_lib->p_ips[handler_index].jprobe.entry;
						d_ip->retprobe.handler =
							pd_lib->p_ips[handler_index].retprobe.handler;
					}
				}
			}
		}
	}

	/* Lib path */
	int lib_path_len = *(u_int32_t *)p;
	DPRINTF("lib_path_len = %d", lib_path_len);
	p += sizeof(u_int32_t);
	char *lib_path = p;
	DPRINTF("lib_path = %s", lib_path);
	p += lib_path_len;

	/* Link FBI info */
	d_lib = &us_proc_info.p_libs[0];
	s_lib.vtps_count = *(u_int32_t *)p;
	DPRINTF("s_lib.vtps_count = %d", s_lib.vtps_count);
	p += sizeof(u_int32_t);
	if (s_lib.vtps_count > 0) {
		s_lib.p_vtps = kmalloc(s_lib.vtps_count
							   * sizeof(ioctl_usr_space_vtp_t), GFP_KERNEL);
		if (!s_lib.p_vtps) {
			//kfree (addrs);
			return -1;
		}
		for (i = 0; i < s_lib.vtps_count; i++) {
			int var_name_len = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
			s_lib.p_vtps[i].name = p;
			p += var_name_len;
			s_lib.p_vtps[i].addr = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
			s_lib.p_vtps[i].type = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
			s_lib.p_vtps[i].size = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
			s_lib.p_vtps[i].reg = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
			s_lib.p_vtps[i].off = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
		}
		unsigned long ucount = 1, pre_addr;
		// array containing elements like (addr, index)
		unsigned long *addrs = kmalloc (s_lib.vtps_count * 2 * sizeof (unsigned long), GFP_KERNEL);
//			DPRINTF ("addrs=%p/%u", addrs, s_lib.vtps_count);
		if (!addrs)
		{
			//note: storage will released next time or at clean-up moment
			return -ENOMEM;
		}
		memset (addrs, 0, s_lib.vtps_count * 2 * sizeof (unsigned long));
		// fill the array in
		for (k = 0; k < s_lib.vtps_count; k++)
		{
			s_vtp = &s_lib.p_vtps[k];
			addrs[2 * k] = s_vtp->addr;
			addrs[2 * k + 1] = k;
		}
		// sort by VTP addresses, i.e. make VTPs with the same addresses adjacent;
		// organize them into bundles
		sort (addrs, s_lib.vtps_count, 2 * sizeof (unsigned long), addr_cmp, generic_swap);

		// calc number of VTPs with unique addresses
		for (k = 1, pre_addr = addrs[0]; k < s_lib.vtps_count; k++)
		{
			if (addrs[2 * k] != pre_addr)
				ucount++;	// count different only
			pre_addr = addrs[2 * k];
		}
		us_proc_info.unres_vtps_count += ucount;
		d_lib->vtps_count = ucount;
		d_lib->p_vtps = kmalloc (ucount * sizeof (us_proc_vtp_t), GFP_KERNEL);
		DPRINTF ("d_lib[%i]->p_vtps=%p/%lu", i, d_lib->p_vtps, ucount);	//, d_lib->path);
		if (!d_lib->p_vtps)
		{
			//note: storage will released next time or at clean-up moment
			kfree (addrs);
			return -ENOMEM;
		}
		memset (d_lib->p_vtps, 0, d_lib->vtps_count * sizeof (us_proc_vtp_t));
		// go through sorted VTPS.
		for (k = 0, j = 0, pre_addr = 0, mvtp = NULL; k < s_lib.vtps_count; k++)
		{
			us_proc_vtp_data_t *vtp_data;
			// copy VTP data
			s_vtp = &s_lib.p_vtps[addrs[2 * k + 1]];
			// if this is the first VTP in bundle (master VTP)
			if (addrs[2 * k] != pre_addr)
			{
				// data are in the array of master VTPs
				mvtp = &d_lib->p_vtps[j++];
				mvtp->addr = s_vtp->addr;
				INIT_LIST_HEAD (&mvtp->list);
			}
			// data are in the list of slave VTPs
			vtp_data = kmalloc (sizeof (us_proc_vtp_data_t), GFP_KERNEL);
			if (!vtp_data)
			{
				//note: storage will released next time or at clean-up moment
				kfree (addrs);
				return -ENOMEM;
			}

			/*len = strlen_user (s_vtp->name);
			  vtp_data->name = kmalloc (len, GFP_KERNEL);
			  if (!vtp_data->name)
			  {
			  //note: storage will released next time or at clean-up moment
			  kfree (vtp_data);
			  kfree (addrs);
			  return -ENOMEM;
			  }
			  if (strncpy_from_user (vtp_data->name, s_vtp->name, len) != (len-1))
			  {
			  //note: storage will released next time or at clean-up moment
			  EPRINTF ("strncpy_from_user VTP name failed %p (%ld)", vtp_data->name, len);
			  kfree (vtp_data->name);
			  kfree (vtp_data);
			  kfree (addrs);
			  return -EFAULT;
			  }
			  //vtp_data->name[len] = 0;*/
			vtp_data->type = s_vtp->type;
			vtp_data->size = s_vtp->size;
			vtp_data->reg = s_vtp->reg;
			vtp_data->off = s_vtp->off;
			list_add_tail_rcu (&vtp_data->list, &mvtp->list);
			pre_addr = addrs[2 * k];
		}
		kfree (addrs);
		kfree(s_lib.p_vtps);
	}


	/* Conds */
	/* first, delete all the conds */
	list_for_each_entry_safe(c, c_tmp, &cond_list.list, list) {
		list_del(&c->list);
		kfree(c);
	}
	/* second, add new conds */
	/* This can be improved (by placing conds into array) */
	nr_conds = *(u_int32_t *)p;
	DPRINTF("nr_conds = %d", nr_conds);
	p += sizeof(u_int32_t);
	for (i = 0; i < nr_conds; i++) {
		p_cond = kmalloc(sizeof(struct cond), GFP_KERNEL);
		if (!p_cond) {
			EPRINTF("Cannot alloc cond!\n");
			return -1;
			break;
		}
		memcpy(&p_cond->tmpl, p, sizeof(struct event_tmpl));
		p_cond->applied = 0;
		list_add(&(p_cond->list), &(cond_list.list));
		p += sizeof(struct event_tmpl);
	}

	/* Event mask */
	if (set_event_mask(*(u_int32_t *)p)) {
		EPRINTF("Cannot set event mask!");
		return -1;
	}

	p += sizeof(u_int32_t);

	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//
int storage_init (void)
{
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode = 0; // MASK IS CLEAR (SINGLE NON_CONTINUOUS BUFFER)
//	ec_info.m_nMode |= ECMODEMASK_MULTIPLE_BUFFER;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

#ifndef __DISABLE_RELAYFS

#ifdef __USE_PROCFS
	gl_pdirRelay = _dir_create (DEFAULT_RELAY_BASE_DIR, _get_proc_root(), &alt_pde);
	if(gl_pdirRelay == NULL) {
		EPRINTF("Cannot create procfs directory for relay buffer!");
		return -1;
	}
#else
	gl_pdirRelay = debugfs_create_dir(DEFAULT_RELAY_BASE_DIR, NULL);
	if(gl_pdirRelay == NULL) {
		EPRINTF("Cannot create directory for relay buffer!");
		return -1;
	}

#endif // __USE_PROCFS

#endif //__DISABLE_RELAYFS

	if(InitializeBuffer(EC_BUFFER_SIZE_DEFAULT) == -1) {
		EPRINTF("Cannot initialize buffer! [Size=%u KB]", EC_BUFFER_SIZE_DEFAULT / 1024 );
		return -1;
	}

	INIT_HLIST_HEAD (&kernel_probes);

	return 0;
}

/*
    Shuts down "storage".
    Assumes that all probes are already deactivated.
*/
void storage_down (void)
{
	if(UninitializeBuffer() == -1)
		EPRINTF("Cannot uninitialize buffer!");

#ifndef __DISABLE_RELAYFS

#ifdef __USE_PROCFS
//	remove_buf(gl_pdirRelay);
#else
	debugfs_remove(gl_pdirRelay);
#endif // __USE_PROCFS

#endif //__DISABLE_RELAYFS

	if (ec_info.collision_count)
		EPRINTF ("ec_info.collision_count=%d", ec_info.collision_count);
	if (ec_info.lost_events_count)
		EPRINTF ("ec_info.lost_events_count=%d", ec_info.lost_events_count);
}

u_int32_t get_probe_func_addr(const char *fmt, va_list args)
{
	if (fmt[0] != 'p')
		return 0;

	return va_arg(args, u_int32_t);
}

void pack_event_info (probe_id_t probe_id, record_type_t record_type, const char *fmt, ...)
{
	unsigned long spinlock_flags = 0L;
	static char buf[EVENT_MAX_SIZE] = "";
	TYPEOF_EVENT_LENGTH event_len = 0L;
	TYPEOF_TIME tv = { 0, 0 };
	TYPEOF_THREAD_ID current_pid = current->pid;
	TYPEOF_PROCESS_ID current_tgid = current->tgid;
	unsigned current_cpu = task_cpu(current);
	va_list args;
	unsigned long addr = 0;
	struct cond *p_cond;
	struct event_tmpl *p_tmpl;

	spin_lock_irqsave(&ec_spinlock, spinlock_flags);
	memset(buf, 0, EVENT_MAX_SIZE);
	spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);

	do_gettimeofday (&tv);

	if (probe_id == KS_PROBE_ID) {
		va_start(args, fmt);
		addr = get_probe_func_addr(fmt, args);
		va_end(args);
		if (!find_probe(addr))
			return;
		if (((addr == pf_addr) && !(probes_flags & PROBE_FLAG_PF_INSTLD)) ||
			((addr == exit_addr) && !(probes_flags & PROBE_FLAG_EXIT_INSTLD)))
			return;
	}
	if (probe_id == US_PROBE_ID) {
		va_start(args, fmt);
		addr = get_probe_func_addr(fmt, args);
		va_end(args);
	}

	/* Checking for all the conditions
	 * except stop condition that we process after saving the event */
	list_for_each_entry(p_cond, &cond_list.list, list) {
		p_tmpl = &p_cond->tmpl;
		switch (p_tmpl->type) {
		case ET_TYPE_START_COND:
			if ((!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_ADDR) ||
				 (addr == p_tmpl->addr)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_PID) ||
				 (current_tgid == p_tmpl->pid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TID) ||
				 (current_pid == p_tmpl->tid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_CPU_NUM) ||
				 (current_cpu == p_tmpl->cpu_num)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_BIN_NAME) ||
				 (strcmp(current->comm, p_tmpl->bin_name) == 0)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TIME) ||
				 (tv.tv_sec > last_attach_time.tv_sec + p_tmpl->sec) ||
				 (tv.tv_sec == last_attach_time.tv_sec + p_tmpl->sec &&
				  tv.tv_usec >= last_attach_time.tv_usec + p_tmpl->usec)) &&
				!p_cond->applied) {
				spin_lock_irqsave(&ec_spinlock, spinlock_flags);
				paused = 0;
				p_cond->applied = 1;
				spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
			}
			break;
		case ET_TYPE_IGNORE_COND:
			/* if (probe_id == PROBE_SCHEDULE) */
			/* 	break; */
			if ((!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_ADDR) ||
				 (addr == p_tmpl->addr)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_PID) ||
				 (current_tgid == p_tmpl->pid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TID) ||
				 (current_pid == p_tmpl->tid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_CPU_NUM) ||
				 (current_cpu == p_tmpl->cpu_num)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_BIN_NAME) ||
				 (strcmp(current->comm, p_tmpl->bin_name) == 0))) {
				spin_lock_irqsave(&ec_spinlock, spinlock_flags);
				ec_info.ignored_events_count++;
				spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
				return;
			}
			break;
		}
	}

	/* Save only not masked entry or return kernel and user space events */
	if (likely(!((probe_id == KS_PROBE_ID || probe_id == US_PROBE_ID)
		  && ((record_type == RECORD_ENTRY && (event_mask & IOCTL_EMASK_ENTRY))
			  || (record_type == RECORD_RET && (event_mask & IOCTL_EMASK_EXIT)))))) {

		spin_lock_irqsave (&ec_spinlock, spinlock_flags);

		if (paused && (!(probe_id == EVENT_FMT_PROBE_ID || probe_id == DYN_LIB_PROBE_ID))) {
			ec_info.ignored_events_count++;
			spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
			return;
		}

		va_start (args, fmt);
		event_len = VPackEvent(buf, sizeof(buf), event_mask, probe_id, record_type, &tv,
							   current_tgid, current_pid, current_cpu, fmt, args);
		va_end (args);

		if(event_len == 0) {
			EPRINTF ("ERROR: failed to pack event!");
			++ec_info.lost_events_count;

		} else if(WriteEventIntoBuffer(buf, event_len) == -1) {
			EPRINTF("Cannot write event into buffer!");
			++ec_info.lost_events_count;
		}
		spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);

	}

	/* Check for stop condition.  We pause collecting the trace right after
	 * storing this event */
	list_for_each_entry(p_cond, &cond_list.list, list) {
		p_tmpl = &p_cond->tmpl;
		switch (p_tmpl->type) {
		case ET_TYPE_STOP_COND:
			if ((!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_ADDR) ||
				 (addr == p_tmpl->addr)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_PID) ||
				 (current_tgid == p_tmpl->pid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TID) ||
				 (current_pid == p_tmpl->tid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_CPU_NUM) ||
				 (current_cpu == p_tmpl->cpu_num)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_BIN_NAME) ||
				(strcmp(current->comm, p_tmpl->bin_name) == 0)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TIME) ||
				 (tv.tv_sec > last_attach_time.tv_sec + p_tmpl->sec) ||
				 (tv.tv_sec == last_attach_time.tv_sec + p_tmpl->sec &&
				  tv.tv_usec >= last_attach_time.tv_usec + p_tmpl->usec)) &&
				!p_cond->applied) {
				spin_lock_irqsave(&ec_spinlock, spinlock_flags);
				paused = 1;
				p_cond->applied = 1;
				spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
			}
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(pack_event_info);

kernel_probe_t* find_probe (unsigned long addr)
{
	kernel_probe_t *p;
	struct hlist_node *node;

	//check if such probe does exist
	hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist)
		if (p->addr == addr)
			break;

	return node ? p : NULL;
}

int add_probe_to_list (unsigned long addr, kernel_probe_t ** pprobe)
{
	kernel_probe_t *new_probe;
	unsigned long jp_handler_addr, rp_handler_addr, pre_handler_addr;
	unsigned long (*find_jp_handler)(unsigned long) =
			(unsigned long (*)(unsigned long))lookup_name("find_jp_handler");
	unsigned long (*find_rp_handler)(unsigned long) =
			(unsigned long (*)(unsigned long))lookup_name("find_rp_handler");
	unsigned long (*find_pre_handler)(unsigned long) =
			(unsigned long (*)(unsigned long))lookup_name("find_pre_handler");

	kernel_probe_t *probe;

	if (pprobe)
		*pprobe = NULL;
	//check if such probe does already exist
	probe = find_probe(addr);
	if (probe) {
		/* It is not a problem if we have already registered
		   this probe before */
		return 0;
	}

	new_probe = kmalloc (sizeof (kernel_probe_t), GFP_KERNEL);
	if (!new_probe)
	{
		EPRINTF ("no memory for new probe!");
		return -ENOMEM;
	}
	memset (new_probe, 0, sizeof (kernel_probe_t));

	new_probe->addr = addr;
	new_probe->jprobe.kp.addr = new_probe->retprobe.kp.addr = (kprobe_opcode_t *)addr;
	new_probe->jprobe.priv_arg = new_probe->retprobe.priv_arg = new_probe;

	//new_probe->jprobe.pre_entry = (kprobe_pre_entry_handler_t) def_jprobe_event_pre_handler;
	if (find_pre_handler == 0 ||
		(pre_handler_addr = find_pre_handler(new_probe->addr)) == 0)
		new_probe->jprobe.pre_entry = (kprobe_pre_entry_handler_t) def_jprobe_event_pre_handler;
	else
		new_probe->jprobe.pre_entry = (kprobe_pre_entry_handler_t)pre_handler_addr;

	if (find_jp_handler == 0 ||
		(jp_handler_addr = find_jp_handler(new_probe->addr)) == 0)
		new_probe->jprobe.entry = (kprobe_opcode_t *) def_jprobe_event_handler;
	else
		new_probe->jprobe.entry = (kprobe_opcode_t *)jp_handler_addr;

	if (find_rp_handler == 0 ||
		(rp_handler_addr = find_rp_handler(new_probe->addr)) == 0)
		new_probe->retprobe.handler =
			(kretprobe_handler_t) def_retprobe_event_handler;
	else
		new_probe->retprobe.handler = (kretprobe_handler_t)rp_handler_addr;

	INIT_HLIST_NODE (&new_probe->hlist);
	hlist_add_head_rcu (&new_probe->hlist, &kernel_probes);

	if (pprobe)
		*pprobe = new_probe;

	return 0;
}

int remove_probe_from_list (unsigned long addr)
{
	kernel_probe_t *p;

	//check if such probe does exist
	p = find_probe (addr);
	if (!p) {
		/* We do not care about it. Nothing bad. */
		return 0;
	}

	hlist_del_rcu (&p->hlist);

	kfree (p);

	return 0;
}


int put_us_event (char *data, unsigned long len)
{
	unsigned long spinlock_flags = 0L;

	SWAP_TYPE_EVENT_HEADER *pEventHeader = (SWAP_TYPE_EVENT_HEADER *)data;	
	char *cur = data + sizeof(TYPEOF_EVENT_LENGTH) + sizeof(TYPEOF_EVENT_TYPE) 
				+ sizeof(TYPEOF_PROBE_ID);
	TYPEOF_NUMBER_OF_ARGS nArgs = pEventHeader->m_nNumberOfArgs;
	TYPEOF_PROBE_ID probe_id = pEventHeader->m_nProbeID;
	//int i;
	
	/*if(probe_id == US_PROBE_ID){
		printk("esrc %p/%d[", data, len);
		for(i = 0; i < len; i++)
			printk("%02x ", data[i]);
		printk("]\n");
	}*/
	
	// set pid/tid/cpu/time	i
	//pEventHeader->m_time.tv_sec = tv.tv_sec;
	//pEventHeader->m_time.tv_usec = tv.tv_usec;

#ifdef MEMORY_CHECKER
	//TODO: move this part to special MEC event posting routine, new IOCTL is needed
	if((probe_id >= MEC_PROBE_ID_MIN) && (probe_id <= MEC_PROBE_ID_MAX))
	{
		if(mec_post_event != NULL)
		{
			int res = mec_post_event(data, len);
			if(res == -1)
			{
				return -1;
			}
		}
		else
		{
			mec_post_event = lookup_name("mec_post_event");
			if(mec_post_event == NULL)
			{
				EPRINTF ("Failed to find function 'mec_post_event' from mec_handlers.ko. Memory Error Checker will work incorrectly.");
			}
			else
			{
				int res = mec_post_event(data, len);
				if(res == -1)
				{
					return -1;
				}
			}
		}
	}
#endif

	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_TIME)){
		TYPEOF_TIME tv = { 0, 0 };
		do_gettimeofday (&tv);
		memcpy(cur, &tv, sizeof(TYPEOF_TIME));
		cur += sizeof(TYPEOF_TIME);
	}
	//pEventHeader->m_nProcessID = current_tgid;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_PID)){		
		//TYPEOF_PROCESS_ID current_tgid = current->tgid;
		(*(TYPEOF_PROCESS_ID *)cur) = current->tgid;
		cur += sizeof(TYPEOF_PROCESS_ID);
	}
	//pEventHeader->m_nThreadID = current_pid;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_TID)){		
		//TYPEOF_THREAD_ID current_pid = current->pid;
		(*(TYPEOF_THREAD_ID *)cur) = current->pid;
		cur += sizeof(TYPEOF_THREAD_ID);
	}
	//pEventHeader->m_nCPU = current_cpu;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_CPU)){		
		//TYPEOF_CPU_NUMBER current_cpu = task_cpu(current);
		(*(TYPEOF_CPU_NUMBER *)cur) = task_cpu(current);
		cur += sizeof(TYPEOF_CPU_NUMBER);
	}
	//printk("%d %x", probe_id, event_mask);
	// dyn lib event should have all args, it is for internal use and not visible to user
	if((probe_id == EVENT_FMT_PROBE_ID) || (probe_id == DYN_LIB_PROBE_ID) || !(event_mask & IOCTL_EMASK_ARGS)){
		// move only if any of prev fields has been skipped 
		if(event_mask & (IOCTL_EMASK_TIME|IOCTL_EMASK_PID|IOCTL_EMASK_TID|IOCTL_EMASK_CPU)){
			memmove(cur, data+sizeof(SWAP_TYPE_EVENT_HEADER)-sizeof(TYPEOF_NUMBER_OF_ARGS), 
					len-sizeof(SWAP_TYPE_EVENT_HEADER)+sizeof(TYPEOF_NUMBER_OF_ARGS)
					-sizeof(TYPEOF_EVENT_LENGTH));
		}
		cur += len-sizeof(SWAP_TYPE_EVENT_HEADER)+sizeof(TYPEOF_NUMBER_OF_ARGS)
				-sizeof(TYPEOF_EVENT_LENGTH);
	}
	else{
		// user space probes should have at least one argument to identify them 
		if((probe_id == US_PROBE_ID) || (probe_id == VTP_PROBE_ID)){
			char *pArg1;
			(*(TYPEOF_NUMBER_OF_ARGS *)cur) = 1;
			cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
			// pack args using format string for the 1st arg only
			memset(cur, 0, ALIGN_VALUE(2));
			cur[0] = 'p'; cur[1] = '\0';
			cur += ALIGN_VALUE(2);
			pArg1 = data + sizeof(SWAP_TYPE_EVENT_HEADER)+ALIGN_VALUE(nArgs+1);
			memmove(cur, pArg1, sizeof(unsigned long));
			cur += sizeof(unsigned long);
		}
		else {
			(*(TYPEOF_NUMBER_OF_ARGS *)cur) = 0;
			cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
		}
	}	
	pEventHeader->m_nLength = cur - data + sizeof(TYPEOF_EVENT_LENGTH);
	*((TYPEOF_EVENT_LENGTH *)cur) = pEventHeader->m_nLength;
	len = pEventHeader->m_nLength;
	
	if(WriteEventIntoBuffer(data, len) == -1) {
		EPRINTF("Cannot write event into buffer!");

		spin_lock_irqsave (&ec_spinlock, spinlock_flags);
		++ec_info.lost_events_count;
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
	}

	return 0;
}

int set_predef_uprobes (ioctl_predef_uprobes_info_t *data)
{
	int i, k, size = 0, probe_size, result, j;
	char *buf, *sep1, *sep2;

	inst_us_proc_t *my_uprobes_info = (inst_us_proc_t *)lookup_name("my_uprobes_info");
	DPRINTF("my_uprobes_info lookup result: 0x%p", my_uprobes_info);
	inst_us_proc_t empty_uprobes_info =
	{
		.libs_count = 0,
		.p_libs = NULL,
	};
	if (my_uprobes_info == 0)
		my_uprobes_info = &empty_uprobes_info;

	for(j = 0; j < data->probes_count; j++){
		probe_size = strlen_user(data->p_probes+size);
		buf = kmalloc(probe_size, GFP_KERNEL);
		if(!buf){
			EPRINTF("failed to alloc mem!");
			return -EFAULT;
		}		
		result = strncpy_from_user(buf, data->p_probes+size, probe_size);
		if (result != (probe_size-1))
		{
			EPRINTF("failed to copy from user!");
			kfree(buf);
			return -EFAULT;
		}
		//DPRINTF("%s", buf);
		sep1 = strchr(buf, ':');
		if(!sep1){
			EPRINTF("skipping invalid predefined uprobe string '%s'!", buf);
			kfree(buf);
			size += probe_size;
			continue;
		}		
		sep2 = strchr(sep1+1, ':');
		if(!sep2 || (sep2 == sep1) || (sep2+2 == buf+probe_size)){
			EPRINTF("skipping invalid predefined uprobe string '%s'!", buf);
			kfree(buf);
			size += probe_size;
			continue;
		}		
		for(i = 0; i < my_uprobes_info->libs_count; i++){
			if(strncmp(buf, my_uprobes_info->p_libs[i].path, sep1-buf) != 0)
				continue;
			for(k = 0; k < my_uprobes_info->p_libs[i].ips_count; k++){
				if(strncmp(sep1+1, my_uprobes_info->p_libs[i].p_ips[k].name, sep2-sep1-1) != 0)
					continue;				
				my_uprobes_info->p_libs[i].p_ips[k].offset = simple_strtoul(sep2+1, NULL, 16);
			}
		}
		kfree(buf);
		size += probe_size;
	}
	return 0;
}

int get_predef_uprobes_size(int *size)
{
	int i, k;

	inst_us_proc_t *my_uprobes_info = (inst_us_proc_t *)lookup_name("my_uprobes_info");
	inst_us_proc_t empty_uprobes_info =
	{
		.libs_count = 0,
		.p_libs = NULL,
	};

	if (my_uprobes_info == 0)
		my_uprobes_info = &empty_uprobes_info;

	*size = 0;
	for(i = 0; i < my_uprobes_info->libs_count; i++){
		int lib_size = strlen(my_uprobes_info->p_libs[i].path);
		for(k = 0; k < my_uprobes_info->p_libs[i].ips_count; k++){
			// libc.so.6:printf:
			*size += lib_size + 1 + strlen(my_uprobes_info->p_libs[i].p_ips[k].name) + 2;
		}
	}
	return 0;
}

int get_predef_uprobes(ioctl_predef_uprobes_info_t *udata)
{
	ioctl_predef_uprobes_info_t data;
	int i, k, size, lib_size, func_size, result;
	unsigned count = 0;
	char sep[] = ":";

	inst_us_proc_t *my_uprobes_info = (inst_us_proc_t *)lookup_name("my_uprobes_info");
	inst_us_proc_t empty_uprobes_info =
	{
		.libs_count = 0,
		.p_libs = NULL,
	};
	if (my_uprobes_info == 0)
		my_uprobes_info = &empty_uprobes_info;

	// get addr of array
	if (copy_from_user ((void *)&data, udata, sizeof (data)))
	{
		EPRINTF("failed to copy from user!");
		return -EFAULT;
	}
		
	size = 0;
	for(i = 0; i < my_uprobes_info->libs_count; i++){
		lib_size = strlen(my_uprobes_info->p_libs[i].path);
		for(k = 0; k < my_uprobes_info->p_libs[i].ips_count; k++){
			// libname
			result = copy_to_user ((void *)(data.p_probes+size), my_uprobes_info->p_libs[i].path, lib_size);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size += lib_size;
			// ":"
			result = copy_to_user ((void *)(data.p_probes+size), sep, 1);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size++;
			// probename
			//DPRINTF("'%s'", my_uprobes_info->p_libs[i].p_ips[k].name);
			func_size = strlen(my_uprobes_info->p_libs[i].p_ips[k].name);
			result = copy_to_user ((void *)(data.p_probes+size), my_uprobes_info->p_libs[i].p_ips[k].name, func_size);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size += func_size;
			// ":\0"
			result = copy_to_user ((void *)(data.p_probes+size), sep, 2);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size += 2;
			count++;
		}
	}

	// set probes_count
	result = copy_to_user ((void *)&(udata->probes_count), &count, sizeof(count));
	if (result)
	{
		EPRINTF("failed to copy to user!");
		return -EFAULT;
	}
	return 0;
}
