////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           ec.c
//
//      DESCRIPTION:
//      This file is C++ source for SWAP driver.
//
//      SEE ALSO:       ec.h
//      AUTHOR:         L.Komkov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include "module.h"
#include "ec.h"
#include "CProfile.h"

////////////////////////////////////////////////////////////////////////////////////////////

ec_info_t ec_info = {
	.ec_state = EC_STATE_IDLE,
	.m_nMode = 0L,
	.buffer_size = EC_BUFFER_SIZE_DEFAULT,
	.ignored_events_count = 0,
	.m_nNumOfSubbuffers = 0,
	.m_nSubbufSize = DEFAULT_SUBBUF_SIZE,
};

////////////////////////////////////////////////////////////////////////////////////////////

spinlock_t ec_spinlock = SPIN_LOCK_UNLOCKED;	// protects 'ec_info'

ec_probe_info_t ec_probe_info = {
	.probe_id = -1,
	.probe_selected = 0,
	.jprobe_active = 0,
	.retprobe_active = 0,
	.address = 0,
};

spinlock_t ec_probe_spinlock = SPIN_LOCK_UNLOCKED;	// protects 'ec_probe_info'

ec_state_t GetECState(void) { return ec_info.ec_state; };

void reset_ec_info_nolock(void)
{
	ec_info.trace_size = 0;
	ec_info.first = 0;
	ec_info.after_last = 0;
	ec_info.ignored_events_count = 0;
	ec_info.saved_events_count = 0;
	ec_info.discarded_events_count = 0;
	ec_info.collision_count = 0;
	ec_info.lost_events_count = 0;
	ec_info.m_nBeginSubbufNum = 0;
	ec_info.m_nEndSubbufNum = 0;
	ec_info.m_nEndOffset = 0;
	ec_info.m_nSubbufSavedEvents = 0;
}

void ResetECInfo(void) {
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	reset_ec_info_nolock();
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
}

void CleanECInfo(void) {
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.buffer_effect = 0;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	ResetECInfo();

}

int IsECMode(unsigned long nMask) { return ((ec_info.m_nMode & nMask) != 0); }

int IsMultipleBuffer() { return IsECMode(MODEMASK_MULTIPLE_BUFFER); }

int IsContinuousRetrieval() { return IsECMode(MODEMASK_CONTINUOUS_RETRIEVAL); }

int SetECMode(unsigned long nECMode) {
	unsigned long spinlock_flags = 0L;

	if((nECMode & MODEMASK_MULTIPLE_BUFFER) != 0) {
		if(EnableMultipleBuffer() == -1) {
			EPRINTF("Cannot enable multiple buffer!");
			return -1;
		}
	} else {
		if(DisableMultipleBuffer() == -1) {
			EPRINTF("Cannot disable multiple buffer!");
			return -1;
		}
	}
	if((nECMode & MODEMASK_CONTINUOUS_RETRIEVAL) != 0) {
		if(EnableContinuousRetrieval() == -1) {
			EPRINTF("Cannot enable continuous retrieval!");
			return -1;
		}
	} else {
		if(DisableContinuousRetrieval() == -1) {
			EPRINTF("Cannot disable continuous retrieval!");
			return -1;
		}
	}

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode = nECMode;
	reset_ec_info_nolock();
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

unsigned long GetECMode(void) { return ec_info.m_nMode; }

unsigned int GetNumOfSubbuffers(unsigned long nBufferSize)
{
	if(nBufferSize % ec_info.m_nSubbufSize > 0)
	     EPRINTF("The buffer size is not divisible by a subbuffer size! (nBufferSize = %d, ec_info.m_nSubbufSize =%d)", nBufferSize ,ec_info.m_nSubbufSize);
	return nBufferSize / ec_info.m_nSubbufSize;
};

#if defined(__DEBUG)
static UNUSED char * ec_state_name (ec_state_t ec_state)
{
	static char *ec_state_names[EC_STATE_TAG_COUNT] = { "IDLE", "ATTACHED", "ACTIVE", "STOPPED" };

	if (((unsigned) ec_info.ec_state) < EC_STATE_TAG_COUNT)
	{
		return ec_state_names[ec_info.ec_state];
	}
	else
	{
		return "<unknown>";
	}
}
#endif /* defined(__DEBUG) */


/*
    On user request user space EC may change state in the following order:
        IDLE -> ATTACHED (on "attach")
        IDLE | ATTACHED -> ACTIVE (on "activate")
        ATTACHED | ACTIVE | STOPPED -> IDLE (on "stop"/"detach")
*/
int ec_user_attach (void)
{
	unsigned long spinlock_flags;
	int result;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
	if (EC_STATE_IDLE == ec_info.ec_state)
	{
		int tmp;
		ec_info.ec_state = EC_STATE_ATTACHED;

		/* save 'start' time */
		struct timeval tv;
		do_gettimeofday(&tv);
		memcpy(&last_attach_time, &tv, sizeof(struct timeval));

		/* unpause if paused */
		paused = 0;

		/* if there is at least one start condition in the list
		   we are paused at the beginning */
		struct cond *p_cond;
		struct event_tmpl *p_tmpl;
		list_for_each_entry(p_cond, &cond_list.list, list) {
			p_tmpl = &p_cond->tmpl;
			if (p_tmpl->type == ET_TYPE_START_COND) {
				paused = 1;
				break;
			}
		}

		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs

		//first of all put event with event format
		tmp = event_mask;
		event_mask = 0;
		pack_event_info(EVENT_FMT_PROBE_ID, RECORD_ENTRY, "x", tmp);
		event_mask = tmp;		
		
		result = attach_selected_probes ();
		if (result == 0)	// instrument user space process 
			result = inst_usr_space_proc ();
		// FIXME: SAFETY CHECK
		if (result)
		{		// return to safe state
			detach_selected_probes ();

			spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
			ec_info.ec_state = EC_STATE_IDLE;
			spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs
		}
		// FIXME: SAFETY CHECK

		notify_user (EVENT_EC_STATE_CHANGE);

	}
	else
	{

		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs
		result = -EINVAL;

	}

	return result;
}

int ec_user_activate (void)
{
	unsigned long spinlock_flags;
	int result;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
	if (EC_STATE_IDLE == ec_info.ec_state)
	{
		int tmp;
		ec_info.ec_state = EC_STATE_ACTIVE;
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs
		//first of all put event with event format
		tmp = event_mask;
		event_mask = 0;
		pack_event_info(EVENT_FMT_PROBE_ID, RECORD_ENTRY, "x", tmp);
		event_mask = tmp;		

		result = attach_selected_probes ();
		if (result == 0)	// instrument user space process 
			result = inst_usr_space_proc ();
		// FIXME: SAFETY CHECK
		if (result)
		{		// return to safe state
			detach_selected_probes ();

			spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
			ec_info.ec_state = EC_STATE_IDLE;
			spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs
		}
		// FIXME: SAFETY CHECK

		notify_user (EVENT_EC_STATE_CHANGE);

	}
	else if (EC_STATE_ATTACHED == ec_info.ec_state)
	{

		ec_info.ec_state = EC_STATE_ACTIVE;
		result = 0;
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs

		notify_user (EVENT_EC_STATE_CHANGE);

	}
	else
	{

		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs
		result = -EINVAL;
	}

	return result;
}

int ec_user_stop (void)
{
	unsigned long spinlock_flags;
	int result = 0, ret = 0;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
	if (EC_STATE_ATTACHED == ec_info.ec_state || EC_STATE_ACTIVE == ec_info.ec_state || EC_STATE_STOPPED == ec_info.ec_state)
	{

		ec_info.ec_state = EC_STATE_IDLE;
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs

		ret = deinst_usr_space_proc ();
		result = detach_selected_probes ();
		if (result == 0)
			result = ret;

		notify_user (EVENT_EC_STATE_CHANGE);

	}
	else
	{

		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs
		result = -EINVAL;

	}

	return result;
}

/*
    Kernel space EC may change state in the following order:
        ATTACHED -> ACTIVE (when start condition is satisfied)
        ACTIVE -> STOPPED (when stop condition is satisfied)
*/
int ec_kernel_activate (void)
{
	unsigned long spinlock_flags;
	int result;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
	if (EC_STATE_ATTACHED == ec_info.ec_state)
	{
		ec_info.ec_state = EC_STATE_ACTIVE;
		result = 0;
	}
	else
	{
		result = -EINVAL;
	}
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs

	notify_user (EVENT_EC_STATE_CHANGE);

	return result;
}

int ec_kernel_stop (void)
{
	unsigned long spinlock_flags;
	int result;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait
	if (EC_STATE_ACTIVE == ec_info.ec_state)
	{
		ec_info.ec_state = EC_STATE_STOPPED;
		result = 0;
	}
	else
	{
		result = -EINVAL;
	}
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs

	notify_user (EVENT_EC_STATE_CHANGE);

	return result;
}

// Copies EC info to user space
// Since "copy_to_user" may block, an intermediate copy of ec_info is used here
int copy_ec_info_to_user_space (ec_info_t * p_user_ec_info)
{
	/*
	   WARNING: to avoid stack overflow the following data structure was made
	   static. As result, simultaneous users of this function will share it
	   and must use additional synchronization to avoid collisions.
	 */
	// FIXME: synchronization is necessary here (ec_info_copy must be locked).
	static ec_info_t ec_info_copy;
	unsigned long spinlock_flags;
	int result;

	// ENTER_CRITICAL_SECTION
	// lock semaphore here


	// ENTER_CRITICAL_SECTION
	spin_lock_irqsave (&ec_spinlock, spinlock_flags);	// make other CPUs wait

	// copy
	memcpy (&ec_info_copy, &ec_info, sizeof (ec_info_copy));

	// LEAVE_CRITICAL_SECTION
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);	// open our data for other CPUs


	result = copy_to_user (p_user_ec_info, &ec_info_copy, sizeof (ec_info_t));

	// LEAVE_CRITICAL_SECTION
	// unlock semaphore here

	if (result)
	{
		EPRINTF ("copy_to_user(%08X,%08X)=%d", (unsigned) p_user_ec_info, (unsigned) &ec_info_copy, result);
		result = -EFAULT;
	}
	return result;
}

int copy_ec_probe_info_to_user_space (ec_probe_info_t * p_user_ec_probe_info)
{
	/*
	   WARNING: to avoid stack overflow the following data structure was made
	   static. As result, simultaneous users of this function will share it
	   and must use additional synchronization to avoid collisions.
	 */
	// FIXME: synchronization is necessary here (ec_info_copy must be locked).
	ec_probe_info_t ec_probe_info_copy;
	unsigned long spinlock_flags;
	int result;

	// ENTER_CRITICAL_SECTION
	// lock semaphore here


	// ENTER_CRITICAL_SECTION
	spin_lock_irqsave (&ec_probe_spinlock, spinlock_flags);	// make other CPUs wait

	// copy
	memcpy (&ec_probe_info_copy, &ec_probe_info, sizeof (ec_probe_info_copy));

	// LEAVE_CRITICAL_SECTION
	spin_unlock_irqrestore (&ec_probe_spinlock, spinlock_flags);	// open our data for other CPUs


	result = copy_to_user (p_user_ec_probe_info, &ec_probe_info_copy, sizeof (ec_probe_info_t));

	// LEAVE_CRITICAL_SECTION
	// unlock semaphore here

	if (result)
	{
		EPRINTF ("copy_to_user(%08X,%08X)=%d", (unsigned) p_user_ec_probe_info, (unsigned) &ec_probe_info_copy, result);
		result = -EFAULT;
	}
	return result;
}
