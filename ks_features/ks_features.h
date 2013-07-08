#ifndef _KS_FEATURES_H
#define _KS_FEATURES_H

enum feature_id {
	FID_FILE,
	FID_IPC,
	FID_NET,
	FID_PROCESS,
	FID_SIGNAL,
	FID_DESC
};

int set_feature(enum feature_id id);
int unset_feature(enum feature_id id);

/* debug */
void print_features(void);
void print_all_syscall(void);
/* debug */

#endif /*  _KS_FEATURES_H */
