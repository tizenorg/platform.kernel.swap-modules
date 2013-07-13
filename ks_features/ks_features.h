#ifndef _KS_FEATURES_H
#define _KS_FEATURES_H

enum feature_id {
	FID_FILE = 1,
	FID_IPC = 2,
	FID_PROCESS = 3,
	FID_SIGNAL = 4,
	FID_NET = 5,
	FID_DESC = 6
};

int set_feature(enum feature_id id);
int unset_feature(enum feature_id id);

/* debug */
void print_features(void);
void print_all_syscall(void);
/* debug */

#endif /*  _KS_FEATURES_H */
