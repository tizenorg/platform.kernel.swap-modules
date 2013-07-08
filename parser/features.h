#ifndef _FEATURES_H
#define _FEATURES_H

#include <linux/types.h>

int init_features(void);
void uninit_features(void);

int set_features(u64 features);

#endif /* _FEATURES_H */
