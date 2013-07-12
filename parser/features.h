#ifndef _FEATURES_H
#define _FEATURES_H

struct conf_data;

int init_features(void);
void uninit_features(void);

int set_features(struct conf_data *conf);

#endif /* _FEATURES_H */
