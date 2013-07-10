#ifndef _US_INST_H
#define _US_INST_H

enum MOD_TYPE {
	MT_ADD,
	MT_DEL
};

struct us_inst_data;

int mod_us_inst(struct us_inst_data *us_inst, enum MOD_TYPE mt);

#endif /* _US_INST_H */
