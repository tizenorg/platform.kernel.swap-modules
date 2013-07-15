typedef struct
{
	struct list_head list;
	char *name;
	int installed;
	struct jprobe jprobe;
	struct kretprobe retprobe;
	unsigned long offset;
	unsigned long got_addr;

	unsigned flag_retprobe:1;
	unsigned flag_got:1;
} us_proc_ip_t;

typedef struct
{
	int installed;
	struct jprobe jprobe;
	unsigned long addr;
	struct list_head list;
} us_proc_vtp_t;

typedef struct
{
	unsigned func_addr;
	unsigned got_addr;
	unsigned real_func_addr;
} us_proc_plt_t;

typedef struct
{
	char *path;
	char *path_dyn;
	struct dentry *m_f_dentry;
	unsigned ips_count;
	us_proc_ip_t *p_ips;
	unsigned vtps_count;
	us_proc_vtp_t *p_vtps;
	int loaded;
	unsigned plt_count;
	us_proc_plt_t *p_plt;
	unsigned long vma_start;
	unsigned long vma_end;
	unsigned vma_flag;
} us_proc_lib_t;

typedef struct {
	char *path;
	struct dentry *m_f_dentry;
	pid_t tgid;
	unsigned unres_ips_count;
	unsigned unres_vtps_count;
	int is_plt;
	unsigned libs_count;
	us_proc_lib_t *p_libs;

	// new_dpf
	struct sspt_proc *pp;
} inst_us_proc_t;
