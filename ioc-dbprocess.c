#include <linux/ptrace.h>
#include "epicsStructure.h"

BPF_PERCPU_ARRAY(db_data, dbCommon, 1);

int printprocess(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct dbCommon *precord = (struct dbCommon *)PT_REGS_PARM1(ctx);
    dbCommon *data = db_data.lookup(&zero);

    if (!data)
        return 0;

    int size = sizeof(dbCommon);
    if (precord != 0)
        ret = bpf_probe_read_user(data, size, precord);

    bpf_trace_printk("%s %d %d", data->name, data->time.secPastEpoch, data->time.nsec);

    return 0;
};
