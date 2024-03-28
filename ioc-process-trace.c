#include <linux/ptrace.h>
#include "epicsStructure.h"

// https://docs.kernel.org/bpf/map_of_maps.html
// When creating an outer map, an inner map instance is used to initialize the metadata that
// the outer map holds about its inner maps. This inner map has a separate lifetime from the
// outer map and can be deleted after the outer map has been created.

BPF_PERCPU_ARRAY(db_data, dbCommon, 1);
BPF_PERCPU_ARRAY(retdb_data, dbCommon, 1);
// BPF_ARRAY(ex1, int, 1024);
// BPF_ARRAY(ex2, int, 1024);
// BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);

BPF_STACK(rec_stack, dbCommon *, 1024);

int enter_process(struct pt_regs *ctx)
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

    bpf_trace_printk("enter: %s %d %d", data->name, data->time.secPastEpoch, data->time.nsec);
    rec_stack.push(&precord, 0);

    return 0;
};

int exit_process(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    struct dbCommon *precord;
    rec_stack.pop(&precord);

    dbCommon *data = retdb_data.lookup(&zero);
    if (!data)
        return 0;

    int size = sizeof(dbCommon);
    if (precord != 0)
        ret = bpf_probe_read_user(data, size, precord);
    bpf_trace_printk("exit: %s %d %d", data->name, data->time.secPastEpoch, data->time.nsec);

    return 0;
};
