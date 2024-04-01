#include <linux/ptrace.h>
#include "epicsStructure.h"

// https://docs.kernel.org/bpf/map_of_maps.html
// When creating an outer map, an inner map instance is used to initialize the metadata that
// the outer map holds about its inner maps. This inner map has a separate lifetime from the
// outer map and can be deleted after the outer map has been created.

BPF_PERCPU_ARRAY(db_data, dbCommon, 1);
BPF_PERCPU_ARRAY(retdb_data, dbCommon, 1);
// BPF_PERCPU_ARRAY(dbent, DBENTRY, 1);
//  BPF_ARRAY(ex1, int, 1024);
//  BPF_ARRAY(ex2, int, 1024);
//  BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);
BPF_PERCPU_ARRAY(pdbent, DBENTRY *, 1);
BPF_PERCPU_ARRAY(dbent, DBENTRY, 1);
BPF_PERCPU_ARRAY(recn, dbRecordNode, 1);

// struct key_t
//{
//     char name[41];
// };
//
BPF_STACK(rec_stack, dbCommon *, 1024);
// BPF_HASH(pv_table, key_t, DBENTRY *);

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

    // struct key_t key = {};
    //  key.name = data->name;
    // bpf_snprintf(key.name, sizeof(key.name), "%s", data->name, sizeof(key.name));
    // DBENTRY **ppent = pv_table.lookup(key);
    // if (!ppent)
    //     return 0;

    // DBENTRY *pent;
    // pent = *ppent;

    DBENTRY *ent = dbent.lookup(&zero);
    //  DBENTRY *ent;

    if (!ent)
    {
        bpf_trace_printk("ent");
        return 0;
    }

    // size = sizeof(DBENTRY);
    //  if (pent != 0)
    //  ret = bpf_probe_read_user(ent, size, pent);

    dbRecordNode *recnode = recn.lookup(&zero);
    // DBENTRY *ent;

    if (!recnode)
    {
        bpf_trace_printk("recnode");
        return 0;
    }
    // dbRecordNode *recnode;
    size = sizeof(dbRecordNode);

    // bpf_trace_printk("ent: %d", ent->indfield);
    if (ent->precnode != 0)
    {
        bpf_trace_printk("precnode");
        ret = bpf_probe_read_user(recnode, size, ent->precnode);
    }

    char name[41];
    size = sizeof(name);
    if (recnode->recordname != 0)
    {
        bpf_trace_printk("recordname");
        ret = bpf_probe_read_user(name, size, recnode->recordname);
        bpf_trace_printk("exit 1: %s", name);
    }

    return 0;
};

int enter_createrec(struct pt_regs *ctx)
{
    int ret;
    char name[41];

    if (!PT_REGS_PARM1(ctx))
        return 0;

    DBENTRY *pent = (DBENTRY *)PT_REGS_PARM1(ctx);

    if (!PT_REGS_PARM2(ctx))
        return 0;

    char *pname = (char *)PT_REGS_PARM2(ctx);

    int size = sizeof(name);
    if (pname != 0)
        ret = bpf_probe_read_user(name, size, pname);

    bpf_trace_printk("enter create: %s", name);
    __u32 zero = 0;

    DBENTRY **data = pdbent.lookup(&zero);

    if (!data)
        return 0;

    size = sizeof(DBENTRY *);
    if (pent != 0)
    {
        // ret = bpf_probe_read_user(data, size, &pent);
        *data = pent;
        bpf_trace_printk("pent %d", data);
    }
    // struct key_t key = {};
    // bpf_snprintf(key.name, sizeof(key.name), "%s", name, sizeof(key.name));
    //  key.name = name;
    // pv_table.update(key, &pent);

    return 0;
};

int exit_createrec(struct pt_regs *ctx)
{
    __u32 zero = 0;

    DBENTRY **ppent = pdbent.lookup(&zero);

    if (!ppent)
        return 0;

    DBENTRY *pent = dbent.lookup(&zero);

    if (!pent)
        return 0;

    int size = sizeof(DBENTRY);
    int ret;
    if (pent != 0)
        ret = bpf_probe_read_user(pent, size, *ppent);
    bpf_trace_printk("exit create: %d", pent->pflddes);

    return 0;
};
