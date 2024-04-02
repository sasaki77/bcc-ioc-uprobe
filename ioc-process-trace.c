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
BPF_PERCPU_ARRAY(rectype, dbRecordType, 1);
BPF_PERCPU_ARRAY(mapdbfld, dbFldDes, 1);

struct key_t
{
    char name[61];
};

BPF_STACK(rec_stack, dbCommon *, 1024);
BPF_HASH(pv_table, struct key_t, DBENTRY *);

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

    struct key_t key;
    memcpy(key.name, data->name, sizeof(key.name));
    bpf_trace_printk("%s", key.name);
    bpf_trace_printk("%d", key.name[19]);

    DBENTRY **pent = pv_table.lookup(&key);

    if (!pent)
    {
        bpf_trace_printk("pent");
        bpf_trace_printk("%d", pent);
        return 0;
    }

    DBENTRY *ent = *pent;

    if (!ent)
    {
        return 0;
    }

    dbRecordNode *recnode = recn.lookup(&zero);

    if (!recnode)
    {
        return 0;
    }
    size = sizeof(dbRecordNode);

    if (ent->precnode != 0)
    {
        ret = bpf_probe_read_user(recnode, size, ent->precnode);
    }

    char name[41];
    size = sizeof(name);
    if (recnode->recordname != 0)
    {
        ret = bpf_probe_read_user(name, size, recnode->recordname);
        bpf_trace_printk("exit: %s", name);
    }

    dbRecordType *type = rectype.lookup(&zero);
    if (!type)
    {
        return 0;
    }

    size = sizeof(dbRecordType);
    if (ent->precordType != 0)
    {
        ret = bpf_probe_read_user(type, size, ent->precordType);
    }

    dbFldDes *dbfld = mapdbfld.lookup(&zero);

    if (!dbfld)
    {
        return 0;
    }
    size = sizeof(dbFldDes);

    if (type->pvalFldDes != 0)
    {
        ret = bpf_probe_read_user(dbfld, size, type->pvalFldDes);
        bpf_trace_printk("exit: %d", dbfld->field_type);
    }

    char fname[10];
    size = sizeof(name);
    if (dbfld->name != 0)
    {
        ret = bpf_probe_read_user(fname, size, dbfld->name);
        bpf_trace_printk("exit: %s", fname);
    }

    __u32 val;
    if (precord != 0)
    {
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
        bpf_trace_printk("exit val: %d", val);
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

    struct key_t key;
    bpf_trace_printk("key.name %d", key.name[19]);
    size = sizeof(key.name);
    if (pname != 0)
        ret = bpf_probe_read_user(key.name, size, pname);

    bpf_trace_printk("enter create: %s", name);
    __u32 zero = 0;

    DBENTRY **data = pdbent.lookup(&zero);

    if (!data)
        return 0;

    size = sizeof(DBENTRY *);
    if (pent != 0)
    {
        *data = pent;
        bpf_trace_printk("pent %d", data);
    }
    bpf_trace_printk("key.name %d", key.name[19]);
    int flag = 0;
    bpf_trace_printk("key.name %d", key.name[19]);
    for (int i = 0; i < sizeof(key.name); i++)
    {
        if (flag == 1)
        {
            key.name[i] = 0;
        }
        if (key.name[i] == 0)
        {
            flag = 1;
        }
    }

    pv_table.update(&key, &pent);

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
