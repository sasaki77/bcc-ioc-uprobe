#include <linux/ptrace.h>
#include "epicsStructure.h"

BPF_PERCPU_ARRAY(db_data, dbCommon, 1);
BPF_PERCPU_ARRAY(retdb_data, dbCommon, 1);
BPF_PERCPU_ARRAY(recn, dbRecordNode, 1);
BPF_PERCPU_ARRAY(rectype, dbRecordType, 1);
BPF_PERCPU_ARRAY(mapdbfld, dbFldDes, 1);

struct key_t
{
    char name[61];
};

struct create_rec_args
{
    struct key_t key;
    DBENTRY *pentry;
};

BPF_PERCPU_ARRAY(dbent, struct create_rec_args, 1);

BPF_HASH(pv_entry_hash, struct key_t, DBENTRY);

struct process_info
{
    __u32 id;
    __u32 count;
};

struct key_proc_pv
{
    __u64 pid;
    __u32 id;
    __u32 count;
};

BPF_HASH(process_hash, __u64, struct process_info);
BPF_HASH(proc_pv_hash, struct key_proc_pv, dbCommon *);

BPF_ARRAY(temp, double, 1);

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

    struct process_info proc_info = {0, 0};
    struct process_info *pproc_info;
    struct key_proc_pv key;
    __u64 pid = bpf_get_current_pid_tgid();

    pproc_info = process_hash.lookup(&pid);

    if (!pproc_info)
    {
        __u32 random_id = bpf_get_prandom_u32();
        proc_info.id = random_id;
    }
    else
    {
        proc_info.count = pproc_info->count;
        proc_info.id = pproc_info->id;
    }
    proc_info.count = proc_info.count + 1;

    key.pid = pid;
    key.id = proc_info.id;
    key.count = proc_info.count;

    process_hash.update(&pid, &proc_info);
    proc_pv_hash.update(&key, &precord);

    return 0;
};

int exit_process(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    struct process_info proc_info = {0, 0};
    struct process_info *pproc_info;
    struct key_proc_pv key_pv;
    __u64 pid = bpf_get_current_pid_tgid();

    pproc_info = process_hash.lookup(&pid);

    if (!pproc_info)
    {
        return 0;
    }

    key_pv.pid = pid;
    key_pv.id = pproc_info->id;
    key_pv.count = pproc_info->count;

    struct dbCommon **pprecord;
    pprecord = proc_pv_hash.lookup(&key_pv);

    if (!pprecord)
    {
        return 0;
    }

    struct dbCommon *precord;
    precord = *pprecord;

    proc_pv_hash.delete(&key_pv);

    if (pproc_info != 0)
    {
        proc_info.count = pproc_info->count;
        proc_info.id = pproc_info->id;
        proc_info.count = proc_info.count - 1;
        if (proc_info.count == 0)
        {
            process_hash.delete(&pid);
        }
        else
        {
            process_hash.update(&pid, &proc_info);
        }
    }

    process_hash.update(&pid, &proc_info);

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

    DBENTRY *ent = pv_entry_hash.lookup(&key);

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

    char name[61];
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
    }

    double *t = temp.lookup(&zero);
    if (!t)
        return 0;

    char fname[10];
    size = sizeof(name);
    if (dbfld->name != 0)
    {
        ret = bpf_probe_read_user(fname, size, dbfld->name);
        bpf_trace_printk("exit: %s", fname);
    }

    int field_type = dbfld->field_type;
    bpf_trace_printk("field: %d", field_type);

    if (precord != 0)
    {
        switch (field_type)
        {
        case DBF_CHAR:
        {
            __s8 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_SHORT:
        {
            __s16 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_LONG:
        {
            __s32 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_INT64:
        {
            __s64 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_UCHAR:
        {
            __u8 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_USHORT:
        case DBF_ENUM:
        {
            __u16 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_ULONG:
        {
            __u32 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_UINT64:
        {
            __u64 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        case DBF_FLOAT:
        case DBF_DOUBLE:
        {
            double val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            break;
        }
        default:
            break;
        }
    }

    return 0;
};

int enter_createrec(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    if (!PT_REGS_PARM1(ctx))
        return 0;

    DBENTRY *pent = (DBENTRY *)PT_REGS_PARM1(ctx);

    if (!PT_REGS_PARM2(ctx))
        return 0;

    char *pname = (char *)PT_REGS_PARM2(ctx);

    struct create_rec_args *ent = dbent.lookup(&zero);

    if (!ent)
        return 0;
    ent->pentry = pent;

    int size = sizeof(ent->key.name);
    if (pname != 0)
        ret = bpf_probe_read_user(ent->key.name, size, pname);

    bpf_trace_printk("enter create: %s", ent->key.name);

    int flag = 0;
    for (int i = 0; i < sizeof(ent->key.name); i++)
    {
        if (flag == 1)
        {
            ent->key.name[i] = 0;
        }
        if (ent->key.name[i] == 0)
        {
            flag = 1;
        }
    }

    return 0;
};

int exit_createrec(struct pt_regs *ctx)
{
    __u32 zero = 0;

    struct create_rec_args *pent;
    pent = dbent.lookup(&zero);

    if (!pent)
        return 0;

    DBENTRY ent;

    int ret;
    if (pent != 0)
        ret = bpf_probe_read_user(&ent, sizeof(ent), pent->pentry);

    bpf_trace_printk("exit create");

    pv_entry_hash.update(&(pent->key), &ent);

    return 0;
};
