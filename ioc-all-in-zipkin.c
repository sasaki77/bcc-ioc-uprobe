#include <linux/ptrace.h>
#include <linux/sched.h>
#include "epicsStructure.h"

BPF_PERCPU_ARRAY(db_data, dbCommon, 1);
BPF_PERCPU_ARRAY(retdb_data, dbCommon, 1);
BPF_PERCPU_ARRAY(recn, dbRecordNode, 1);
BPF_PERCPU_ARRAY(rectype, dbRecordType, 1);
BPF_PERCPU_ARRAY(mapdbfld, dbFldDes, 1);

BPF_PERCPU_ARRAY(dbent_dbl, DBENTRY *, 1);

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

BPF_RINGBUF_OUTPUT(ring_buf, 1 << 4);

struct event_process
{
    __u32 type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 ktime_ns;
    __u32 state;
    __u32 id;
    __u32 count;
    __u32 ts_sec;
    __u32 ts_nano;
    char pvname[61];
    __u32 val_type;
    __s64 val_i;
    __u64 val_u;
    double val_d;
    char val_s[MAX_STRING_SIZE];
};

BPF_ARRAY(event_temp, struct event_process, 1);

BPF_PERCPU_ARRAY(e, struct event_process, 1);

enum state_type
{
    STATE_ENTER_PROC = 1,
    STATE_EXIT_PROC = 2,
};

enum val_type
{
    VAL_TYPE_INT = 1,
    VAL_TYPE_UINT = 2,
    VAL_TYPE_DOUBLE = 3,
    VAL_TYPE_STRING = 4,
    VAL_TYPE_NULL = 5,
};

BPF_PERCPU_ARRAY(db_data_put, dbAddr, 1);

struct event_put
{
    __u64 ktime_ns;
    char pvname[61];
    char field_name[61];
    __u32 val_type;
    __s64 val_i;
    __u64 val_u;
    double val_d;
    char val_s[MAX_STRING_SIZE];
};

BPF_RINGBUF_OUTPUT(ring_buf_put, 1 << 4);

int enter_dbput(struct pt_regs *ctx, void *paddr, short dbrType, void *pbuffer, long nRequest)
{
    int ret;
    short _dbrType;
    long _nRequest;
    __u32 zero = 0;
    struct event_put e = {};

    e.ktime_ns = bpf_ktime_get_ns();

    dbAddr *data = db_data_put.lookup(&zero);

    if (!data)
        return 0;

    int size = sizeof(dbAddr);
    if (paddr != 0)
        ret = bpf_probe_read_user(data, size, paddr);

    if (!pbuffer)
        return 0;

    _dbrType = dbrType;
    _nRequest = nRequest;

    char fieldname[41];
    dbAddr *n = (dbAddr *)paddr;

    if (n != 0)
        ret = bpf_probe_read_user(fieldname, sizeof(fieldname), n->pfldDes->name);

    switch (_dbrType)
    {
    case DBF_STRING:
    {
        ret = bpf_probe_read_user(&(e.val_s), MAX_STRING_SIZE, (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_STRING;
        break;
    }
    case DBF_CHAR:
    {
        __s8 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_INT;
        e.val_i = (__s64)val;
        break;
    }
    case DBF_SHORT:
    {
        __s16 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_INT;
        e.val_i = (__s64)val;
        break;
    }
    case DBF_LONG:
    {
        __s32 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_INT;
        e.val_i = (__s64)val;
        break;
    }
    case DBF_INT64:
    {
        __s64 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_INT;
        e.val_i = (__s64)val;
        break;
    }
    case DBF_UCHAR:
    {
        __u8 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_UINT;
        e.val_u = (__u64)val;
        break;
    }
    case DBF_USHORT:
    case DBF_ENUM:
    {
        __u16 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_UINT;
        e.val_u = (__u64)val;
        break;
    }
    case DBF_ULONG:
    {
        __u32 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_UINT;
        e.val_u = (__u64)val;
        break;
    }
    case DBF_UINT64:
    {
        __u64 val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_UINT;
        e.val_u = (__u64)val;
        break;
    }
    case DBF_FLOAT:
    case DBF_DOUBLE:
    {
        double val;
        ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)pbuffer));
        e.val_type = VAL_TYPE_DOUBLE;
        e.val_d = (double)val;
        break;
    }
    default:
        e.val_type = VAL_TYPE_NULL;
        break;
    }

    ret = bpf_probe_read_user(e.pvname, sizeof(e.pvname), data->precord->name);
    ret = bpf_probe_read_user(e.field_name, sizeof(e.field_name), n->pfldDes->name);

    ring_buf_put.ringbuf_output(&e, sizeof(struct event_put), 0);

    return 0;
};

int enter_process(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;
    struct event_process *e = event_temp.lookup(&zero);

    if (!e)
        return 0;

    e->ktime_ns = bpf_ktime_get_ns();

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
        bpf_trace_printk("hello %d", random_id);
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

    e->type = 0;
    e->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(e->comm), sizeof(e->comm));
    e->state = STATE_ENTER_PROC;
    memcpy((e->pvname), data->name, sizeof(e->pvname));
    e->id = proc_info.id;
    e->count = proc_info.count;
    e->ts_sec = data->time.secPastEpoch;
    e->ts_nano = data->time.nsec;
    e->val_i = 0;
    e->val_u = 0;
    e->val_d = 0;

    ring_buf.ringbuf_output(e, sizeof(struct event_process), 0);

    return 0;
};

int exit_process(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    struct event_process *e = event_temp.lookup(&zero);

    if (!e)
        return 0;
    e->ktime_ns = bpf_ktime_get_ns();

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
            bpf_trace_printk("trace: %d", proc_info.count);
            process_hash.delete(&pid);
        }
        else
        {
            process_hash.update(&pid, &proc_info);
        }
    }

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

    char pvname[61];
    size = sizeof(pvname);
    if (recnode->recordname != 0)
    {
        ret = bpf_probe_read_user(pvname, size, recnode->recordname);
        bpf_trace_printk("exit: %s", pvname);
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
    size = sizeof(fname);
    if (dbfld->name != 0)
    {
        ret = bpf_probe_read_user(fname, size, dbfld->name);
        bpf_trace_printk("exit: %s", fname);
    }

    int field_type = dbfld->field_type;
    bpf_trace_printk("field: %d", field_type);

    e->type = 1;
    e->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(e->comm), sizeof(e->comm));
    e->state = STATE_EXIT_PROC;
    memcpy(e->pvname, pvname, sizeof(e->pvname));
    e->id = proc_info.id;
    e->count = proc_info.count + 1;
    e->ts_sec = data->time.secPastEpoch;
    e->ts_nano = data->time.nsec;
    e->val_type = 0;
    e->val_i = 0;
    e->val_u = 0;
    e->val_d = 0;

    if (precord != 0)
    {
        switch (field_type)
        {
        case DBF_STRING:
        {
            ret = bpf_probe_read_user(&(e->val_s), MAX_STRING_SIZE, (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %s", e->val_s);
            e->val_type = VAL_TYPE_STRING;
            break;
        }
        case DBF_CHAR:
        {
            __s8 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_INT;
            e->val_i = (__s64)val;
            break;
        }
        case DBF_SHORT:
        {
            __s16 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_INT;
            e->val_i = (__s64)val;
            break;
        }
        case DBF_LONG:
        {
            __s32 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_INT;
            e->val_i = (__s64)val;
            break;
        }
        case DBF_INT64:
        {
            __s64 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_INT;
            e->val_i = (__s64)val;
            break;
        }
        case DBF_UCHAR:
        {
            __u8 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_UINT;
            e->val_u = (__u64)val;
            break;
        }
        case DBF_USHORT:
        case DBF_ENUM:
        {
            __u16 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_UINT;
            e->val_u = (__u64)val;
            break;
        }
        case DBF_ULONG:
        {
            __u32 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_UINT;
            e->val_u = (__u64)val;
            break;
        }
        case DBF_UINT64:
        {
            __u64 val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_UINT;
            e->val_u = (__u64)val;
            break;
        }
        case DBF_FLOAT:
        case DBF_DOUBLE:
        {
            double val;
            ret = bpf_probe_read_user(&val, sizeof(val), (void *)((char *)recnode->precord + dbfld->offset));
            bpf_trace_printk("exit val: %d", val);
            e->val_type = VAL_TYPE_DOUBLE;
            e->val_d = (double)val;
            break;
        }
        default:
            e->val_type = VAL_TYPE_NULL;
            break;
        }
    }

    ring_buf.ringbuf_output(e, sizeof(struct event_process), 0);

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

int enter_dbfirstrecord(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    if (!PT_REGS_PARM1(ctx))
        return 0;

    DBENTRY *pent = (DBENTRY *)PT_REGS_PARM1(ctx);

    DBENTRY **ent = dbent_dbl.lookup(&zero);

    if (!ent)
        return 0;
    *ent = pent;

    return 0;
};

int exit_dbfirstrecord(struct pt_regs *ctx)
{
    __u32 zero = 0;

    DBENTRY **ppent = dbent_dbl.lookup(&zero);
    if (!ppent)
        return 0;
    DBENTRY *pent = *ppent;

    if (!pent)
        return 0;

    DBENTRY ent;

    int ret;
    if (pent != 0)
        ret = bpf_probe_read_user(&ent, sizeof(ent), pent);

    dbRecordNode *recnode = recn.lookup(&zero);

    if (!recnode)
    {
        return 0;
    }
    int size = sizeof(dbRecordNode);

    if (ent.precnode != 0)
    {
        ret = bpf_probe_read_user(recnode, size, ent.precnode);
    }

    char pvname[61];
    size = sizeof(pvname);
    if (recnode->recordname != 0)
    {
        ret = bpf_probe_read_user(pvname, size, recnode->recordname);
        bpf_trace_printk("dbl: %s", pvname);
    }

    struct key_t key;
    memcpy(key.name, pvname, sizeof(key.name));

    int flag = 0;
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

    pv_entry_hash.update(&key, &ent);
    return 0;
};
