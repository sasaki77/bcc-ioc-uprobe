#include <linux/ptrace.h>
#include <linux/sched.h>
#include "epicsStructure.h"

#define TASK_COMM_LEN 16

struct otel_context
{
    __u64 tid;
    __u64 sid;
};

struct key_t
{
    char name[61];
};

struct create_rec_args
{
    struct key_t key;
    DBENTRY *pentry;
};

struct process_info
{
    __u32 count;
};

struct key_proc_pv
{
    __u32 pid;
    __u32 count;
};

struct event_process
{
    __u32 type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 ktime_ns;
    __u32 state;
    __u64 ptid;
    __u64 psid;
    __u64 tid;
    __u64 sid;
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

struct event_put
{
    __u64 ktime_ns;
    __u64 ktime_ns_end;
    char pvname[61];
    char field_name[61];
    __u64 ptid;
    __u64 psid;
    __u64 tid;
    __u64 sid;
    __u32 val_type;
    __s64 val_i;
    __u64 val_u;
    double val_d;
    char val_s[MAX_STRING_SIZE];
};

struct put_pv
{
    char name[61];
    __u32 id;
};

struct event_caput
{
    __u64 ktime_ns;
    __u64 ktime_ns_end;
    char pvname[100];
    __u64 ptid;
    __u64 psid;
    __u64 tid;
    __u64 sid;
    __u32 val_type;
    __s64 val_i;
    __u64 val_u;
    double val_d;
    char val_s[MAX_STRING_SIZE];
};

BPF_HASH(otel_ctx, __u64, struct otel_context);

BPF_PERCPU_ARRAY(db_data, dbCommon, 1);
BPF_PERCPU_ARRAY(retdb_data, dbCommon, 1);
BPF_PERCPU_ARRAY(recn, dbRecordNode, 1);
BPF_PERCPU_ARRAY(rectype, dbRecordType, 1);
BPF_PERCPU_ARRAY(mapdbfld, dbFldDes, 1);
BPF_PERCPU_ARRAY(dbent_dbl, DBENTRY *, 1);
BPF_PERCPU_ARRAY(dbent, struct create_rec_args, 1);

BPF_HASH(pv_entry_hash, struct key_t, DBENTRY);

BPF_HASH(process_hash, __u64, struct process_info);
BPF_HASH(proc_pv_hash, struct key_proc_pv, dbCommon *);

BPF_RINGBUF_OUTPUT(ring_buf, 1 << 4);

BPF_PERCPU_ARRAY(event_temp, struct event_process, 1);
BPF_PERCPU_ARRAY(e, struct event_process, 1);
BPF_PERCPU_ARRAY(db_data_put, dbAddr, 1);

BPF_RINGBUF_OUTPUT(ring_buf_put, 1 << 4);
BPF_HASH(put_pv_hash, __u64, struct event_put);

BPF_PERCPU_ARRAY(link_data, struct link, 1);
BPF_PERCPU_ARRAY(calink_data, struct caLink, 1);
BPF_HASH(caput_pv_hash, __u64, struct event_caput);
BPF_RINGBUF_OUTPUT(ring_buf_caput, 1 << 4);

static __always_inline short pickPvValue(short dbr_type, void *pbuffer, __s64 *val_i, __u64 *val_u, double *val_d, char *val_s)
{
    int ret;
    short val_type;

    switch (dbr_type)
    {
    case DBF_STRING:
    {
        ret = bpf_probe_read_user(val_s, MAX_STRING_SIZE, pbuffer);
        val_type = VAL_TYPE_STRING;
        break;
    }
    case DBF_CHAR:
    {
        __s8 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_INT;
        *val_i = (__s64)val;
        break;
    }
    case DBF_SHORT:
    {
        __s16 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_INT;
        *val_i = (__s64)val;
        break;
    }
    case DBF_LONG:
    {
        __s32 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_INT;
        *val_i = (__s64)val;
        break;
    }
    case DBF_INT64:
    {
        __s64 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_INT;
        *val_i = (__s64)val;
        break;
    }
    case DBF_UCHAR:
    {
        __u8 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_UINT;
        *val_u = (__u64)val;
        break;
    }
    case DBF_USHORT:
    case DBF_ENUM:
    {
        __u16 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_UINT;
        *val_u = (__u64)val;
        break;
    }
    case DBF_ULONG:
    {
        __u32 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_UINT;
        *val_u = (__u64)val;
        break;
    }
    case DBF_UINT64:
    {
        __u64 val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_UINT;
        *val_u = (__u64)val;
        break;
    }
    case DBF_FLOAT:
    case DBF_DOUBLE:
    {
        double val;
        ret = bpf_probe_read_user(&val, sizeof(val), pbuffer);
        val_type = VAL_TYPE_DOUBLE;
        *val_d = (double)val;
        break;
    }
    default:
        val_type = VAL_TYPE_NULL;
        break;
    }
    return val_type;
}

static __always_inline void updateOtelContext(__u64 pid, __u64 *ptid, __u64 *psid, __u64 *tid, __u64 *sid)
{
    struct otel_context *ot_ctx = otel_ctx.lookup(&pid);
    struct otel_context new_ctx;

    if (!ot_ctx)
    {
        ot_ctx = &new_ctx;
        ot_ctx->tid = bpf_get_prandom_u32();
        ot_ctx->tid = (ot_ctx->tid - 1) | (ot_ctx->tid + 1) << 32;
        *ptid = 0;
        *psid = 0;
    }
    else
    {
        *ptid = ot_ctx->tid;
        *psid = ot_ctx->sid;
    }

    ot_ctx->sid = bpf_get_prandom_u32();
    ot_ctx->sid = (ot_ctx->sid - 1) | (ot_ctx->sid + 1) << 32;

    *tid = ot_ctx->tid;
    *sid = ot_ctx->sid;

    otel_ctx.update(&pid, ot_ctx);
}

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

    e.val_type = pickPvValue(dbrType, pbuffer, &(e.val_i), &(e.val_u), &(e.val_d), e.val_s);
    ret = bpf_probe_read_user(e.pvname, sizeof(e.pvname), data->precord->name);
    ret = bpf_probe_read_user(e.field_name, sizeof(e.field_name), n->pfldDes->name);

    __u64 pid = bpf_get_current_pid_tgid();
    updateOtelContext(pid, &(e.ptid), &(e.psid), &(e.tid), &(e.sid));

    put_pv_hash.update(&pid, &e);

    return 0;
};

int exit_dbput(struct pt_regs *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid();
    struct event_put *p = put_pv_hash.lookup(&pid);
    if (!p)
    {
        return 0;
    }

    p->ktime_ns_end = bpf_ktime_get_ns();
    ring_buf_put.ringbuf_output(p, sizeof(struct event_put), 0);

    put_pv_hash.delete(&pid);
    otel_ctx.delete(&pid);

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

    struct process_info proc_info = {0};
    struct process_info *pproc_info;
    struct key_proc_pv key;
    __u64 pid = bpf_get_current_pid_tgid();

    pproc_info = process_hash.lookup(&pid);

    __u32 random_id = bpf_get_prandom_u32();

    if (pproc_info)
    {
        proc_info.count = pproc_info->count;
    }
    proc_info.count = proc_info.count + 1;

    key.pid = pid & 0xffffffff;
    key.count = proc_info.count;

    process_hash.update(&pid, &proc_info);
    proc_pv_hash.update(&key, &precord);
    bpf_trace_printk("enter process: %d %d", key.pid, key.count);

    e->type = 0;
    e->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(e->comm), sizeof(e->comm));
    e->state = STATE_ENTER_PROC;
    memcpy((e->pvname), data->name, sizeof(e->pvname));
    e->count = proc_info.count;
    e->ts_sec = data->time.secPastEpoch;
    e->ts_nano = data->time.nsec;
    e->val_i = 0;
    e->val_u = 0;
    e->val_d = 0;

    updateOtelContext(pid, &(e->ptid), &(e->psid), &(e->tid), &(e->sid));

    ring_buf.ringbuf_output(e, sizeof(struct event_process), 0);

    return 0;
};

int exit_process(struct pt_regs *ctx)
{
    int ret;
    __u32 zero = 0;

    struct event_process *e = event_temp.lookup(&zero);
    bpf_trace_printk("exit process");

    if (!e)
        return 0;
    e->ktime_ns = bpf_ktime_get_ns();

    struct process_info proc_info = {0};
    struct process_info *pproc_info;
    struct key_proc_pv key_pv;
    __u64 pid = bpf_get_current_pid_tgid();

    pproc_info = process_hash.lookup(&pid);

    if (!pproc_info)
    {
        return 0;
    }

    key_pv.pid = pid;
    key_pv.count = pproc_info->count;

    struct dbCommon **pprecord;
    pprecord = proc_pv_hash.lookup(&key_pv);
    bpf_trace_printk("exit process: %d %d", key_pv.pid, key_pv.count);

    if (!pprecord)
    {
        bpf_trace_printk("exit error");
        return 0;
    }

    struct dbCommon *precord;
    precord = *pprecord;

    proc_pv_hash.delete(&key_pv);

    if (pproc_info != 0)
    {
        proc_info.count = pproc_info->count;
        proc_info.count = proc_info.count - 1;
        if (proc_info.count == 0)
        {
            bpf_trace_printk("trace: %d", proc_info.count);
            process_hash.delete(&pid);
            otel_ctx.delete(&pid);
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
    e->count = proc_info.count + 1;
    e->ts_sec = data->time.secPastEpoch;
    e->ts_nano = data->time.nsec;
    e->val_type = 0;
    e->val_i = 0;
    e->val_u = 0;
    e->val_d = 0;

    if (precord != 0)
    {
        e->val_type = pickPvValue(field_type, (void *)((char *)recnode->precord + dbfld->offset), &(e->val_i), &(e->val_u), &(e->val_d), e->val_s);
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

int enter_caput(struct pt_regs *ctx, struct link *plink, short dbrType,
                void *pbuffer, long nRequest, dbCaCallback callback, void *userPvt)
{
    int ret;
    short _dbrType;
    __u32 zero = 0;
    struct event_caput e = {};

    e.ktime_ns = bpf_ktime_get_ns();

    struct link *ldata = link_data.lookup(&zero);

    if (!ldata)
        return 0;

    if (!plink)
        return 0;

    ret = bpf_probe_read_user(ldata, sizeof(struct link), plink);

    caLink *pca = calink_data.lookup(&zero);

    if (!pca)
        return 0;

    if (!(plink->value.pv_link.pvt))
        return 0;

    ret = bpf_probe_read_user(pca, sizeof(struct caLink), plink->value.pv_link.pvt);

    char pvname[100];

    if (!(pca->pvname))
        return 0;

    ret = bpf_probe_read_user(e.pvname, sizeof(pvname), pca->pvname);

    if (!pbuffer)
        return 0;

    _dbrType = dbrType;

    char fieldname[41];
    e.val_type = pickPvValue(dbrType, pbuffer, &(e.val_i), &(e.val_u), &(e.val_d), e.val_s);

    bpf_trace_printk("record=%s", pvname);
    bpf_trace_printk("value=%d", e.val_type);

    __u64 pid = bpf_get_current_pid_tgid();
    updateOtelContext(pid, &(e.ptid), &(e.psid), &(e.tid), &(e.sid));

    caput_pv_hash.update(&pid, &e);

    return 0;
};

int exit_caput(struct pt_regs *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid();
    struct event_caput *p = caput_pv_hash.lookup(&pid);

    if (!p)
    {
        return 0;
    }

    p->ktime_ns_end = bpf_ktime_get_ns();
    ring_buf_caput.ringbuf_output(p, sizeof(struct event_caput), 0);

    caput_pv_hash.delete(&pid);

    return 0;
};
