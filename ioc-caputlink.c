#include <linux/ptrace.h>
#include "epicsStructure.h"

BPF_PERCPU_ARRAY(link_data, struct link, 1);
BPF_PERCPU_ARRAY(calink_data, struct caLink, 1);

struct event
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

BPF_RINGBUF_OUTPUT(ring_buf, 1 << 4);

enum val_type
{
    VAL_TYPE_INT = 1,
    VAL_TYPE_UINT = 2,
    VAL_TYPE_DOUBLE = 3,
    VAL_TYPE_STRING = 4,
    VAL_TYPE_NULL = 5,
};

int enter_caput(struct pt_regs *ctx, struct link *plink, short dbrType,
                const void *pbuffer, long nRequest, dbCaCallback callback, void *userPvt)
{
    int ret;
    short _dbrType;
    long _nRequest;
    __u32 zero = 0;
    struct event e = {};

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

    ret = bpf_probe_read_user(pvname, sizeof(pvname), pca->pvname);

    if (!pbuffer)
        return 0;

    _dbrType = dbrType;
    _nRequest = nRequest;

    char fieldname[41];

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

    bpf_trace_printk("record=%s", pvname);
    bpf_trace_printk("value=%d", e.val_type);

    return 0;
};
