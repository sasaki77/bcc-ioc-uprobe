#include <linux/ptrace.h>
#include "epicsStructure.h"

BPF_PERCPU_ARRAY(db_data, dbAddr, 1);

int printput(struct pt_regs *ctx, void *paddr, short dbrType, void *pbuffer, long nRequest)
{
    int ret;
    short _dbrType;
    long _nRequest;
    __u32 zero = 0;

    dbAddr *data = db_data.lookup(&zero);

    if (!data)
        return 0;

    int size = sizeof(dbAddr);
    if (paddr != 0)
        ret = bpf_probe_read_user(data, size, paddr);

    char buf[41];
    if (pbuffer != 0)
        ret = bpf_probe_read_user(buf, sizeof(buf), pbuffer);

    _dbrType = dbrType;
    _nRequest = nRequest;

    char fieldname[41];
    dbAddr *n = (dbAddr *)paddr;

    if (n != 0)
        ret = bpf_probe_read_user(fieldname, sizeof(fieldname), n->pfldDes->name);

    bpf_trace_printk("record=%s", data->precord->name);
    bpf_trace_printk("field=%s", fieldname);
    bpf_trace_printk("value=%s", buf);

    return 0;
};
