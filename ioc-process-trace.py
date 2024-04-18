#!/usr/bin/python3

from __future__ import print_function
from os import getpid
import argparse
import ctypes as ct
import time
import sys

from bcc import BPF

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "-p", "-path", dest="libpath", required=True, help="Path to libdbCore"
)

args = parser.parse_args()
libpath = args.libpath

b = BPF(src_file="ioc-process-trace.c", debug=0)
b.attach_uprobe(
    name=libpath,
    sym="dbCreateRecord",
    fn_name="enter_createrec",
)
b.attach_uretprobe(
    name=libpath,
    sym="dbCreateRecord",
    fn_name="exit_createrec",
)

b.attach_uprobe(
    name=libpath,
    sym="dbProcess",
    fn_name="enter_process",
)
b.attach_uretprobe(
    name=libpath,
    sym="dbProcess",
    fn_name="exit_process",
)

b.attach_uprobe(
    name=libpath,
    sym="dbGetRecordName",
    fn_name="enter_dbfirstrecord",
)
b.attach_uretprobe(
    name=libpath,
    sym="dbGetRecordName",
    fn_name="exit_dbfirstrecord",
)

# header
# print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MSG"))


# The structure is defined manually in this program.
# BCC can cast the automatically, but double is not supported.
# https://github.com/iovisor/bcc/pull/2198

TASK_COMM_LEN = 16  # linux/sched.h


class Data(ct.Structure):
    _fields_ = [
        ("type", ct.c_int),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("ktime_ns", ct.c_ulonglong),
        ("state", ct.c_uint),
        ("id", ct.c_uint),
        ("count", ct.c_uint),
        ("ts_sec", ct.c_uint),
        ("ts_nano", ct.c_uint),
        ("pvname", ct.c_char * 61),
        ("val_type", ct.c_uint),
        ("val_i", ct.c_longlong),
        ("val_u", ct.c_ulonglong),
        ("val_d", ct.c_double),
    ]


STATE_ENTER_PROC = 1
STATE_EXIT_PROC = 2

STATE_DICT = {STATE_ENTER_PROC: '"Enter Process"', STATE_EXIT_PROC: '"Exit Process"'}

VAL_TYPE_INT = 1
VAL_TYPE_UINT = 2
VAL_TYPE_DOUBLE = 3


def callback(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    comm = f'"{event.comm.decode("utf-8")}"'
    pvname = f'"{event.pvname.decode("utf-8")}"'
    state = STATE_DICT.get(event.state, "Unknown")
    if event.type == 0:
        msg = f"pid={event.pid} comm={comm} time_ns={event.ktime_ns} state={state} id={event.id} count={event.count} ts_sec={event.ts_sec} ts_nano={event.ts_nano} pvname={pvname}"
    elif event.type == 1:
        val = 0
        if event.val_type == VAL_TYPE_INT:
            val = event.val_i
        if event.val_type == VAL_TYPE_UINT:
            val = event.val_u
        if event.val_type == VAL_TYPE_DOUBLE:
            val = event.val_d
        msg = f"pid={event.pid} comm={comm} time_ns={event.ktime_ns} state={state} id={event.id} count={event.count} ts_sec={event.ts_sec} ts_nano={event.ts_nano} pvname={pvname} val={val}"
    print(msg)


b["ring_buf"].open_ring_buffer(callback)

# format output
# me = getpid()
# while 1:
#    try:
#        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
#    except ValueError:
#        continue
#    if pid == me or msg == "":
#        continue
#    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))


try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()
