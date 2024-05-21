#!/usr/bin/python3

from __future__ import print_function
from os import getpid
import argparse
import ctypes as ct
import time
import sys

from bcc import BPF


from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from opentelemetry.exporter.zipkin.proto.http import ZipkinExporter

from psutil import boot_time
from customidgen import CustomIdGen


resource = Resource(attributes={SERVICE_NAME: "process-service"})
zipkin_exporter = ZipkinExporter(endpoint="http://localhost:9411/api/v2/spans")

# provider = TracerProvider()
provider = TracerProvider(resource=resource)
# processor = BatchSpanProcessor(ConsoleSpanExporter())
processor = BatchSpanProcessor(zipkin_exporter)
provider.add_span_processor(processor)

# Sets the global default tracer provider
trace.set_tracer_provider(provider)

# Creates a tracer from the global tracer provider
tracer = trace.get_tracer("my.tracer.name")

custom_id_generator = CustomIdGen()
put_resource = Resource(attributes={SERVICE_NAME: "put-service"})
put_tracer_provider = TracerProvider(
    resource=put_resource, id_generator=custom_id_generator
)
# put_processor = BatchSpanProcessor(ConsoleSpanExporter())
put_processor = BatchSpanProcessor(zipkin_exporter)
put_tracer_provider.add_span_processor(put_processor)

put_tracer = trace.get_tracer("tracer.two", tracer_provider=put_tracer_provider)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "-p", "-path", dest="libpath", required=True, help="Path to libdbCore"
)

args = parser.parse_args()
libpath = args.libpath

b = BPF(src_file="ioc-all-in-zipkin.c", debug=0)
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
b.attach_uprobe(
    name=libpath,
    sym="dbPutField",
    fn_name="enter_dbput",
)
b.attach_uretprobe(
    name=libpath,
    sym="dbPutField",
    fn_name="exit_dbput",
)

# The structure is defined manually in this program.
# BCC can cast the automatically, but double is not supported.
# https://github.com/iovisor/bcc/pull/2198

TASK_COMM_LEN = 16  # linux/sched.h
MAX_STRING_SIZE = 60


class Data_process(ct.Structure):
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
        ("val_s", ct.c_char * MAX_STRING_SIZE),
    ]


class Data_put(ct.Structure):
    _fields_ = [
        ("ktime_ns", ct.c_ulonglong),
        ("ktime_ns_end", ct.c_ulonglong),
        ("pvname", ct.c_char * 61),
        ("field_name", ct.c_char * 61),
        ("id", ct.c_uint),
        ("val_type", ct.c_uint),
        ("val_i", ct.c_longlong),
        ("val_u", ct.c_ulonglong),
        ("val_d", ct.c_double),
        ("val_s", ct.c_char * MAX_STRING_SIZE),
    ]


STATE_ENTER_PROC = 1
STATE_EXIT_PROC = 2

STATE_DICT = {STATE_ENTER_PROC: '"Enter Process"', STATE_EXIT_PROC: '"Exit Process"'}

VAL_TYPE_INT = 1
VAL_TYPE_UINT = 2
VAL_TYPE_DOUBLE = 3
VAL_TYPE_STRING = 4
VAL_TYPE_NULL = 5

procs = {}
BOOT_TIME_NS = int((time.time() - time.monotonic()) * 1e9)
EPICS_TIME_OFFSET = 631152000


def callback_process(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_process)).contents

    proc = []
    if event.id in procs:
        proc = procs[event.id]
    else:
        procs[event.id] = proc

    if event.state == STATE_ENTER_PROC:
        events = [event]
        proc.append(events)
        return

    if event.state == STATE_EXIT_PROC:
        events = proc[event.count - 1]
        events.append(event)
        if event.count == 1:
            custom_id_generator.set_generate_span_id_arguments(None, None)
            export_zipkin_index(proc, 0)
            del procs[event.id]


def export_zipkin_index(proc, index):
    if len(proc) < index + 1:
        return

    events = proc[index]

    if len(events) < 2:
        return

    enter = events[0]
    exit = events[1]

    if enter.state == STATE_EXIT_PROC:
        return

    val = 0
    if exit.val_type == VAL_TYPE_INT:
        val = exit.val_i
    if exit.val_type == VAL_TYPE_UINT:
        val = exit.val_u
    if exit.val_type == VAL_TYPE_DOUBLE:
        val = exit.val_d
    if exit.val_type == VAL_TYPE_STRING:
        val = exit.val_s.decode("utf-8")
    if exit.val_type == VAL_TYPE_NULL:
        val = "NULL"

    pvname = enter.pvname.decode("utf-8")
    span_name = f"{pvname} ({val})"
    ctx = None

    if index == 0:
        rid = enter.id
        sid = rid | rid << 32
        tid = sid | sid << 64

        span_context = SpanContext(
            trace_id=tid,
            span_id=sid,
            is_remote=True,
            trace_flags=TraceFlags(0x01),
        )
        ctx = trace.set_span_in_context(NonRecordingSpan(span_context))

    with tracer.start_as_current_span(
        span_name,
        start_time=(enter.ktime_ns + BOOT_TIME_NS),
        end_on_exit=False,
        context=ctx,
    ) as span:
        export_zipkin_index(proc, index + 1)
        ts = int((exit.ts_sec + EPICS_TIME_OFFSET) * 1e9 + exit.ts_nano)
        span.add_event("Process", timestamp=ts)
        span.set_attribute("pv.name", pvname)
        span.set_attribute("pv.value", val)
        span.end(exit.ktime_ns + BOOT_TIME_NS)


def callback_put(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_put)).contents

    if event.val_type == VAL_TYPE_INT:
        val = event.val_i
    if event.val_type == VAL_TYPE_UINT:
        val = event.val_u
    if event.val_type == VAL_TYPE_DOUBLE:
        val = event.val_d
    if event.val_type == VAL_TYPE_STRING:
        val = event.val_s.decode("utf-8")
    if event.val_type == VAL_TYPE_NULL:
        val = "NULL"

    rid = event.id
    sid = rid | rid << 32
    tid = sid | sid << 64

    pvname = event.pvname.decode("utf-8")
    field_name = event.field_name.decode("utf-8")
    span_name = f"{pvname} ({val})"
    custom_id_generator.set_generate_span_id_arguments(tid, sid)
    with put_tracer.start_as_current_span(
        span_name,
        start_time=(event.ktime_ns + BOOT_TIME_NS),
        end_on_exit=False,
    ) as span:
        span.set_attribute("pv.name", pvname)
        span.set_attribute("pv.field", field_name)
        span.set_attribute("pv.value", val)
        span.end(event.ktime_ns_end + BOOT_TIME_NS)


b["ring_buf"].open_ring_buffer(callback_process)
b["ring_buf_put"].open_ring_buffer(callback_put)


print("start")

try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()

# me = getpid()
# while 1:
#    try:
#        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
#    except ValueError:
#        continue
#    if pid == me or msg == "":
#        continue
#    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
