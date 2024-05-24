from __future__ import print_function
import ctypes as ct
import time


from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from opentelemetry.sdk.resources import SERVICE_NAME, Resource


from customidgen import CustomIdGen


TASK_COMM_LEN = 16  # linux/sched.h
MAX_STRING_SIZE = 60

VAL_TYPE_INT = 1
VAL_TYPE_UINT = 2
VAL_TYPE_DOUBLE = 3
VAL_TYPE_STRING = 4
VAL_TYPE_NULL = 5

BOOT_TIME_NS = int((time.time() - time.monotonic()) * 1e9)
EPICS_TIME_OFFSET = 631152000

STATE_ENTER_PROC = 1
STATE_EXIT_PROC = 2


# The structure is defined manually in this program.
# BCC can cast the automatically, but double is not supported.
# https://github.com/iovisor/bcc/pull/2198


class Data_process(ct.Structure):
    _fields_ = [
        ("type", ct.c_int),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("ktime_ns", ct.c_ulonglong),
        ("state", ct.c_uint),
        ("ptid", ct.c_ulonglong),
        ("psid", ct.c_ulonglong),
        ("tid", ct.c_ulonglong),
        ("sid", ct.c_ulonglong),
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


class ProcessTracer(object):
    def __init__(self, servie_name, processor):
        self.custom_id_generator = CustomIdGen()

        resource = Resource(attributes={SERVICE_NAME: servie_name})

        provider = TracerProvider(
            resource=resource, id_generator=self.custom_id_generator
        )
        provider.add_span_processor(processor)

        self.tracer = trace.get_tracer("my.tracer.name", tracer_provider=provider)

        self.procs = {}

    def callback(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data_process)).contents

        proc = []
        if event.pid in self.procs:
            proc = self.procs[event.pid]
        else:
            self.procs[event.pid] = proc

        # print(f"{event.pvname} {event.pid} {event.state} {event.ptid} {event.psid}")
        if event.state == STATE_ENTER_PROC:
            events = [event]
            proc.append(events)
            return

        if event.state == STATE_EXIT_PROC:
            events = proc[event.count - 1]
            events.append(event)
            if event.count == 1:
                for p in proc:
                    self.export_zipkin_index(p)

                del self.procs[event.pid]

    def export_zipkin_index(self, events):
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

        # print(pvname)
        ptid = enter.ptid | enter.ptid << 64
        # print(ptid)
        if ptid != 0:
            psid = enter.psid

            span_context = SpanContext(
                trace_id=ptid,
                span_id=psid,
                is_remote=True,
                trace_flags=TraceFlags(0x01),
            )
            ctx = trace.set_span_in_context(NonRecordingSpan(span_context))

        sid = enter.sid
        tid = enter.tid | enter.tid << 64
        self.custom_id_generator.set_generate_span_id_arguments(tid, sid)
        with self.tracer.start_as_current_span(
            span_name,
            start_time=(enter.ktime_ns + BOOT_TIME_NS),
            end_on_exit=False,
            context=ctx,
        ) as span:
            # export_zipkin_index(proc, index + 1)
            ts = int((exit.ts_sec + EPICS_TIME_OFFSET) * 1e9 + exit.ts_nano)
            span.add_event("Process", timestamp=ts)
            span.set_attribute("pv.name", pvname)
            span.set_attribute("pv.value", val)
            span.set_attribute("os.pid", enter.pid)
            span.end(exit.ktime_ns + BOOT_TIME_NS)
