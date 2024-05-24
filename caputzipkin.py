from __future__ import print_function
import ctypes as ct
import time


from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from opentelemetry.sdk.resources import SERVICE_NAME, Resource


from customidgen import CustomIdGen

# The structure is defined manually in this program.
# BCC can cast the automatically, but double is not supported.
# https://github.com/iovisor/bcc/pull/2198

VAL_TYPE_INT = 1
VAL_TYPE_UINT = 2
VAL_TYPE_DOUBLE = 3
VAL_TYPE_STRING = 4
VAL_TYPE_NULL = 5

BOOT_TIME_NS = int((time.time() - time.monotonic()) * 1e9)

MAX_STRING_SIZE = 60


class Data(ct.Structure):
    _fields_ = [
        ("ktime_ns", ct.c_ulonglong),
        ("ktime_ns_end", ct.c_ulonglong),
        ("pvname", ct.c_char * 100),
        ("ptid", ct.c_ulonglong),
        ("psid", ct.c_ulonglong),
        ("tid", ct.c_ulonglong),
        ("sid", ct.c_ulonglong),
        ("val_type", ct.c_uint),
        ("val_i", ct.c_longlong),
        ("val_u", ct.c_ulonglong),
        ("val_d", ct.c_double),
        ("val_s", ct.c_char * MAX_STRING_SIZE),
    ]


class CaputTracer(object):
    def __init__(self, servie_name, processor):
        self.custom_id_generator = CustomIdGen()

        resource = Resource(attributes={SERVICE_NAME: servie_name})

        provider = TracerProvider(
            resource=resource, id_generator=self.custom_id_generator
        )
        provider.add_span_processor(processor)

        self.tracer = trace.get_tracer("tracer.two", tracer_provider=provider)

    def callback(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents

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

        ptid = event.ptid | event.ptid << 64
        if ptid != 0:
            psid = event.psid

            span_context = SpanContext(
                trace_id=ptid,
                span_id=psid,
                is_remote=True,
                trace_flags=TraceFlags(0x01),
            )
            ctx = trace.set_span_in_context(NonRecordingSpan(span_context))

        sid = event.sid
        tid = event.tid | event.tid << 64

        pvname = event.pvname.decode("utf-8")
        span_name = f"{pvname} ({val})"
        self.custom_id_generator.set_generate_span_id_arguments(tid, sid)
        with self.tracer.start_as_current_span(
            span_name,
            start_time=(event.ktime_ns + BOOT_TIME_NS),
            end_on_exit=False,
            context=ctx,
        ) as span:
            span.set_attribute("pv.name", pvname)
            span.set_attribute("pv.value", val)
            span.end(event.ktime_ns_end + BOOT_TIME_NS)
