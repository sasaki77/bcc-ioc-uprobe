#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
import ctypes as ct
import time
import argparse
import sys

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from opentelemetry.exporter.zipkin.proto.http import ZipkinExporter

from psutil import boot_time


MAX_STRING_SIZE = 60


class Data(ct.Structure):
    _fields_ = [
        ("ktime_ns", ct.c_ulonglong),
        ("pvname", ct.c_char * 61),
        ("field_name", ct.c_char * 61),
        ("val_type", ct.c_uint),
        ("val_i", ct.c_longlong),
        ("val_u", ct.c_ulonglong),
        ("val_d", ct.c_double),
        ("val_s", ct.c_char * MAX_STRING_SIZE),
    ]


BOOT_TIME_NS = int((time.time() - time.monotonic()) * 1e9)
EPICS_TIME_OFFSET = 631152000

VAL_TYPE_INT = 1
VAL_TYPE_UINT = 2
VAL_TYPE_DOUBLE = 3
VAL_TYPE_STRING = 4
VAL_TYPE_NULL = 5

resource = Resource(attributes={SERVICE_NAME: "your-service-name"})
zipkin_exporter = ZipkinExporter(endpoint="http://localhost:9411/api/v2/spans")

# provider = TracerProvider()
provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(ConsoleSpanExporter())
# processor = BatchSpanProcessor(zipkin_exporter)
provider.add_span_processor(processor)

# Sets the global default tracer provider
trace.set_tracer_provider(provider)

# Creates a tracer from the global tracer provider
tracer = trace.get_tracer("my.tracer.name")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "-p", "-path", dest="libpath", required=True, help="Path to libdbCore"
)

args = parser.parse_args()
libpath = args.libpath

b = BPF(src_file="ioc-dbputfield.c", debug=0)
b.attach_uprobe(
    name=libpath,
    sym="dbPutField",
    fn_name="printput",
)


def callback(cpu, data, size):
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

    pvname = event.pvname.decode("utf-8")
    span_name = f"{pvname} ({val})"
    with tracer.start_as_current_span(
        span_name,
        start_time=(event.ktime_ns + BOOT_TIME_NS),
        end_on_exit=False,
    ) as span:
        span.set_attribute("pv.name", pvname)
        span.set_attribute("pv.value", val)
        span.end(event.ktime_ns + BOOT_TIME_NS)


b["ring_buf"].open_ring_buffer(callback)

print("start")

try:
    while 1:
        b.ring_buffer_poll()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()
