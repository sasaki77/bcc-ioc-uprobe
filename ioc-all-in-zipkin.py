#!/usr/bin/python3

from __future__ import print_function
from os import getpid
import argparse
import time
import sys

from bcc import BPF


from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from opentelemetry.exporter.zipkin.proto.http import ZipkinExporter

from ptracezipkin import ProcessTracer
from putzipkin import PutTracer
from caputzipkin import CaputTracer


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
b.attach_uprobe(
    name=libpath,
    sym="dbCaPutLinkCallback",
    fn_name="enter_caput",
)
b.attach_uretprobe(
    name=libpath,
    sym="dbCaPutLinkCallback",
    fn_name="exit_caput",
)


resource = Resource(attributes={SERVICE_NAME: "process-service"})
zipkin_exporter = ZipkinExporter(endpoint="http://localhost:9411/api/v2/spans")

# processor = BatchSpanProcessor(ConsoleSpanExporter())
prt = ProcessTracer("process-service", BatchSpanProcessor(zipkin_exporter))
ptt = PutTracer("put-service", BatchSpanProcessor(zipkin_exporter))
cpt = CaputTracer("caput-service", BatchSpanProcessor(zipkin_exporter))

b["ring_buf"].open_ring_buffer(prt.callback)
b["ring_buf_put"].open_ring_buffer(ptt.callback)
b["ring_buf_caput"].open_ring_buffer(cpt.callback)


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
