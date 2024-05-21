#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from os import getpid
import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "-p", "-path", dest="libpath", required=True, help="Path to libdbCore"
)

args = parser.parse_args()
libpath = args.libpath

b = BPF(src_file="ioc-caputlink.c", debug=0)
b.attach_uprobe(
    name=libpath,
    sym="dbCaPutLinkCallback",
    fn_name="enter_caput",
)

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MSG"))

# format output
me = getpid()
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if pid == me or msg == "":
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
