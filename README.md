# BCC EPICS IOC uprobe monitor

This is the test codes for BCC to monitor the ioc library symbol.

## Requirements

- BCC: Refer to the [install manual](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

## Usage

```bash
$ sudo ./ioc-dbputfield.py -p <path to libdbCore library>
TIME(s)            COMM             PID    MSG
694.082620000      b'softIoc'       4408   b'record=ET_SASAKI:TEST1'
694.082768000      b'softIoc'       4408   b'field=VAL'
694.082768000      b'softIoc'       4408   b'value=1'
700.326237000      b'CAS-client'    4946   b'record=ET_SASAKI:TEST1'
700.326385000      b'CAS-client'    4946   b'field=HIGH'
700.326386000      b'CAS-client'    4946   b'value=10'
```

```bash
$ sudo ./ioc-dbprocess.py -p <path to libdbCore library>
TIME(s)            COMM             PID    MSG
756.698499000      b'softIoc'       4408   b'ET_SASAKI:TEST1 1078961809 296875269'
756.698704000      b'softIoc'       4408   b'ET_SASAKI:TEST2 1078961809 296877156'
```
