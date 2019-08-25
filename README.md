# golang_struct_builder

an IDA 7.0+ script that creates and names structures from go type
runtime metadata.

## usage

1. run golang_loader_assist.py beforehand
  (https://github.com/strazzere/golang_loader_assist when IDA 7.0
   support lands, otherwise use a barely passable 7.0 compat version
   at https://github.com/spigwitmer/golang_loader_assist)
2. run golang_struct_builder.py


## constraints

* x86_64 only
* tested only on go1.11 and go1.12
