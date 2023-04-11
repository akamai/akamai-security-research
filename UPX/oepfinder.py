#!/usr/bin/env python

# Copyright 2023 Akamai Technologies, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in
# compliance with the License.  You may obtain a copy
# of the License at
# 
#   https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in
# writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing
# permissions and limitations under the License. 

import os
import sys
import r2pipe
import time

filename = sys.argv[1]
coredump = filename+'.coredump'

## load our file and get it setup for debugging
r2 = r2pipe.open(filename, flags=['-2'])
r2.cmd('doo')

## extract arch and bits info
binfo = r2.cmdj('iaj')['info']
arch = binfo['arch']
bits = binfo['bits']

if arch != "x86":
    print("arch is not supported :*(")
    quit()
else:
    if bits == 64:
        arch = "x86_64"

## start our process of checking for syscalls
## use OEAX and ORAX values to figure out what
## syscall was just made (EAX and RAX will be 
## clobbered by the sysall ret val
while True:
    syscall = r2.cmd('dcs')
    if arch == "x86":
        syscall_val = int(r2.cmd('dr?oeax'),16)
        if syscall_val == 91:
            break
    elif arch == "x86_64":
        syscall_val = int(r2.cmd('dr?orax'),16)
        if syscall_val == 11:
            break

## start our search for clean ELF headers
dm_res = r2.cmdj('dmj')
for seg in dm_res:
    r2.cmd('s '+str(hex(seg['addr'])))
    elf_hit = r2.cmd('/ ELF')
    upx_hit = r2.cmd('/ UPX!')
    if len(elf_hit) > 0:
        if len(upx_hit) == 0:
            break

## using our confirmed ELF header address
## extract OEP 
elf_headers = r2.cmdj('pfj.elf_header')
OEP = 0
for elfhdr in elf_headers:
    if elfhdr['name'] == 'entry':
        OEP = str(hex(elfhdr['value']))
        break

## seek to OEP and grab 25 diasm instructions
r2.cmd('s '+OEP)
ent_inst = r2.cmdj('pdj 25')

## for 32 bit we'll be looking for hlt & call
## before we look for our push to do this
## we'll consume the instructions backwards 
## for 64bit the match is strong without needing
## context so just search for the mov into RDI
ent_inst.reverse()
hlt = False
call = False
for inst in ent_inst:
    if inst['disasm'].find('hlt') != -1:
        hlt = True
        continue
    if hlt == True and inst['disasm'].find('call') != -1:
        call = True
        continue
    if hlt == True and call == True:
        if arch == "x86":
            if inst['disasm'].find('push 0x') != -1:
                main_addr = inst['disasm'].split(' ')[1].strip()
                break
        elif arch == "x86_64":
            if inst['disasm'].find('mov rdi, 0x') != -1:
                main_addr = inst['disasm'].split(',')[1].strip()
                break

## generate our coredump and produce findings
r2.cmd('dg '+coredump)

print("\n============\n")
print('coredump written to: ')
print(coredump)
print("\nfunc addresses:")
print('OEP @ '+OEP)
print('main @ '+main_addr)
print("\n============\n")

quit()
