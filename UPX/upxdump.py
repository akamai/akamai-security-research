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

filename=sys.argv[1]
dump_filename=filename+".dumped"

## load our file in debugger mode
print("loading "+filename)
r2 = r2pipe.open(filename, flags=['-2'])
r2.cmd('doo')

## get arch and bits info
binfo = r2.cmdj('iaj')['info']
arch = binfo['arch']
bits = binfo['bits']

if arch != "x86":
    print("arch is not supported :*(")
    quit()
else:
    if bits == 64:
        arch = "x86_64"

## start syscall monitoring
print("looking for post unpack breakpoint...")
while True:
    syscall = r2.cmd('dcs')
    if arch == "x86":
        syscall_val = int(r2.cmd('dr?oeax'),16)
        ##if syscall_val == 257:
        if syscall_val == 91:
            break
    elif arch == "x86_64":
        syscall_val = int(r2.cmd('dr?orax'),16)
        if syscall_val == 11:
            break
print("found it!")

## get memory map to identify segments
print("getting memory map...")
dm_res = r2.cmdj('dmj')

## patch existing elf headers to clean up 
## what will become incorrect sections info
print("patching ELF headers...")
base = r2.cmdj('dmj')[0]
r2.cmd('s '+str(hex(base['addr'])))
dump_headers = r2.cmdj('pfj.elf_header')
for elf_head in dump_headers:
    if elf_head['name'] == 'shnum':
        cmd = 'w0 1 @'+str(hex(elf_head['offset']))
        r2.cmd(cmd)
    elif elf_head['name'] == 'shstrndx':
        cmd = 'w0 1 @'+str(hex(elf_head['offset']))
        r2.cmd(cmd)
    elif elf_head['name'] == 'shoff':
        cmd = 'w0 8 @'+str(hex(elf_head['offset']))
        r2.cmd(cmd)

## dump the segments to disk
print("extracting mem segments...")
dump_names = []
for seg in dm_res:
    if seg['name'].find('unk') != -1:
        if seg['perm'].find('---') == -1:
            seg_len = seg['addr_end']-seg['addr']
            seg_name = "seg_"+seg['name']
            dump_cmd = "wtf "+seg_name+" "+str(hex(seg_len))+" @ "+str(hex(seg['addr']))
            r2.cmd(dump_cmd)
            dump_names.append(seg_name)
            print(seg_name+" extracted...")

## reconstruct our unpacked ELF file
## using the extracted segments
## test for ELF minus UPX! headers and
## skip segments until you find a clean
## ELF header... also clean up 
print("generating dumped ELF...")
dumped = open(dump_filename,"w+b")
elf_found = False
for seg_name in dump_names:
    seg = open(seg_name,"r+b")
    seg_data = seg.read()
    seg.close()
    os.remove(seg_name)
    if elf_found == False:
        if seg_data[1:4] == b"ELF":
            if seg_data.find(b"UPX!") != -1:
                continue
            elf_found = True
        else:
            continue
    dumped.write(seg_data)

## done, close our dump file and inform user
dumped.close()
print("dumped binary written to: "+dump_filename)
quit()
