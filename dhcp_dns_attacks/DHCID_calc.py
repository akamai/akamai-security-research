from hashlib import sha256
import base64 


mac = "00155d011a03" 
fqdn = "pc.aka.test" 


buf = b"\x01" # \x01 stands for DHCP HType of Ethernet 
buf += bytearray.fromhex(mac) # concat with the mac address bytes 


temp = b"" 
count = 0 


# transform the FQDN into DNS wire format and append to the previous data 
for ch in fqdn: 
    if ch == '.':
        buf += count.to_bytes(1,"big") 
        count = 0 
        buf += temp 
        temp = b""
    else: 
        count += 1 
        temp += ord(ch).to_bytes(1,"big") 


buf += count.to_bytes(1,"big") 
buf += temp 
buf += (0).to_bytes(1,"big") 


hash_val = sha256() 
hash_val.update(buf) 
data = hash_val.digest() 


data = b"\x00\x01\x01" + data # Add the default DHCID data bits 


base64_bytes = base64.b64encode(data) 
print(base64_bytes)

