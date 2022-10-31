# PE RPC Scraper

This script is used to analyze PE files for RPC interfaces.
It can be used to bulk analyze a folder or simply one file.

The output is a json file with information about the RPC interfaces used in the PE file.  
Additional information is available if the PE is the RPC server.

Usage: `python usage: pe_rpc_scraper.py [-h] [-r] [-d {idapro,radare}] [-P DISASSEMBLER_PATH] scrape_path output_path`  
If no output path is specified, then by default output would be to the cwd, with the filename "rpc_interfaces.json".


The script was tested on both Windows and Linux, but the disassemblers were tested on a single OS.  
- The Ida integration was tested on Windows, and the scripts assume by default that the idat binary is located under Ida's default installation folder.
- The Ida integration creates ida databases on the same folder as the input file, so make sure you have write permissions there (System32 would cause issues for example)
- The Radare2 integration was tested on Linux - it uses r2pipe, which doesn't work well on newer Windows versions. It assumes r2 can be found through the PATH environment variable.

Example output, as well as some parsing that we did can be found in [rpc_interface_lists](../rpc_interface_lists)

The json output follows this scheme:
```json
  {
  "pe_file_name": {
    "interface_uuid": {
      "role": "client"|"server",
      "number_of_functions": 0,
      "function_pointers": [],
      "function_names": [],
      "interface_address": "0x0"
    },
    "interface_registration_info": {
      "interface_registration_xref_address": {
        "interface_address": "0x0",
        "flags": "0x0",
        "security_callback_addr": "0x0",
        "security_callback_name": "",
        "has_security_descriptor": false|true,
        "global_caching_enabled": false|true
      }
    }
  }
}
```
