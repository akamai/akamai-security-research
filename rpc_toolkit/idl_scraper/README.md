# IDL Scraper

Microsoft publishes, as part of the [technical documents](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/e36c976a-6263-42a8-b119-7a3cc41ddd2a) of their implemented protocols, [IDL files](https://learn.microsoft.com/en-us/windows/win32/midl/interface-definition-idl-file). These files describe the protocols' RPC interfaces as well as the funcions they expose and the structures used by the interface.

## Why should I care?

The publicly available IDL files tell us about the various RPC interfaces implemented in Windows. We believe that having this inventory at hand can be the basis for future MS-RPC security research, for example by:
* Inspecting functions that are exposed over MS-RPC and the parameters they take (file paths? UNCs? strings? buffers?). [_PetitPotam_](https://github.com/topotam/PetitPotam) is an example of such function which could be exploited.
* Comparing the public IDL files with the interfaces compiled into RPC server binaries (the latter information can be obtained by running the [PE RPC interface scraper](https://github.com/akamai/akamai_security_research_priv/tree/main/rpc_toolkit/pe_rpc_if_scraper)).

## What does each script do?

`idl_scraper` simply downloads all IDL files from Microsoft's website to a local folder.

`idl_parser` analyzes these IDLs (mostly using regex) to fetch interface names and UUIDs, function names and signatures and writes all these details to a CSV file. The parser operates on files which are saved locally, and therefore requires a prior execution of the scraper.

## Running the code

Make sure all required libraries are installed by running `pip install -r requirements.txt`.

### IDL Scraper

When executed without any command-line argumnets (i.e. `python idl_scraper.py`), the scraper will download all available IDL files to a folder `IDLFiles` in your current working directory.

You can set the output directory, or a specific protocol name whose IDL file(s) to download, by explicitly specifying the relevant command-line argument. Protocol names can be found on [this page](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/e36c976a-6263-42a8-b119-7a3cc41ddd2a) and usually look something like `ms-tsch`, `mc-ccfg`, `ms-efsr`, etc.

```
usage: idl_scraper.py [-h] [-o OUTPUT] [-p PROTOCOL]

Download all IDL files available in Microsoft's technical documents

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        path to output folder for all IDL files
  -p PROTOCOL, --protocol PROTOCOL
                        name of protocol whose IDL to download, e.g. "ms-tsch"
```

### IDL Parser
The input can either be a single IDL file, or a folder containing multiple IDL files. This argument has to be explicitly specified.

The output is a CSV file with informative summary of the observed interfaces. The results are saved in `idl_functions.csv` unless specified otherwise. 

```
usage: idl_parser.py [-h] [-r] input_path [output_path]

positional arguments:
  input_path   folder or file we wish to parse
  output_path  path for csv output file

optional arguments:
  -h, --help   show this help message and exit
  -r           parse recursively
 ```
