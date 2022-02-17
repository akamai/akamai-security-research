# rpc-filters

This is a git repo to organize some of our knowledge and examples regarding Windows RPC filters.

## RPC Filter Layers and Conditions.xlsx
 This Excel file contains a listing of all Windows Firewall RPC layers, and the conditions they accept, with a short explanation. It is mostly relevant for WinAPI developers, as the layer and condition names are taken directly from the API documentation. Netsh users shouldn't have a problem matching the WinAPI layer and condition name to how they appear in netsh though.
## netsh_rpc_filter.txt
This is a short script file for netsh, that creates a block filter rule on the RPC interface for the Windows Event Log.
To use it, just supply it to netsh with the `-f` flag: `netsh -f netsh_rpc_filter.txt`
This is an example for filter rule creation in netsh, feel free to adapt it to your needs
## RPCFiltersViaWinAPI.c
This is a C source code for RPC filter rule creation with WinAPI. There are a few different functions inside to create different types of filters - on an Interface UUID, on a remote IPv4 address or on a user/group SID. The rule creation functions also contain code to enable auditing for the rules. To use it, just compile the source code to an executable and run it. The filter session created during the rule creation is set to dynamic, so all rules created will be deleted once the process terminates.
## Viewing or Deleting Created Filters
Viewing or deleting filter rules can be done in netsh's `rpc filter` context. Run netsh, and switch to the rpc filter context using `rpc filter`.
Then, to view existing RPC filters, use netsh’s `show filter` command.
To delete RPC filters, use netsh’s `delete filter` command: ```delete filter filterkey=all```
The `filterkey` argument accepts either `all` to delete all rules, or a specific rule UUID, which you can see when you view the filter using `show filter`