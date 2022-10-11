# RPC Toolkit

![RPC Toolkit banner](rpc_toolkit.png)

RPC Toolkit is a set of tools, articles, blog posts and links to help security researchers drive their RPC research.

During the last months, our team has put a lot of effort in learning MS-RPC, its internals, security and weaknesses. Along the way, we wrote some tools and automations to facilitate parts of the research process. We have shared our findings in blog posts, tweets and conference talks, and we'd like to make all these materials accessible through this repo.

We will also link to external tools and publications by other researchers, which we found useful in our learning process.

## Tools

* [IDL scraper and parser](idl_scraper)
* [PE RPC scraper and parser](pe_rpc_if_scraper)
* [RPCView](https://www.rpcview.org/) (by Jean-Marie Borello, Julien Boutet, Jeremy Bouetard and Yoanne Girardin)
* [RPCEnum](https://github.com/xpn/RpcEnum) (by [@_xpn_](https://twitter.com/_xpn_))

## MS-RPC Background and Analysis

* [RPC Interface Inventory](rpc_interface_lists)
* [A Definitive Guide to the Remote Procedure Call (RPC) Filter](https://www.akamai.com/blog/security/guide-rpc-filter)
* [Analyzing RPC With Ghidra and Neo4j](https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/) (by [@_xpn_](https://twitter.com/_xpn_))
* [Offensive Windows IPC Internals 2: RPC](https://csandker.io/2021/02/21/Offensive-Windows-IPC-2-RPC.html) (by [@csandker](https://twitter.com/0xcsandker))

## Vulnerabilities

* [CVE-2022-30216 - Authentication coercion of the Windows “Server” service](https://www.akamai.com/blog/security/authentication-coercion-windows-server-service)
* [Critical Remote Code Execution Vulnerabilities in Windows RPC Runtime](https://www.akamai.com/blog/security/critical-remote-code-execution-vulnerabilities-windows-rpc-runtime)
* [RPC Runtime, Take Two: Discovering a New Vulnerability](https://www.akamai.com/blog/security/rpc-runtime-patch-tuesday-take-two)
* [Cold Hard Cache: Caching Vulnerabilities in the _Server_ and _Workstation_ Services](https://www.akamai.com/blog/security-research/cold-hard-cache-bypassing-rpc-with-cache-abuse)

## Exploitation Proof-of-Concept (PoC)

* [CVE-2022-30216](../PoCs/cve-2022-30216)
* CVE-2022-38034 (TBD)
* _srvsvc_ Caching Bypass (TBD)

## Conferences Materials

* [DEF CON 30](https://defcon.org/html/defcon-30/dc-30-index.html) (Ben Barnea, Ophir Harpaz)
  * [Slides](../conferences_materials/DEF%20CON%2030/Exploring%20Ancient%20Ruins%20to%20Find%20Modern%20Bugs%20-%20Discovering%20a%200-Day%20in%20MS-RPC%20Service.pdf)
  * [Demo video](../conferences_materials/DEF%20CON%2030/CVE-2022-30216_RelayDemo.webm)
* [Hexacon](https://www.hexacon.fr/) (Stiv Kupchik, Ophir Harpaz)
  * Slides
  * Demo video
    
-------
Copyright 2022 Akamai Technologies Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
