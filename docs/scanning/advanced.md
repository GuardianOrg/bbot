# Advanced

Below you can find some advanced uses of BBOT.

## BBOT as a Python library

#### Synchronous
```python
from bbot.scanner import Scanner

if __name__ == "__main__":
    scan = Scanner("evilcorp.com", presets=["subdomain-enum"])
    for event in scan.start():
        print(event)
```

#### Asynchronous
```python
from bbot.scanner import Scanner

async def main():
    scan = Scanner("evilcorp.com", presets=["subdomain-enum"])
    async for event in scan.async_start():
        print(event.json())

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## Command-Line Help

<!-- BBOT HELP OUTPUT -->
```text
[1;34musage: [0m[1;35mbbot[0m [[32m-h[0m] [[32m-t [33mTARGET [TARGET ...][0m] [[32m-w [33mWHITELIST [WHITELIST ...][0m] [[32m-b [33mBLACKLIST [BLACKLIST ...][0m] [[36m--strict-scope[0m] [[32m-p [33m[PRESET ...][0m] [[32m-c [33m[CONFIG ...][0m] [[36m-lp[0m]
               [[32m-m [33mMODULE [MODULE ...][0m] [[32m-l[0m] [[36m-lmo[0m] [[36m-em [33mMODULE [MODULE ...][0m] [[32m-f [33mFLAG [FLAG ...][0m] [[36m-lf[0m] [[36m-rf [33mFLAG [FLAG ...][0m] [[36m-ef [33mFLAG [FLAG ...][0m] [[36m--allow-deadly[0m] [[32m-n [33mSCAN_NAME[0m] [[32m-v[0m]
               [[32m-d[0m] [[32m-s[0m] [[36m--force[0m] [[32m-y[0m] [[36m--fast-mode[0m] [[36m--dry-run[0m] [[36m--current-preset[0m] [[36m--current-preset-full[0m] [[36m-mh [33mMODULE[0m] [[32m-o [33mDIR[0m] [[36m-om [33mMODULE [MODULE ...][0m] [[36m-lo[0m] [[36m--json[0m] [[36m--brief[0m]
               [[36m--event-types [33mEVENT_TYPES [EVENT_TYPES ...][0m] [[36m--exclude-cdn[0m] [[36m--no-deps[0m | [36m--force-deps[0m | [36m--retry-deps[0m | [36m--ignore-failed-deps[0m | [36m--install-all-deps[0m] [[36m--version[0m]
               [[36m--proxy [33mHTTP_PROXY[0m] [[32m-H [33mCUSTOM_HEADERS [CUSTOM_HEADERS ...][0m] [[32m-C [33mCUSTOM_COOKIES [CUSTOM_COOKIES ...][0m] [[36m--custom-yara-rules [33mCUSTOM_YARA_RULES[0m] [[36m--user-agent [33mUSER_AGENT[0m]

Bighuge BLS OSINT Tool

[1;34moptions:[0m
  [1;32m-h[0m, [1;36m--help[0m            show this help message and exit

[1;34mTarget:[0m
  [1;32m-t[0m, [1;36m--targets[0m [1;33mTARGET [TARGET ...][0m
                        Targets to seed the scan
  [1;32m-w[0m, [1;36m--whitelist[0m [1;33mWHITELIST [WHITELIST ...][0m
                        What's considered in-scope (by default it's the same as --targets)
  [1;32m-b[0m, [1;36m--blacklist[0m [1;33mBLACKLIST [BLACKLIST ...][0m
                        Don't touch these things
  [1;36m--strict-scope[0m        Don't consider subdomains of target/whitelist to be in-scope

[1;34mPresets:[0m
  [1;32m-p[0m, [1;36m--preset[0m [1;33m[PRESET ...][0m
                        Enable BBOT preset(s)
  [1;32m-c[0m, [1;36m--config[0m [1;33m[CONFIG ...][0m
                        Custom config options in key=value format: e.g. 'modules.shodan.api_key=1234'
  [1;36m-lp[0m, [1;36m--list-presets[0m   List available presets.

[1;34mModules:[0m
  [1;32m-m[0m, [1;36m--modules[0m [1;33mMODULE [MODULE ...][0m
                        Modules to enable. Choices: affiliates,ajaxpro,anubisdb,apkpure,asn,aspnet_bin_exposure,azure_realm,azure_tenant,baddns,baddns_direct,baddns_zone,badsecrets,bevigil,bucket_amazon,bucket_digitalocean,bucket_file_enum,bucket_firebase,bucket_google,bucket_microsoft,bufferoverrun,builtwith,bypass403,c99,certspotter,chaos,code_repository,credshed,crt,crt_db,dehashed,digitorus,dnsbimi,dnsbrute,dnsbrute_mutations,dnscaa,dnscommonsrv,dnsdumpster,dnstlsrpt,docker_pull,dockerhub,dotnetnuke,emailformat,extractous,ffuf,ffuf_shortnames,filedownload,fingerprintx,fullhunt,generic_ssrf,git,git_clone,gitdumper,github_codesearch,github_org,github_usersearch,github_workflows,gitlab_com,gitlab_onprem,google_playstore,gowitness,graphql_introspection,hackertarget,host_header,httpx,hunt,hunterio,iis_shortnames,ip2location,ipneighbor,ipstack,jadx,leakix,legba,lightfuzz,medusa,myssl,newsletters,ntlm,nuclei,oauth,otx,paramminer_cookies,paramminer_getparams,paramminer_headers,passivetotal,pgp,portfilter,portscan,postman,postman_download,rapiddns,reflected_parameters,retirejs,robots,securitytrails,securitytxt,shodan_dns,shodan_idb,sitedossier,skymem,smuggler,social,sslcert,subdomaincenter,subdomainradar,telerik,trickest,trufflehog,url_manipulation,urlscan,vhost,viewdns,virustotal,wafw00f,wappalyzer,wayback,wpscan
  [1;32m-l[0m, [1;36m--list-modules[0m    List available modules.
  [1;36m-lmo[0m, [1;36m--list-module-options[0m
                        Show all module config options
  [1;36m-em[0m, [1;36m--exclude-modules[0m [1;33mMODULE [MODULE ...][0m
                        Exclude these modules.
  [1;32m-f[0m, [1;36m--flags[0m [1;33mFLAG [FLAG ...][0m
                        Enable modules by flag. Choices: active,affiliates,aggressive,baddns,cloud-enum,code-enum,deadly,download,email-enum,iis-shortnames,passive,portscan,safe,service-enum,slow,social-enum,subdomain-enum,subdomain-hijack,web-basic,web-paramminer,web-screenshots,web-thorough
  [1;36m-lf[0m, [1;36m--list-flags[0m     List available flags.
  [1;36m-rf[0m, [1;36m--require-flags[0m [1;33mFLAG [FLAG ...][0m
                        Only enable modules with these flags (e.g. -rf passive)
  [1;36m-ef[0m, [1;36m--exclude-flags[0m [1;33mFLAG [FLAG ...][0m
                        Disable modules with these flags. (e.g. -ef aggressive)
  [1;36m--allow-deadly[0m        Enable the use of highly aggressive modules

[1;34mScan:[0m
  [1;32m-n[0m, [1;36m--name[0m [1;33mSCAN_NAME[0m  Name of scan (default: random)
  [1;32m-v[0m, [1;36m--verbose[0m         Be more verbose
  [1;32m-d[0m, [1;36m--debug[0m           Enable debugging
  [1;32m-s[0m, [1;36m--silent[0m          Be quiet
  [1;36m--force[0m               Run scan even in the case of condition violations or failed module setups
  [1;32m-y[0m, [1;36m--yes[0m             Skip scan confirmation prompt
  [1;36m--fast-mode[0m           Scan only the provided targets as fast as possible, with no extra discovery
  [1;36m--dry-run[0m             Abort before executing scan
  [1;36m--current-preset[0m      Show the current preset in YAML format
  [1;36m--current-preset-full[0m
                        Show the current preset in its full form, including defaults
  [1;36m-mh[0m, [1;36m--module-help[0m [1;33mMODULE[0m
                        Show help for a specific module

[1;34mOutput:[0m
  [1;32m-o[0m, [1;36m--output-dir[0m [1;33mDIR[0m  Directory to output scan results
  [1;36m-om[0m, [1;36m--output-modules[0m [1;33mMODULE [MODULE ...][0m
                        Output module(s). Choices: asset_inventory,csv,discord,emails,http,json,mysql,neo4j,nmap_xml,postgres,python,slack,splunk,sqlite,stdout,subdomains,teams,txt,web_parameters,web_report,websocket
  [1;36m-lo[0m, [1;36m--list-output-modules[0m
                        List available output modules
  [1;36m--json[0m, [1;32m-j[0m            Output scan data in JSON format
  [1;36m--brief[0m, [1;36m-br[0m          Output only the data itself
  [1;36m--event-types[0m [1;33mEVENT_TYPES [EVENT_TYPES ...][0m
                        Choose which event types to display
  [1;36m--exclude-cdn[0m, [1;36m-ec[0m    Filter out unwanted open ports on CDNs/WAFs (80,443 only)

[1;34mModule dependencies:[0m
  Control how modules install their dependencies

  [1;36m--no-deps[0m             Don't install module dependencies
  [1;36m--force-deps[0m          Force install all module dependencies
  [1;36m--retry-deps[0m          Try again to install failed module dependencies
  [1;36m--ignore-failed-deps[0m  Run modules even if they have failed dependencies
  [1;36m--install-all-deps[0m    Install dependencies for all modules

[1;34mMisc:[0m
  [1;36m--version[0m             show BBOT version and exit
  [1;36m--proxy[0m [1;33mHTTP_PROXY[0m    Use this proxy for all HTTP requests
  [1;32m-H[0m, [1;36m--custom-headers[0m [1;33mCUSTOM_HEADERS [CUSTOM_HEADERS ...][0m
                        List of custom headers as key value pairs (header=value).
  [1;32m-C[0m, [1;36m--custom-cookies[0m [1;33mCUSTOM_COOKIES [CUSTOM_COOKIES ...][0m
                        List of custom cookies as key value pairs (cookie=value).
  [1;36m--custom-yara-rules[0m, [1;36m-cy[0m [1;33mCUSTOM_YARA_RULES[0m
                        Add custom yara rules to excavate
  [1;36m--user-agent[0m, [1;36m-ua[0m [1;33mUSER_AGENT[0m
                        Set the user-agent for all HTTP requests

EXAMPLES

    Subdomains:
        bbot -t evilcorp.com -p subdomain-enum

    Subdomains (passive only):
        bbot -t evilcorp.com -p subdomain-enum -rf passive

    Subdomains + port scan + web screenshots:
        bbot -t evilcorp.com -p subdomain-enum -m portscan gowitness -n my_scan -o .

    Subdomains + basic web scan:
        bbot -t evilcorp.com -p subdomain-enum web-basic

    Web spider:
        bbot -t www.evilcorp.com -p spider -c web.spider_distance=2 web.spider_depth=2

    Everything everywhere all at once:
        bbot -t evilcorp.com -p kitchen-sink

    List modules:
        bbot -l

    List output modules:
        bbot -lo

    List presets:
        bbot -lp

    List flags:
        bbot -lf

    Show help for a specific module:
        bbot -mh <module_name>

```
<!-- END BBOT HELP OUTPUT -->
