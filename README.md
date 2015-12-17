ssllabs-scan
============

This tool is a command-line client for the SSL Labs APIs, designed for
automated and/or bulk testing.

If you'd like to contribute, please have a look at the TODO file. For larger work,
please get in touch first. For smaller work (there are some TODO comments in the
source code), feel free to submit pull requests.

To report a problem, please create a new issue on GitHub: https://github.com/ssllabs/ssllabs-scan/issues
Please don't send bug reports to the mailing list.

To discuss the API and the development of the reference client implementation, please
join the ssllabs-devel mailing list: https://sourceforge.net/p/ssllabs/mailman/ssllabs-devel/

Before you use this tool please review the terms and conditions, which can be found here:
https://www.ssllabs.com/about/terms.html

##Requirements

* Go >= 1.3

##Usage 

SYNOPSIS
```
    ssllabs-scan [options] hostname
    ssllabs-scan [options] --hostfile file
```

OPTIONS

| Option      | Default value | Description |
| ----------- | ------------- | ----------- |
| --api       | BUILTIN       | API entry point, for example https://www.example.com/api/ |
| --verbosity | info          | Configure log verbosity: error, info, debug, or trace |
| --quiet     | false         | Disable status messages (logging) |
| --ignore-mismatch | false   | Proceed with assessments on certificate mismatch |
| --json-flat | false         | Output results in flattened JSON format |
| --hostfile  | none          | File containing hosts to scan (one per line) |
| --usecache  | false         | If true, accept cached results (if available), else force live scan |
| --grade     | false         | Output only the hostname: grade |
| --hostcheck | false         | If true, host resolution failure will result in a fatal error |

##Using behind a web Proxy

Linux/Unix:
```
    export HTTP_PROXY=[http://]host[:port]
```
Windows:

```
    set HTTP_PROXY=[http://]host[:port]
```

The rules of Go's ProxyFromEnvironment apply (HTTP_PROXY, HTTPS_PROXY, NO_PROXY, lowercase variants allowed).

##Third-Party Tools and Libraries

A list of libraries and tools that rely on the SSL Labs APIs can be found on the SSL Labs web site: https://www.ssllabs.com/projects/ssllabs-apis/

##Docker

Docker images for this project are available at:

* [https://github.com/jumanjihouse/docker-ssllabs-scan]
  (https://github.com/jumanjihouse/docker-ssllabs-scan)
