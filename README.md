ssllabs-scan
============

This tool is a command-line client for the SSL Labs APIs, designed for
automated and/or bulk testing.

If you'd like to contribute, please have a look at the TODO file. For larger work,
please get in touch first. For smaller work (there are some TODO comments in the
source code), feel free to submit pull requests.

To report a problem related to this tool, please create a new issue on GitHub: https://github.com/ssllabs/ssllabs-scan/issues
Please don't send bug reports to the community.

To discuss the API and the development of the reference client implementation and other questions not related to this command line tool, please
join the SSL Labs community: https://community.qualys.com/community/ssllabs

Before you use this tool please review the terms and conditions, which can be found here:
https://www.ssllabs.com/about/terms.html

## Requirements

* Go >= 1.3

## Installation

### Prebuilt Binaries

A [precompiled version is available](https://github.com/ssllabs/ssllabs-scan/releases) with each release.

### Using Docker

1. Build the [Docker](https://docs.docker.com/) image:

```bash
sudo docker build -t ssllabs-scan https://github.com/ssllabs/ssllabs-scan.git
```

2. Run the Docker image:

```bash
sudo docker run ssllabs-scan example.com
```

### From Source

If you prefer to build your own binary from the latest release of the source code, make sure you have a correctly configured **Go >= 1.10** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install) Then, take the following steps:

1. Download ssllabs-scan:

```bash
go get -u github.com/ssllabs/ssllabs-scan/...
```

2. If you wish to rebuild the binaries from the source code:

```bash
cd $GOPATH/src/github.com/ssllabs/ssllabs-scan

go install ./...
```

## Usage 

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

## Third-Party Tools and Libraries

A list of libraries and tools that rely on the SSL Labs APIs can be found on the SSL Labs web site: https://www.ssllabs.com/projects/ssllabs-apis/

## Docker

Docker images for this project are available at:

* [https://github.com/jumanjihouse/docker-ssllabs-scan](https://github.com/jumanjihouse/docker-ssllabs-scan)
