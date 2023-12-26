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

Deprecated clients are now available at [deprecated-clients](deprecated-clients)

## Requirements

* Go >= 1.3

## Usage 

SYNOPSIS

If you're using API v4 for the first time then please use the [ssllabs-scan-v4-register](ssllabs-scan-v4-register.go)

```
    ssllabs-scan-v4-register --firstName John --lastName Doe --organization Example --email johndoe@example.com
    ssllabs-scan-v4 [options] --email johndoe@example.com hostname
    ssllabs-scan-v4 [options] --email johndoe@example.com --hostfile file
```

OPTIONS
[ssllabs-scan-v4.go](ssllabs-scan-v4.go)

| Option            | Default value | Description                                                         |
|-------------------|---------------|---------------------------------------------------------------------|
| --api             | BUILTIN       | API entry point, for example https://www.example.com/api/           |
| --verbosity       | info          | Configure log verbosity: error, info, debug, or trace               |
| --quiet           | false         | Disable status messages (logging)                                   |
| --ignore-mismatch | false         | Proceed with assessments on certificate mismatch                    |
| --json-flat       | false         | Output results in flattened JSON format                             |
| --hostfile        | none          | File containing hosts to scan (one per line)                        |
| --usecache        | false         | If true, accept cached results (if available), else force live scan |
| --grade           | false         | Output only the hostname: grade                                     |
| --hostcheck       | false         | If true, host resolution failure will result in a fatal error       |
| --email           | ""            | Registered organization email for API v4 **(required)**             |

[ssllabs-scan-v4-register.go](ssllabs-scan-v4-register.go)

| Option           | Default value | Description                                                                |
|------------------|---------------|----------------------------------------------------------------------------|
| --firstName      | ""            | First name of the user                                                     |
| --lastName       | ""            | Last name of the user                                                      |
| --organization   | ""            | Organization of the user                                                   |
| --email          | ""            | Organization email of the user                                             |
| --registerApiUrl | BUILTIN       | Register API entry point, for example https://www.example.com/api/register |

## Third-Party Tools and Libraries

A list of libraries and tools that rely on the SSL Labs APIs can be found on the SSL Labs web site: https://www.ssllabs.com/projects/ssllabs-apis/

## Docker

Docker images for this project are available at:

* [https://github.com/jumanjihouse/docker-ssllabs-scan](https://github.com/jumanjihouse/docker-ssllabs-scan)
