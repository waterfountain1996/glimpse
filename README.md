# glimpse

A simple SOCKS5 server written in Go. It only supports `CONNECT` commands and has password authentication.

## Installation

To install `glimpse` run:

```bash
go install github.com/waterfountain1996/glimpse@latest
```

## Usage

Note that username without a password is an **invalid** configuration, while a password without
a username is.

```bash
Usage of glimpse:
  -b string
        Address to listen on (default ":1080")
  -p string
        Proxy password
  -u string
        Proxy user
```
