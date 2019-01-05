# go-memkeys

## Overview

Memcached top-like cache key monitoring utility inspired by the mctop/memkeys projects.

## Installation

Follow the simple golang process steps of `get`, `build`, and run :)

```bash
> git clone https://github.com/darthhexx/go-memkeys

> cd go-memkeys

> go get

> go build
```

## Running

The required parameters are what you would expect.

```bash
Usage of go-memkeys:
  -i string
    	Interface to read packets from (default "en0")
  -p int
    	Port number (default 11211)
```

## Export data in JSON format

In order to export all the data recorded by the application; press 'd' (dump) during execution. A file will be saved as `{timestamp}-stats.json` in the applcation's directory, assuming the user has the required directory ACLs.
