# go-memkeys

## Overview

Memcached top-like cache key monitoring utility inspired by the mctop/memkeys projects.

## Installation

Follow the simple golang process steps of `get`, `build`, and run. The application also relies on the pcap library, so ensure that is installed on your OS before you perform the next steps.

```bash
> git clone https://github.com/darthhexx/go-memkeys

> cd go-memkeys

> go get

> go build
```

## Running

The required parameters are what you would expect.

```bash
Usage of ./go-memkeys:
  -i string
    	Interface to read packets from. (default "en0")
  -limitrows int
    	Limits the number of records output to JSON. This is only used in conjunction with 'polloutput'. (default 5000)
  -order string
    	Whether to sort in (desc)ending or (asc)ending order. (default "desc")
  -p int
    	Port number. (default 11211)
  -polloutput int
    	Capture data, write to JSON output, and exit after 'polloutput' seconds. (max is 120 seconds)
  -profile
    	Output cpu profile data to a 'cpu-profile' file.
  -sortby string
    	Column to sort the data on. (default "bandwidth")
```

## Export data in JSON format

In order to export all the data recorded by the application; press 'd' (dump) during execution. A file will be saved as `{timestamp}-stats.json` in the applcation's directory, assuming the user has the required directory ACLs.

To run the app in a no-gui mode that only outputs JSON, use the `polloutput number-of-secs` command:
> go-memkeys -i en0 -p 11211 -polloutput 5

This will capture data for 5 seconds and then output the JSON data to stdout.

Other useful flags are the `sortby`, `order`, and `limitrows` that allow you to set which colums to sort on ascending or descending and how many records to output after the sorting.
