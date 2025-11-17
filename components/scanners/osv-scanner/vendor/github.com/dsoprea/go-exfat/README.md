[![GoDoc](https://godoc.org/github.com/dsoprea/go-exfat?status.svg)](https://godoc.org/github.com/dsoprea/go-exfat)
[![Build Status](https://travis-ci.org/dsoprea/go-exfat.svg?branch=master)](https://travis-ci.org/dsoprea/go-exfat)
[![Coverage Status](https://coveralls.io/repos/github/dsoprea/go-exfat/badge.svg?branch=master)](https://coveralls.io/github/dsoprea/go-exfat?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/dsoprea/go-exfat)](https://goreportcard.com/report/github.com/dsoprea/go-exfat)

# Overview

This is a read-only exFAT implementation based on the Microsoft-published
specs ([exFAT file system specification](https://docs.microsoft.com/en-us/windows/win32/fileio/exfat-specification)).
The primary purpose of this project is to provide an unprivileged API to access
an exFAT filesystem from any platform. This project also provides several tools
that can be used to explore the filesystem and extract files from it.


# Command-Line Tools

- *exfat_list_contents*: List all files with or without complete directory-entry
  information.
- *exfat_extract_file*: Extract a single file to a file or STDOUT. May also be
  used to print all clusters and sectors visited for the extraction.
- *exfat_print_boot_sector_header*: Dump filesystem parameters. Largely sourced
  from the boot-sector header.


# Notes

- All entry-types are parsed as per the requirements of the specification.
  However:

  - Up-case tables, which support case insensitivity, are not read and therefore
    not applied. As a result, all file-operations are case-sensitive (and the
    villagers rejoiced).

  - Allocation bitmaps are not read, so it's not possible to know which clusters
    are or are not used. This is not required for browsing the filesystem or
    reading files.

- Timestamps are accurate to one second.
