# tldr

[![Running?](https://img.shields.io/uptimerobot/status/m789963227-8ecf98b56e5473d68e65fc94)](https://status.partridge.tech)
[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)
[![Forked From](https://img.shields.io/badge/forked%20from-TLDR-red.svg)](https://github.com/mandatoryprogrammer/TLDR)

A(nother) continuously updated historical TLD records archive.

This repository is updated approximately every three hours with the results from [DNS zone transfer attempts](https://en.wikipedia.org/wiki/DNS_zone_transfer) against the [root nameservers](https://en.wikipedia.org/wiki/Root_name_server) and all existing TLD servers. This is done to keep record of zone files for various TLDs and to monitor how these zones change overtime.

The current list of zones is available [here](https://github.com/tweedge/tldr/blob/main/ZONES.md). You can watch that file for changes in case another [.kp DNS leak](https://github.com/mandatoryprogrammer/NorthKoreaDNSLeak) occurs (or similar).

## Credits

This is a fork of [mandatoryprogrammer/TLDR](https://github.com/mandatoryprogrammer/TLDR), which is slightly modified to:

* Show the current state of all available records in the archives directly, by omitting records (or even TLDs) which don't currently permit AXFRs (or have network errors, etc.).
* Run on Python3 instead of Python2.

TLDR itself was initially inspired by [pzb/TLDs](https://github.com/pzb/TLDs).