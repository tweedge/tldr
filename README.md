# tldr

[![Forked From](https://img.shields.io/badge/forked%20from-TLDR-blue.svg)](https://github.com/mandatoryprogrammer/TLDR)
[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)
[![Operated By](https://img.shields.io/badge/operated%20by-some%20nerd-red.svg)](https://chris.partridge.tech)

*A(nother) continuously updated historical TLD records archive.*

This repository is updated approximately every three hours with the results from [DNS zone transfer attempts](https://en.wikipedia.org/wiki/DNS_zone_transfer) against the [root nameservers](https://en.wikipedia.org/wiki/Root_name_server) and all existing TLD servers. This is done to keep record of zone files for various TLDs and to monitor how these zones change over time.

The current list of zones is available [here](https://github.com/tweedge/tldr/blob/main/ZONES.md). You can watch that file for changes in case another [.kp DNS leak](https://github.com/mandatoryprogrammer/NorthKoreaDNSLeak) occurs (or similar).

## Zone Transfers for Roots and TLDs

Allowing global zone transfers is sometimes considered a security vulnerability due to this functionality giving attackers the ability to easily enumerate all DNS zone data for a specific domain. This is seen as an issue for system administrators who want to make enumerating sub-domains and other DNS data "hard" for malicious actors (read: forcing them to open [OWASP/amass](https://github.com/OWASP/Amass)).

However, when it comes to TLDs and the root nameservers, zone transfers are shown in a different light. Zone transfers at this level can be beneficial as they are an easy way for a TLD to be transparent about its DNS changes. This project is **not** meant to encourage TLD DNS hosting providers to disable global zone transfers but rather to gather data on the ever-changing zone information for the Internet's TLDs.

## Credits

This is a fork of [mandatoryprogrammer/TLDR](https://github.com/mandatoryprogrammer/TLDR), which has been only slightly modified to:

* Show the current state of all available records in the archives directly, by omitting records (or even TLDs) which don't currently permit AXFRs (or have network errors, etc.).
* Run on Python3 instead of Python2.

TLDR itself was initially inspired by [pzb/TLDs](https://github.com/pzb/TLDs).
