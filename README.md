# SIEM Log Parser 📊

A Python-based log analysis and ingestion utility designed to simulate Security Information and Event Management (SIEM) data extraction. It rapidly processes unstructured server logs to identify and tally brute-force attack vectors.

**Features:**
* Implements Python's `re` (Regular Expressions) module to reliably extract IPv4 Indicators of Compromise (IoCs) from raw text.
* Utilizes line-by-line file reading to maintain a low memory footprint, ensuring the tool can process massive log files without exhausting system RAM.
* Features a built-in `collections.Counter` logic engine to aggregate attacker frequencies and flag high-risk IPs.
* Includes a multi-threaded Tkinter GUI and an automated dummy-log generator for immediate testing in non-Linux environments.

*Built as Day 26 of a 30-Day Network Engineering & Security portfolio streak.*
