# Real telemetry acceptance

The dedicated `real-telemetry` backend CI job downloads the Zeek project's
`quickstart.pcap` from an immutable `zeek/zeek-docs` commit, runs it through
the official `zeek/zeek:lts` container, and sends the resulting real
`conn.log` records through ArgusProwl's Zeek parser and production event
pipeline.

Source capture: [Zeek quickstart.pcap](https://github.com/zeek/zeek-docs/blob/a30a11fb6da620d61a8722d57a7f4ae8a73566f8/traces/quickstart.pcap).

Zeek's [Quick Start Guide](https://github.com/zeek/zeek-docs/blob/a30a11fb6da620d61a8722d57a7f4ae8a73566f8/quickstart.rst)
documents that this capture contains two HTTP requests, including a
non-standard HTTP method that Zeek records as unusual behavior. The
acceptance test validates the two connection records, their parser-derived
network fields, evidence persistence, and the enabled `first_seen_src_dst`
production detection rule.

The PCAP is downloaded at test time and is not copied into this repository.
The regular pytest suite skips this test when
`ARGUSPROWL_REAL_ZEEK_CONN_LOG` is not set; the dedicated CI job sets that
variable after generating the logs. This is a reproducible benign baseline,
not a malicious-detection efficacy benchmark. Positive malicious cases,
false-positive measurement, and sustained replay remain separate release
requirements.
