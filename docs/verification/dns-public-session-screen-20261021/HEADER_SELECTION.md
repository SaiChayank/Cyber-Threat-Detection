# Bounded artifact selection, before capture bytes

21 October 2026, baseline `6aa53b4`. Documentary checks support limited metadata
acquisition for two subsets; neither receives a reserved evaluation role.

1. Active Countermeasures' dnscat2 one-hour capture only. The producer explicitly
   invites download and analysis, describes an executed lab with target/source
   and controlled DNS namespace, names the original standard PCAP and publishes
   SHA256 `b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd`.
   Download opaquely to ignored data intake with a 3 MiB bound, verify the complete
   SHA256 before opening a header, then read exactly the first 24 bytes and use
   existing `ingest.pcap_reader.validate_header`. Do not parse packet headers,
   timestamps, DNS queries, tool payloads or predictions. Keep producer context
   separate from independently joined session/time annotations, which remain
   unestablished. The one-hour and 24-hour exports are conservatively related;
   never count them as independent sessions. No 24-hour capture acquisition.
   Local analysis permission does not imply redistribution permission.

2. Burgos DOI `10.71486/dgza-t550`, exact published ZIP
   `Martinez-Raw_Network Traffic_Captures_for_IoT-Dataset_2025.zip`. Its producer
   README explicitly declares CC BY 4.0, executed `benign_first_cap.pcap` and
   `benign_second_cap.pcap` captures, telemetry/DNS intent and separate malicious
   run. HEAD reports 1,269,092,760 bytes. Reuse the existing tested bounded ZIP
   central-directory reader only: each range <=1 MiB, require HTTP 206 and exact
   Content-Range, preserve conditional identity with ETag or Last-Modified.
   Inspect archive names/sizes/CRC only. No full archive download, member
   decompression, packet/header/time/query inspection, format conversion or
   classifier. Stop on unsupported ranges or missing identity. Two declared
   benign runs cannot be inflated into >=50 DNS sessions; application-category
   joins and the README's microsecond/millisecond timing discrepancy stay open.

ZIZA CSVs/word lists and netrack LFS/capture/CSV members stay unopened. No source
or filename is a predictive feature. Preserve all 130 existing originals and
all gates; downloaded bytes/header metadata cannot enable a candidate. Output
partial qualification and specific missing requirements, not a formal metric.
