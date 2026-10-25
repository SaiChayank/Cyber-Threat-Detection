# Fixed diagnostic parsing/join choices

Original syntax sample: RFC3164 month/day/second, `dnsmasq[pid]: query[TYPE]
NAME from ADDRESS`; forwarded/reply lines are not additional client questions.
Use source year 2022 and documented inet-firewall UTC. Keep actual seconds; do
not manufacture subsecond times, sort input, deduplicate questions or shift clocks.
Record malformed queries, other records, observed types/sources, chronology and
outside-simulation questions. Full textual names require nonempty labels <=63
bytes and total DNS wire-name length <=255; root is allowed. No restriction to
hostname letters/digits, encoded-payload decoding or external lookup.

End markers have exactly the original receiver's documented `3x7-.0-.` prefix,
literal transfer filename and `.email-19.kennedy-mendoza.info` suffix. Match DNS
case-insensitively, allowing the equivalent terminal root dot. Require QTYPE A
and the candidate originating host 10.143.0.103 for a source-consistent match.
Do not match by entropy, label length, predicted class, arbitrary substrings or
nearest timestamp. An event matches only the same original UTC integer-second
bucket as its receiver event. Record other-source, wrong-type, wrong-time,
ambiguous and out-of-observation events separately; no post-hoc tolerance tuning.
The configured service/host and exact successful marker join support a controlled
lab transfer association, not an independently observed process start for every
question or complete per-session intent truth. Multiple DNS attempts remain
multiple observations and an ambiguous join never becomes an exact match.

Treat the entire source run and all its related exports as exposed development
qualification; none is reserved. The 31 saved files cannot become 31 independent
experiments. User state records summarize original normal application actions;
state/transition counts do not certify independent benign DNS sessions. Do not
label all other DNS questions benign or run candidate/rule/model inference.
