# Resume the same opaque artifact

The sequential transfer was stopped because its observed transfer rate made a
whole-archive download needlessly slow. Preserve its incomplete `.zip.partial`
prefix as untrusted. Finish only the remaining bytes of the same fixed archive
in eight non-overlapping ranges, each in a separate exclusive ignored segment.
Enforce HTTP 206, exact original total/Content-Range, identity encoding and exact
response lengths. No more than eight concurrent streams. Reassemble only after
all bytes exist; compute the producer's whole-archive MD5 and local SHA256 over
prefix plus ordered segments before trusting or opening the archive. A mismatch
stops without metadata access. The old prefix and segment files remain untouched.
No data values, gates, test roles, format support or acquisition selection changes.
