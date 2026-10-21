# Opaque AIT archive acquisition before metadata access

The 522,084,364-byte `russellmitchell_no-pcaps.zip` is the smallest published
log-only testbed archive in record 19483937. The cached producer record states
CC BY-NC-SA 4.0; retain attribution and do not redistribute data in Git. Whole
archive MD5 must match `abb43a46c70939ad9f98669e3510d2b7` and a local SHA256 is
recorded before opening its directory or any selected textual member.

The initial bounded directory helper correctly refused the 2,222,342-byte
directory (14,898 entries). The server provides neither ETag nor Last-Modified,
so a whole opaque checksummed download gives stronger identity verification
than independent member ranges. No alteration to that frozen helper or product
archive/capture support is authorized or needed.

Use the exact public URL in `ait-directory-selection.json`, a 522,084,364-byte
streaming bound and an exclusive ignored `.partial` file. Preserve a failed
partial rather than overwrite it. No execution of downloaded contents. After
integrity passes, list directory metadata and open only these suffixes if present:
`dataset.yml`, `gather/attacker_0/logs/attacks.log`, and
`processing/config/servers.yml`. Bound each uncompressed metadata file to 1 MiB,
require unique exact selected paths and CRC verification by the standard library.
Never extract paths to disk. Cache original metadata under fixed local filenames.
All DNS/event/label rows, executable/configuration bodies outside this allowlist,
PCAPs and other testbeds remain unopened. Incidental query strings in execution
logs are development exposure, not reserved inputs. Selection/qualification is
not reserved assignment, scoring, a completed session count or a promotion.
