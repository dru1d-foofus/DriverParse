# DriverParse

Just a small python utility for parsing large amounts of drivers and saving them to a PSV file.

It checks for several interesting imports:
- KeStackAttachProcess
- MmMapIoSpace
- RtlCopyMemory
- ZwMapViewOfSection
- ZwOpenProcess
- ZwOpenSection
- ZwQuerySystemInformation
- ZwTerminateProcess

Next, the utility will check SHA256 hashes of the provided drivers and see if they're associated with any known blocklists. 

## Example

```bash
$ python parse.py -i drivers/ -o driver-results.csv -x lists/microsoft_driver_blocklist.xml -l lists/loldriver-hashes.txt
```
Example Output
```
File|Driver|Imports|MD5|SHA256|Blocked
LenovoDiagnosticsDriver.sys|True|MmMapIoSpace|b941c8364308990ee4cc6eadf7214e0f|f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe|True
dbutil_2_3.sys|True|MmMapIoSpace|c996d7971c49252c582171d9380360f2|0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5|True
ASUSSAIO.sys|True|MmMapIoSpace|fcf37eebee76a4c69a73c9610d169b49|f4b1ae5555cf77a2353c759a79edee928d74356cfc5c3ffa839f3ee68c2a19f3|False

```

## Sources and shout outs
- https://github.com/magicsword-io/LOLDrivers
- https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
- Shout out to @alfarom256