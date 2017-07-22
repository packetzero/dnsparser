# dnsparser - Simple DNS payload parser in C++
Intended for parsing DNS packet payload.
- Does not need entire payload
- Does not assume payload is DNS
- Supports IPV4 / IPV6 Answer records.
- Not thread-safe... restrict DnsParser.parse to single thread.

# Build
osx/linux:
```sh build.sh```
Windows:
```build.bat```

# Test
osx/linux:
```sh test.sh```
