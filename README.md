# dnsparser - Simple DNS payload parser in C++
Intended for parsing DNS packet payload.  Builds as a static library. See [dnssniffer](https://github.com/packetzero/dnssniffer) for an example of using it in an application.

- Does not need entire payload
- Does not assume payload is DNS
- Supports IPV4 / IPV6 Answer records.
- Not thread-safe... restrict DnsParser.parse to single thread.
- Speedup upto 30% by not tracking paths.
- Speedup upto 400% by ignoring CNAMEs all together.

Example Usage:
```
DnsParser *parser = DnsParserNew(myListener, isPathEnabled, ignoreCnames);
parser->parse((char *)data.data(), data.size());
```

# Build
osx/linux:
```sh build.sh```
Windows:
```build.bat```

# Run Google unit tests
osx/linux:
```sh test.sh```

# Debug
On MacOS, use XCode to open .xcodeproj file placed in the platform/Darwin-x86_64/ dir after running build.sh.

On Windows, use Visual Studio to open the .sln file placed in platform/win32-msvc2012/ dir after running build.sh.

And, hey... there's always command-line lldb or gdb. 👍🏼
