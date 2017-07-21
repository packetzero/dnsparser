#ifndef _NM_DNS_H_
#define _NM_DNS_H_

#include <string>

#ifdef WIN32
#include <Ws2tcpip.h>   // in_addr
#else // WIN32
#include <netinet/in.h> // in_addr
#endif // WIN32

class DnsParserListener
{
public:
  virtual void onDnsRec(in_addr addr, std::string name, std::string path) = 0;
  virtual void onDnsRec(in6_addr addr, std::string name, std::string path) = 0;
};

class DnsParser
{
public:
  virtual int parse(char *payload, int payloadLen)=0;
};

DnsParser* DnsParserNew(DnsParserListener *listener);

#endif // _NM_DNS_H_
