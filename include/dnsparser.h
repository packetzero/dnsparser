// Interface definitions for DNS parser

#ifndef _NM_DNS_H_
#define _NM_DNS_H_

#include <string>

#ifdef WIN32
#include <Ws2tcpip.h>   // in_addr
#else // WIN32
#include <netinet/in.h> // in_addr
#endif // WIN32

/**
 * Implement this interface and pass to DnsParserNew() to
 * receive DNS response records.
 */
class DnsParserListener
{
public:
  /**
   * @param addr Binary IPV4 or IPV6 address in network order.
   * @param name Domain name requested.
   * @param path Domain name and chain of CNAME entries separated by "||"
   */
  virtual void onDnsRec(in_addr addr, std::string name, std::string path) = 0;
  virtual void onDnsRec(in6_addr addr, std::string name, std::string path) = 0;
};

class DnsParser
{
public:
  /**
   * parse
   * When response records are discovered, DnsParserListener.onDnsRec()
   * callback is called.
   * @param payload Pointer to first byte of (UDP) payload for DNS datagram.
   * @param payloadLen Length in bytes of payload.
   */
  virtual int parse(char *payload, int payloadLen)=0;
};

/**
 * Create a return a new instance of DnsParser and register listener.
 *
 * @param listener       For callbacks
 * @params isPathEnabled If false, the paths will always be empty in callbacks.
 *                       About a 30% speedup.
 * @params ignoreCnames  If true, paths will be empty, and no CNAMES parsed.
 *                       May lead to error if ANSWER records for different
 *                       domains are intermingled in same datagram.
 *                       About a 400% speedup.
 */
DnsParser* DnsParserNew(DnsParserListener *listener, bool isPathEnabled = true, bool ignoreCnames = false);

#endif // _NM_DNS_H_
