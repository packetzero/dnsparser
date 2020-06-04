#include "../include/dnsparser.h"
#include "cname_tracker.h"
#include <stdint.h>
#include <string.h> // memcpy

#include <map>
using namespace std;

/*
* Implementation of DnsParser
*/
class DnsParserImpl : public DnsParser
{
public:

  // @implements
  virtual int parse(char *payload, int payloadLen);

  DnsParserImpl(DnsParserListener* listener, bool isPathEnabled, bool ignoreCnames) : _listener(listener), _ignoreCnames(ignoreCnames) {
    _cnameTracker = CnameTrackerNew(isPathEnabled);
  }

private:

  int    dnsReadAnswers(char *payload, int payloadLen, char *ptr, int remaining, int numAnswers);

  DnsParserListener* _listener;
  bool               _ignoreCnames;
  CnameTracker*      _cnameTracker;
};

//-------------------------------------------------------------------------
// DnsParserNew - return new instance of DnsParserImpl
//-------------------------------------------------------------------------
DnsParser* DnsParserNew(DnsParserListener* listener, bool isPathEnabled, bool ignoreCnames) {
  return new DnsParserImpl(listener, isPathEnabled, ignoreCnames);
}

// Reads a uint16_t and byte-swaps ntohs()
#define U16S(_PAYLOAD, _INDEX) \
((((uint8_t*)(_PAYLOAD))[_INDEX] << 8) + ((uint8_t*)(_PAYLOAD))[_INDEX+1])


struct dns_hdr_t
{
  uint16_t _txid;
  uint16_t _flags;
  uint16_t _numQueries;
  uint16_t _numAnswers;
  uint16_t _numAuth;
  uint16_t _numAddl;
};

#define DNS_FLAG_RESPONSE 0x8000
#define DNS_FLAG_OPCODE(FLGS) ((FLGS >> 11) & 0x0F)

//-------------------------------------------------------------------------
// skip_name - jump over name
// @returns -1 on error, otherwise length of name
//-------------------------------------------------------------------------
int skip_name(char *ptr, int remaining)
{
  char *p = ptr;
  char *end = p + remaining;
  while (p < end) {
    int dotLen = *p;
    if ((dotLen & 0xc0) == 0xc0) {
      printf("skip_name not linear!\n");
    }
    if (dotLen < 0 || dotLen >= remaining) return -1;
    if (dotLen == 0) return (int)(p - ptr + 1);
    p += dotLen + 1;
    remaining -= dotLen + 1;
  }
  return -1;
}

//-------------------------------------------------------------------------
// Read query records
// @returns -1 on error
// @returns Number of bytes taken up by query records
//-------------------------------------------------------------------------
int dnsReadQueries(char *payload, int payloadLen, char *ptr, int remaining, int numQueries)
{
  int rem = remaining;
  char *p = ptr;
  while(numQueries > 0)
  {
    int nameLen = skip_name(p, remaining);
    if (nameLen <= 0) return -1;
    remaining -= nameLen + 4;
    p += nameLen + 4;
    if (remaining < 0) return -1;
    numQueries --;
  }
  return (rem - remaining);
}

#define MAX_STR_LEN 128

//-------------------------------------------------------------------------
// Reads the domain name at nameOffset in payload
// retstr will contain domain name on exit.
// @returns Length in bytes of retstr on exit.
// @returns -1 on error.
//-------------------------------------------------------------------------
static int dnsReadName(string &retstr /* out */, uint16_t nameOffset, char *payload, int payloadLen)
{
  if (nameOffset == 0 || nameOffset >= payloadLen) return -1;

  char tmp[MAX_STR_LEN];
  char *dest = tmp;

  char *pstart = payload + nameOffset;
  char *p = pstart;
  char *end = payload + payloadLen;
  while (p < end) {
    uint16_t dotLen = *p;
    if ((dotLen & 0xc0) == 0xc0) {
      if (p > pstart)
      retstr = string(tmp,(int)(p - pstart -1));

      p++;
      string subStr;
      int subOff = (uint8_t)*p;
      dnsReadName(subStr, subOff, payload, payloadLen);
      retstr += '.' + subStr;
      return retstr.length();
    }
    if (dotLen < 0 || ((p + dotLen) >= end)) return -1;
    if (dotLen == 0) {
      if (p > pstart)
      retstr = string(tmp,(int)(p - pstart -1));
      return retstr.length();
    }

    // if we get here, dotLen > 0

    // sanity check on max length of temporary buffer
    if ((dest + dotLen + 1) >= (tmp + sizeof(tmp))) {
      return -1;
    }

    if (dest != tmp) { *dest++ = '.'; }
    p++;
    memcpy(dest, p, dotLen);
    p += dotLen;
    dest += dotLen;
  }

  return -1;
}

struct dns_ans_t
{
  uint16_t _nm;
  uint16_t _type;
  uint16_t _cls;
  uint16_t _ttl1;   // if using uint32, compiler will pad struct.
  uint16_t _ttl2;
  uint16_t _datalen;
};

#define DNS_ANS_TYPE_CNAME 5
#define DNS_ANS_TYPE_A     1  // ipv4 address
#define DNS_ANS_TYPE_AAAA 28  // ipv6
#define DNS_ANS_CLASS_IN 1

//-------------------------------------------------------------------------
// dnsReadAnswers
// Read response records (numAnswers expected) at ptr.
// _listener.onDnsRec() will be called for each record found.
//
// @param payload    Start of DNS payload.
// @param payloadLen Length in bytes of payload.
// @param ptr        Start of DNS Answer queries.
// @param remaining  Bytes remaining after ptr to end of payload.
// @param numAnswers The number of answer records expected.
//
// @returns -1 on error.
// @returns Length in bytes of response record block.
//-------------------------------------------------------------------------
int DnsParserImpl::dnsReadAnswers(char *payload, int payloadLen, char *ptr, int remaining, int numAnswers)
{
  _cnameTracker->clear();
  string firstName;

  int len = 0;
  while(numAnswers > 0)
  {
    dns_ans_t ans;

    if ((remaining - len) <= (int) sizeof(ans)) return -1;

    char *p = ptr + len;
    int ptrOffset = (int)(p - payload);

    ans._nm = U16S(p,0);

    string name;
    int nameLen = 0;
    int nameOffset = 0;
    int fieldsOffset = 0;

    if ((ans._nm & 0xc000) == 0xc000) {
      nameOffset = ans._nm & 0x3fff;
      nameLen = dnsReadName(name, nameOffset, payload, payloadLen);
      fieldsOffset=0;
    } else {
      nameOffset = ptrOffset;
      nameLen = dnsReadName(name, nameOffset, payload, payloadLen);
      fieldsOffset=nameLen;
    }

    if (nameLen<=0) return -1;

    ans._type = U16S(p,fieldsOffset+2);
    ans._cls = U16S(p,fieldsOffset+4);
    ans._datalen = U16S(p,fieldsOffset+10);


    // check datalen bounds

    if ((remaining - len - sizeof(ans) - fieldsOffset) < ans._datalen) {
      return -1;
    }

    if (firstName.length() == 0) firstName = name;

    // read data section

    switch (ans._type) {
      case DNS_ANS_TYPE_CNAME:
      {
        if (_ignoreCnames) break;
        string cname;
        dnsReadName(cname, ptrOffset + sizeof(ans), payload, payloadLen);
        if (cname.length() > 0 && cname != name)  // avoid infinite recursion
          _cnameTracker->addCname(name, cname);

        break;
      }
      case DNS_ANS_TYPE_A:
      {
        in_addr addr;
        addr.s_addr = *((uint32_t *)(p + sizeof(ans) + fieldsOffset));

        if (_ignoreCnames) {
          if (0L != _listener) _listener->onDnsRec(addr, firstName, "");
          break;
        }

        name_path_tuple npt = _cnameTracker->getWithPath(name);

        if (0L != _listener)
          _listener->onDnsRec(addr, npt.name, npt.path);

        break;
      }
      case DNS_ANS_TYPE_AAAA:
      {
        in6_addr addr;
        memcpy(&addr, p+sizeof(ans)+fieldsOffset, sizeof(addr));

        if (_ignoreCnames) {
          if (0L != _listener)
            _listener->onDnsRec(addr, firstName, "");
          break;
        }

        name_path_tuple npt = _cnameTracker->getWithPath(name);

        if (0L != _listener)
          _listener->onDnsRec(addr, npt.name, npt.path);
        break;
      }
      default:
      break;
    }

    len += sizeof(ans) + fieldsOffset + ans._datalen;

    numAnswers--;
  }
  return len;
}


//-------------------------------------------------------------------------
// parse()
// NOTE: Don't assume payload is DNS. Could be any protocol or garbage.
// NOTE: Don't assume entire payload is present - packet capture may
//       be truncated.
// @param payload    Pointer to first byte in payload.
// @param payloadLen Length in bytes of payload.
//-------------------------------------------------------------------------
int DnsParserImpl::parse(char *payload, int payloadLen)
{
  dns_hdr_t hdr;
  if (payloadLen < (int)sizeof(hdr)) return -1;

  hdr._txid = U16S(payload,0);
  hdr._flags = U16S(payload,2);
  hdr._numQueries = U16S(payload,4);
  hdr._numAnswers = U16S(payload,6);

  if (DNS_FLAG_OPCODE(hdr._flags) != 0) return -1; // not a standard query.

  if ((hdr._flags & DNS_FLAG_RESPONSE) == 0) return 0;

  {
    // response

    if (hdr._numAnswers <= 0) return 0; // only care about answers

    if (hdr._numQueries > 4 || hdr._numAnswers > 20) return -1; // unreasonable?

    int recordOffset = sizeof(hdr);
    if (hdr._numQueries > 0) {
      int size = dnsReadQueries(payload, payloadLen, payload + recordOffset, payloadLen - recordOffset, hdr._numQueries);
      if (size < 0) return -1; // error
      recordOffset += size;
      if ((payloadLen - recordOffset) < 0) return -1;
    }
    if (hdr._numAnswers > 0) {
      /* int size = */ dnsReadAnswers(payload, payloadLen, payload + recordOffset, payloadLen - recordOffset, hdr._numAnswers);
    }
    return 0;
  }
}
