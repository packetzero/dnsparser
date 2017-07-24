#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <map>
using namespace std;

#include "../include/dnsparser.h"

#ifdef WIN32
#include <Ws2tcpip.h>
#else // WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif // WIN32


int parse_addr6(std::string addr6, in6_addr &val) {
  return inet_pton(AF_INET6, addr6.c_str(), (void *) &val);
}

int parse_addr4(std::string addr4, in_addr &val) {
  return inet_pton(AF_INET, addr4.c_str(), (void *) &val);
}

class ParseDnsTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  // virtual void TearDown() {}
};

// all payloads taken from test/pcaps/dns.pcap.
// payload taken by right-clicking on DNS section in wireshark and choosing copy..as HEX stream.

static const string strDnsPayload1="9cfb81800001000300000000017007747970656b6974036e65740000010001c00c000500010000005f001b017007747970656b6974066e65742d763207656467656b6579c016c02b0005000100000180001805653833383504647363670a616b616d616965646765c016c05200010001000000140004174cc31a";

// AAAA response
//  p.typekit.net CNAME p.typekit.net-v2.edgekey.net
//  CNAME -> e8385.dscg.akamaiedge.net
//  e8385.dscg.akamaiedge.net: type AAAA, class IN, addr 2600:1404:27:2a2::20c1
//  e8385.dscg.akamaiedge.net: type AAAA, class IN, addr 2600:1404:27:299::20c1
static const string
strDnsPayloadv6="01d181800001000400000000017007747970656b6974036e657400001c0001c00c000500010000005f001b017007747970656b6974066e65742d763207656467656b6579c016c02b0005000100000180001805653833383504647363670a616b616d616965646765c016c052001c000100000014001026001404002702a200000000000020c1c052001c0001000000140010260014040027029900000000000020c1";

// from a 341 byte packet. 12 ipv4 addrs, 2 cnames
static const string
strDnsPayload14answers="8da281800001000e00000000026c620367656f096f666669636533363503636f6d0000010001c00c0005000100000097001a076f75746c6f6f6b096f666669636533363503636f6d0167c013c032000500010000010d0013106f75746c6f6f6b2d6e616d736f757468c013c05800010001000000de000428619652c05800010001000000de000428611e82c05800010001000000de0004286131b2c05800010001000000de000428619432c05800010001000000de000428618d72c05800010001000000de000428619662c05800010001000000de00042861aa1ac05800010001000000de0004286180d2c05800010001000000de000428618402c05800010001000000de0004286177d2c05800010001000000de0004286191b2c05800010001000000de0004286191ba";

static const string
strDnsPayloadProb="ABF8818000010004000000000377777709746F6D73697470726F03636F6D0000010001C00C000500010000007A0002C010C010000100010000003C000434214FC0C010000100010000003C000422D10D32C010000100010000003C000423A5F1EF491BDA1E720359CEB10C0062000000620000001200D4AE52A13E839801A7B1";

// A github.com 192.30.253.112
// A github.com 192.30.253.113
static const string
strDnsAnsNoCnames="9663818000010002000000000667697468756203636f6d0000010001c00c00010001000000050004c01efd70c00c00010001000000050004c01efd71";

static void hexstring_to_bin(string s, vector<uint8_t> &dest)
{
  auto p = s.data();
  auto end = p + s.length();

  while (p < end) {
    const char hexbytestr[]={*p, *(p+1), 0};
    uint8_t val = strtol(hexbytestr, NULL, 16);
    dest.push_back(val);
    p += 2;
  }
}

static std::string addr2text ( const in_addr& Addr )
{
  std::string strPropText="errIPv4";
  char IPv4AddressAsString[INET_ADDRSTRLEN];      //buffer needs 16 characters min
  if ( NULL != inet_ntop ( AF_INET, &Addr, IPv4AddressAsString, sizeof(IPv4AddressAsString) ) )
  strPropText = IPv4AddressAsString;
  return strPropText;
}

static std::string addr2text ( const in6_addr& Addr )
{
 std::string strPropText="errIPV6";
 char IPv6AddressAsString[INET6_ADDRSTRLEN];    //buffer needs 46 characters min
 if ( NULL != inet_ntop ( AF_INET6, &Addr, IPv6AddressAsString, sizeof(IPv6AddressAsString) ) )
   strPropText = IPv6AddressAsString;
 return strPropText;
}

// emulate what application would provide, so we can test parser
// holds ipv4 or v6 parser entry
struct MyDnsEntry
{
  bool     _isV6;
  in_addr  _addr4;
  in6_addr _addr6;
  string   _name;
  string   _path;

  MyDnsEntry(in_addr addr, std::string name, std::string path): _isV6(false), _addr4(addr), _name(name), _path(path) {}
  MyDnsEntry(in6_addr addr, std::string name, std::string path): _isV6(true), _addr6(addr), _name(name), _path(path) {}
};
// receives onDnsRec callbacks from parser, stores then in local maps
class MyDnsParserListener : public DnsParserListener
{
public:
  MyDnsParserListener():_map4(), _map6() {}

  virtual void onDnsRec(in_addr addr, std::string name, std::string path) {
    _map4[addr.s_addr] = new MyDnsEntry(addr, name, path);
  }
  virtual void onDnsRec(in6_addr addr, std::string name, std::string path) {
    vector<uint8_t> bytes(16);
    memcpy(bytes.data(), &addr, 16);

    _map6[bytes] = new MyDnsEntry(addr, name, path);
  }

  MyDnsEntry* lookup(in_addr addr) {
    auto it = _map4.find(addr.s_addr);
    if (it == _map4.end()) return 0L;
    return it->second;
  }

  MyDnsEntry* lookup(in6_addr addr) {
    vector<uint8_t> bytes(16);
    memcpy(bytes.data(), &addr, 16);

    auto it = _map6.find(bytes);
    if (it == _map6.end()) return 0L;
    return it->second;
  }

  std::map<uint32_t,MyDnsEntry*> _map4;
  std::map<vector<uint8_t>,MyDnsEntry*> _map6;
};

class ConcatListener : public DnsParserListener
{
public:

  virtual void onDnsRec(in_addr addr, std::string name, std::string path) {
    str += name;
    str += "=";
    str += addr2text(addr);
    str += ",";
  }
  virtual void onDnsRec(in6_addr addr, std::string name, std::string path) {
    str += name;
    str += "=";
    str += addr2text(addr);
    str += ",";
  }

  std::string str;
};


// tests start here

TEST_F(ParseDnsTest, single)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayload1, data);
  MyDnsParserListener *rmap = new MyDnsParserListener();
  DnsParser *parser = DnsParserNew(rmap);
  parser->parse((char *)data.data(), data.size());

  in_addr addr;
  parse_addr4("23.76.195.26", addr);

  const MyDnsEntry* entry = rmap->lookup(addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("p.typekit.net", entry->_name);
}

TEST_F(ParseDnsTest, singleIgnoreCnames)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayload14answers, data);
  MyDnsParserListener *rmap = new MyDnsParserListener();

  DnsParser *parser = DnsParserNew(rmap, false, true);  // don't track cnames

  parser->parse((char *)data.data(), data.size());

  in_addr addr;
  addr.s_addr = 0xb2916128;

  const MyDnsEntry* entry = rmap->lookup(addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("lb.geo.office365.com", entry->_name);
}

TEST_F(ParseDnsTest, singleIgnoreCnames2)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsAnsNoCnames, data);
  MyDnsParserListener *rmap = new MyDnsParserListener();

  DnsParser *parser = DnsParserNew(rmap, false, true);  // don't track cnames

  parser->parse((char *)data.data(), data.size());

  in_addr addr;
  parse_addr4("192.30.253.112", addr);

  const MyDnsEntry* entry = rmap->lookup(addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("github.com", entry->_name);
  ASSERT_EQ(0,entry->_path.length());

  parse_addr4("192.30.253.113", addr);

  entry = rmap->lookup(addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("github.com", entry->_name);

}

// Compare results with and without ignoreCnames==true
TEST_F(ParseDnsTest, ignoreCnamesCompare)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayload14answers, data);

  ConcatListener *listener = new ConcatListener();
  DnsParser *parser = DnsParserNew(listener);
  parser->parse((char *)data.data(), data.size());
  string expected = listener->str;

  listener->str.clear();
  parser = DnsParserNew(listener, false, true);  // don't track cnames
  parser->parse((char *)data.data(), data.size());

  ASSERT_EQ(expected, listener->str);
}

TEST_F(ParseDnsTest, removeOldEntries)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayload1, data);
  MyDnsParserListener *rmap = new MyDnsParserListener();
  DnsParser *parser = DnsParserNew(rmap);
  parser->parse((char *)data.data(), data.size());

  ASSERT_EQ(rmap->_map4.size(), 1);

}

// This packet lead to a parse error that had to be fixed.
TEST_F(ParseDnsTest, problem1)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayloadProb, data);
  MyDnsParserListener *rmap = new MyDnsParserListener();
  DnsParser *parser = DnsParserNew(rmap);
  parser->parse((char *)data.data(), data.size());

  in_addr addr;
  parse_addr4("35.165.241.239", addr);

  MyDnsEntry* entry = rmap->lookup(addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("tomsitpro.com", entry->_name);
}

// make sure we handle incomplete packets.  This is not an all-encompassing test
TEST_F(ParseDnsTest, incompletePacket)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayload14answers.substr(0,strDnsPayload14answers.length()-60), data);
  MyDnsParserListener *rmap = new MyDnsParserListener();
  DnsParser *parser = DnsParserNew(rmap);
  parser->parse((char *)data.data(), data.size());

  in_addr addr;
  parse_addr4("40.97.30.130", addr);

  MyDnsEntry* entry = rmap->lookup(addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("lb.geo.office365.com", entry->_name);
}

TEST_F(ParseDnsTest, singlev6)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayloadv6, data);
  MyDnsParserListener *rmap = new MyDnsParserListener();
  DnsParser *parser = DnsParserNew(rmap);

  parser->parse((char *)data.data(), data.size());

  in6_addr addr6;
  parse_addr6("2600:1404:27:2a2::20c1", addr6);
  MyDnsEntry* entry = rmap->lookup(addr6);

  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("p.typekit.net", entry->_name);

  parse_addr6("2600:1404:27:299::20c1", addr6);
  entry = rmap->lookup(addr6);

  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ("p.typekit.net", entry->_name);

  parse_addr6("0000:1404:00:2a2::00", addr6);
  entry = rmap->lookup(addr6);

  ASSERT_TRUE(entry == 0L);
}

#include "../src/cname_tracker.h"

TEST_F(ParseDnsTest, cnameTracker)
{
  CnameTracker* ct = CnameTrackerNew(true);
  ct->addCname("a", "b");
  ct->addCname("b", "c");

  name_path_tuple npt = ct->getWithPath("c");

  ASSERT_EQ("a", npt.name);
  ASSERT_EQ("a||b||c", npt.path);

  npt = ct->getWithPath("b");

  ASSERT_EQ("a", npt.name);
  ASSERT_EQ("a||b", npt.path);

  npt = ct->getWithPath("blah");

  ASSERT_EQ("blah", npt.name);
  ASSERT_EQ("blah", npt.path);

  ct->clear();

  npt = ct->getWithPath("c");

  ASSERT_EQ("c", npt.name);
  ASSERT_EQ("c", npt.path);

  delete ct;
}

TEST_F(ParseDnsTest, cnameTrackerNoPath)
{
  CnameTracker* ct = CnameTrackerNew(false);
  ct->addCname("a", "b");
  ct->addCname("b", "c");

  name_path_tuple npt = ct->getWithPath("c");

  ASSERT_EQ("a", npt.name);
  ASSERT_EQ("", npt.path);

  npt = ct->getWithPath("b");

  ASSERT_EQ("a", npt.name);
  ASSERT_EQ("", npt.path);

  npt = ct->getWithPath("blah");

  ASSERT_EQ("blah", npt.name);
  ASSERT_EQ("", npt.path);

  ct->clear();

  npt = ct->getWithPath("c");

  ASSERT_EQ("c", npt.name);
  ASSERT_EQ("", npt.path);

  delete ct;
}

static const int loopCount = 1000000;

// Timing tests based on my Macbook pro
// isPathEnabled TRUE  : 11.5 seconds
// isPathEnabled FALSE :  8.5 seconds
// ignoreCnames TRUE:     2.7 seconds
/*
TEST_F(ParseDnsTest, bench)
{
  vector<uint8_t> data;
  hexstring_to_bin(strDnsPayload14answers.substr(0,strDnsPayload14answers.length()), data);
  MyDnsParserListener *rmap = 0L;//new MyDnsParserListener();
  DnsParser *parser = DnsParserNew(rmap, false, true);

  for (int i=0;i<loopCount;i++) {
    parser->parse((char *)data.data(), data.size());
  }

  // rely on google test timing printout
}
*/

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  return status;
}
