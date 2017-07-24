#ifndef _CNAME_TRACKER_H_
#define _CNAME_TRACKER_H_

#include <string>

struct name_path_tuple {
  std::string name;       // top-level name. e.g. 'p.typekit.net'
  std::string path;       // e.g. 'p.typekit.net||p.typekit.net-v2.edgekey.net||e8385.dscg.akamaiedge.net'
};

class CnameTracker
{
public:
  virtual void                  addCname(std::string name, std::string cname) = 0;

  virtual const name_path_tuple getWithPath(std::string nameOrCname) = 0;

  virtual void                  clear() = 0;

  virtual ~CnameTracker() {};  // virtual destructor hint needed for most c++ compilers.
};

/**
 * Returns a new instance of CnameTracker implementation.
 * If isPathEnabled == false, getWithPath() will return values with empty path,
 * as a slight performance enhancement.
 */
CnameTracker* CnameTrackerNew(bool isPathEnabled);

#endif // _CNAME_TRACKER_H_
