#include "cname_tracker.h"
#include <map>
using namespace std;


static const string PATH_SEP = "||";

class CnameTrackerImpl : public CnameTracker
{
public:
  CnameTrackerImpl(bool isPathEnabled): _cnameMap(), _pathCache(), _isPathEnabled(isPathEnabled) { }

  virtual void                    addCname(std::string name, std::string cname)
  {
    if (name == cname) return;
    _cnameMap[cname] = name;
  }

  //-------------------------------------------------------------------------
  // Find the top-level domain name and build CNAME path for name.
  //
  // @param nameOrCname  Name to lookup
  //-------------------------------------------------------------------------
  virtual const name_path_tuple   getWithPath(std::string nameOrCname)
  {
    auto it = _pathCache.find(nameOrCname);

    if (it != _pathCache.end()) return it->second;

    string path;
    string topName = calc_path_r(nameOrCname, path);

    name_path_tuple t = {topName, path};
    _pathCache[nameOrCname] = t;
    return t;
  }

  //-------------------------------------------------------------------------
  // clear caches
  //-------------------------------------------------------------------------
  virtual void clear() { _cnameMap.clear(); _pathCache.clear(); }

private:

  //-------------------------------------------------------------------------
  // Prepends name to path.
  //-------------------------------------------------------------------------
  void _pathPush(std::string &path, std::string name)
  {
    if (false == _isPathEnabled) return;  // don't waste time building path

    if (path.length() > 0)
    path = name + PATH_SEP + path;
    else
    path = name;
  }


  //-------------------------------------------------------------------------
  // recursively find parent name
  //-------------------------------------------------------------------------
  std::string calc_path_r(std::string name, std::string &path)
  {
    auto it = _cnameMap.find(name);

    // second==name should never happen.  safeguard against infinite recursion

    if (it == _cnameMap.end() || it->second == name) {
      _pathPush(path, name);
      return name;
    }

    _pathPush(path, name);
    return calc_path_r(it->second, path);

  }

  map<string, string>          _cnameMap;
  map<string, name_path_tuple> _pathCache;
  bool                         _isPathEnabled;
};


//-------------------------------------------------------------------------
// CnameTrackerNew - factory
//-------------------------------------------------------------------------
CnameTracker* CnameTrackerNew(bool isPathEnabled)
{
  return new CnameTrackerImpl(isPathEnabled);
}
