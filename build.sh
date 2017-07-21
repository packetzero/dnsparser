#!/bin/sh
TOP=$PWD
PLATFORM=`uname -s`-`uname -m`			# e.g. Darwin-x86_64 , Linux-x86_64

mkdir -p platform/$PLATFORM
cd platform/$PLATFORM

# default to release build.  set CONFIG=Debug for debug build on osx
if [ "${CONFIG}" == "" ] ; then
  CONFIG="Release"
fi


GO=make
CMAKE=cmake
GENFILE="Unix Makefiles"

if [ `uname -s` == "Darwin" ] ; then
  GENFILE="Xcode"
  GO="xcodebuild -configuration ${CONFIG} "
  if [ -f /Applications/CMake.app/Contents/bin/cmake ] ; then
  	CMAKE=/Applications/CMake.app/Contents/bin/cmake
  fi
fi

$CMAKE -G "$GENFILE" -DCMAKE_BUILD_TYPE=${CONFIG} ../../ && $GO

