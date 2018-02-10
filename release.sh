#!/bin/bash

set -v -e -o pipefail

DFLAGS="-release" DMD="$(command -v ldmd2)" ./build.sh
VERSION=$(git describe --abbrev=0 --tags)

unameOut="$(uname -s)"
case "$unameOut" in
    Linux*) OS=linux; ;;
    OSX*) OS=osx; ;;
    *) echo "Unknown OS: $unameOut"; exit 1
esac

archiveName="dub-$VERSION-$OS-x86_64.tar.gz"

echo "Building $archiveName"
tar cvfz "bin/$archiveName" -C bin dub

if [ "$OS" == "linux" ] ; then
    archiveName="dub-$VERSION-$OS-x86.tar.gz"
    echo "Building $archiveName"
    DFLAGS="-release -m32" DMD="$(command -v ldmd2)" ./build.sh
    tar cvfz "bin/$archiveName" -C bin dub
fi

# Set latest version, s.t. GH_PAGES get updated
mkdir -p docs
echo $VERSION > docs/LATEST
