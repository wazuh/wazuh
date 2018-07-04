#! /bin/sh
set -x -e
# --no-recursive is available only in recent autoconf versions
autoreconf -fv --install
cp INSTALL.tmp INSTALL
