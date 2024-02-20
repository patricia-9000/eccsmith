#!/bin/bash

# build eccsmith
mkdir build
cd build
cmake ..
make -j$(nproc)

# install and start rasdaemon
git clone https://github.com/mchehab/rasdaemon.git
cd rasdaemon
./configure
make
make install
rasdaemon
cd ..
