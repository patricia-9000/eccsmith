#!/bin/bash

# build eccsmith
mkdir build
cd build
cmake ..
make -j$(nproc)
cd ..

# install and start rasdaemon
apt install rasdaemon
rasdaemon
