# Eccsmith, a fork of Blacksmith

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Eccsmith can verify if ECC is working properly on your system, by attempting to inject bitflip errors into memory and then using [Rasdaemon](https://github.com/mchehab/rasdaemon) to detect whether or not they are successfully corrected by the ECC mechanism.

Eccsmith is a modified and repurposed version of [Blacksmith](https://github.com/comsec-group/blacksmith), the program accompanying the paper _[Blacksmith: Scalable Rowhammering in the Frequency Domain](https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf)_ (Jattke, van der Veen, Frigo, Gunter, and Razavi). Eccsmith itself is forked from [another fork of Blacksmith](https://github.com/UzL-ITS/blacksmith/tree/jsonconfig-upstream-staging) made by The University of Lübeck's Institute for IT Security, which makes the program easier to use across different hardware.

Eccsmith has been verified to work on Ubuntu 22.04.4 LTS.

## Step 1 - Build

First, you must have g++ (version 8 or above) and cmake (version 3.14 or above) installed. Then simply run the build script, which will build Eccsmith with all of its dependencies:

```bash
bash build.sh
```

## Step 2 - Rasdaemon

Install Rasdaemon:

```bash
sudo apt install rasdaemon
```

And make it start monitoring for ECC corrections:

```bash
rasdaemon
```

## Step 3 - Hugepages

You also need to enable 1 GB hugepages on your system. To do this, edit the contents of the file `/etc/default/grub` so that the line:

```
GRUB_CMDLINE_LINUX=""
```

Instead reads:

```
GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=1"
```

Then run:

```bash
sudo update-grub
```

Then restart your system, and hugepages will be enabled.

## Step 4 - Memory mapping

Eccsmith needs to know how your computer translates from logical memory addresses to physical memory addresses in order for the rowhammer exploit to work. This is determined by the following factors:

- The memory controller your computer uses
- The memory hardware in your computer, i.e.:
	- Number of active DRAM channels
	- Number of active DIMMs
	- Number of ranks on each DIMM (sides with banks on them, so either 1 or 2)
	- Total number of banks on each DIMM (across both ranks if applicable)

Once you know what these are for your computer, you need to pick the corresponding config file from the [config directory](config/). For example, the file named `coffee-lake-1-1-2-32.json` is for computers using the Intel Coffee Lake memory controller with 1 channel, 1 DIMM, 2 ranks, and 32 banks. Once you know which config file to use, you can move on to running Eccsmith.

### Config file details

The configs are JSON files with the following format:

| Key           | Type                 | Example                                           |
|---------------|----------------------|---------------------------------------------------|
| `name`        | string               | "coffee-lake-1-1-2-32"                            |
| `channels`    | uint                 | 1                                                 |
| `dimms`       | uint                 | 1                                                 |
| `ranks`       | uint                 | 2                                                 |
| `total_banks` | uint                 | 32                                                |
| `row_bits`    | [uint &#124; [uint]] | [29,28,27,26,25,24,23,22,21,20,19,18]             |
| `col_bits`    | [uint &#124; [uint]] | [12,11,10,9,8,7,6,5,4,3,2,1,0]                    |
| `bank_bits`   | [uint &#124; [uint]] | [[6, 13], [14, 18], [15, 19], [16, 20], [17, 21]] |

`row_bits`, `col_bits`, and `bank_bits` define the actual memory mapping function, which differs depending on the combination of memory controller and memory hardware being used. These three arrays represent how the bits in a logical address are used by the memory mapping function to determine which row, column, and bank make up the corresponding physical address.

The pairs in `bank_bits` mean those two bits are XORed in the memory mapping function. The same bit can appear in more than one of the three arrays, but all three must contain a total of 30 items between them, where a pair of bits within an array counts as one item. The number of items in `bank_bits` must be at least enough to distinguish between all the banks in your computer's DRAM, i.e. if there are 32 banks then there must be 5 items in `bank_bits`, because 32 can be represented by 5 bits. In seemingly all cases, `col_bits` is the bits from 12 to 0 descending, and `row_bits` is the bits from 29 descending until there are enough for all three arrays to sum to 30 items.

If the config directory doesn't contain a config file which is compatible with your computer, then you will have to create your own, and reverse-engineer your computer's memory mapping function yourself using [DRAMA](https://github.com/IAIK/drama).

## Running

Run the `eccsmith` executable located in the `build` directory. It must be run with the `-c` argument to determine which config file to use. For example:

```bash
sudo ./build/eccsmith -c config/coffee-lake-1-1-2-32.json
```

Eccsmith runs for a maximum of 3 hours by default. It may end earlier if it gathers enough information before then. Once the Rowhammer fuzzing stage of the run begins, it will print details of any ECC corrections or uncorrected bit flips it encounters to the terminal. When the run ends, a verdict on ECC's functionality will be displayed. In-depth details of each run are logged to `run.log` by default.

The following is a list of all suppported arguments:

```
    -h, --help
        shows this help message

==== Mandatory Parameters ==================================

    -c, --config
        path to JSON file containing the memory configuration to use. See below for sample configuration 
        
==== Optional Parameters ===================================

    -t, --runtime-limit
        number of hours to run the fuzzer before sweeping/terminating (default: 3)
    -l, --logfile
        log to specified file (default: run.log)
    -p, --probes
        number of different DRAM locations to try each pattern on (default: 3)

```

