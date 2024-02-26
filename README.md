# Eccsmith, a fork of Blacksmith

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Eccsmith can verify if ECC is working properly on your system, by attempting to inject bitflip errors into memory and then using [Rasdaemon](https://github.com/mchehab/rasdaemon) to detect whether or not they are successfully corrected by the ECC mechanism.

Eccsmith is a modified and repurposed version of [Blacksmith](https://github.com/comsec-group/blacksmith), the program accompanying the paper _[Blacksmith: Scalable Rowhammering in the Frequency Domain](https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf)_ (Jattke, van der Veen, Frigo, Gunter, and Razavi). Eccsmith itself is forked from [another fork of Blacksmith](https://github.com/UzL-ITS/blacksmith/tree/jsonconfig-upstream-staging) made by The University of Lübeck's Institute for IT Security, which makes the program easier to use across different hardware.

Eccsmith has been verified to work on Ubuntu 22.04.4 LTS.

**This project is stil being developed and adapted from Blacksmith! The rest of this readme is a work in progress!**

## Step 1 - Build

First, you must have installed the packages g++ (version 8 or above) and cmake (version 3.14 or above). Then simply run the build script, which will build Eccsmith with all of its dependencies:

```bash
bash build.sh
```

## Step 2 - Rasdaemon

Next, install Rasdaemon:

```bash
sudo apt install rasdaemon
```

And make it start monitoring:

```bash
rasdaemon
```

## Step 3 - Hugepages

You also need to enable 1 GB hugepages on your system. This can be done by editing the contents of the file `/etc/default/grub` so that the line:

```
GRUB_CMDLINE_LINUX=""
```

Instead reads:

```
GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=1"
```

Then you must run:

```bash
sudo update-grub
```

Finally, restart your system, and hugepages will be enabled. Now you can run Eccsmith.

## Running

Run the `eccsmith` executable located in the `build` directory. After finishing a run, you can find a `fuzz-summary.json` that contains the information from the log file in a machine-processable format. In case you passed the `--sweeping` flag, you can additionally find a `sweep-summary-*.json` file that contains the information of the sweeping pass.

### Supported Parameters

Eccsmith supports the command-line arguments listed in the following.
Except for the `--config` parameter all other parameters are optional.

```
    -h, --help
        shows this help message

==== Mandatory Parameters ==================================

    -c, --config
        path to JSON file containing the memory configuration to use. See below for sample configuration 
    
==== Execution Modes ==============================================

    -g, --generate-patterns
        generates N patterns, but does not perform hammering; used by ARM port
    -y, --replay-patterns <csv-list>
        replays patterns given as comma-separated list of pattern IDs

==== Replaying-Specific Configuration =============================

    -j, --load-json
        loads the specified JSON file generated in a previous fuzzer run, required for --replay-patterns
        
==== Fuzzing-Specific Configuration =============================

    -w, --sweeping
        sweep the best pattern over a contig. memory area after fuzzing (default: true)
    -l, --logfile
        log to specified file (default: run.log)
    -t, --runtime-limit
        number of seconds to run the fuzzer before sweeping/terminating (default: 3 hours)
    -p, --probes
        number of different DRAM locations to try each pattern on (default: NUM_BANKS/4)

```

The default values of the parameters can be found in the [`struct ProgramArguments`](include/Blacksmith.hpp#L8).

## JSON Configuration

### Overview

Eccsmith uses a JSON config file for configuration. To provide a path to the config file, use the `--config` flag. 
All keys in the config file are required for the `eccsmith` binary. For pre-made config files, please refer to the 
[config directory](config/).

### Keys

| Key            | Type                 | Description                                                                                                                                                            | Example                                           |
|----------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| name           | string               | A user-defined name identifying this config                                                                                                                            | "esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS"    |
| channels       | uint                 | Number of active channels in the system                                                                                                                                | 1                                                 |
| dimms          | uint                 | Number of active DIMMs in the system                                                                                                                                   | 1                                                 |
| ranks          | uint                 | Number of ranks on the DIMM                                                                                                                                            | 2                                                 |
| total_banks    | uint                 | Number of *total* banks in the system, i.e., #banks * #ranks                                                                                                           | 32                                                |
| max_rows       | uint                 | Maximum number of aggressor rows                                                                                                                                       | 30                                                |
| threshold      | uint                 | Threshold to distinguish between row buffer miss (t > `threshold`) and row buffer hit (t < `threshhold`).                                                              | 400                                               |
| hammer_rounds  | uint                 | Number of rounds to hammer                                                                                                                                             | 1000000                                           |
| drama_rounds   | uint                 | Number of rounds to measure cache hit/miss latency                                                                                                                     | 1000                                              |
| acts_per_trefi | uint                 | Number of measured activations per REFRESH interval (optional, set to zero to make Eccsmith determine acts-per-ref on the fly)                                       | 76                                                |
| row_bits       | [uint &#124; [uint]] | Row Bits of a given address. For multi-bit schemes, e.g. bank functions, you can pass a list of bits. Each entry in the list determines a row in the address matrix    | [29,28,27,26,25,24,23,22,21,20,19,18]             |
| col_bits       | [uint &#124; [uint]] | Column bits of a given address. For multi-bit schemes, e.g. bank functions, you can pass a list of bits. Each entry in the list determines a row in the address matrix | [12,11,10,9,8,7,6,5,4,3,2,1,0]                    |
| bank_bits      | [uint &#124; [uint]] | Bank bits of a given address. For multi-bit schemes, e.g. bank functions, you can pass a list of bits. Each entry in the list determines a row in the address matrix   | [[6, 13], [14, 18], [15, 19], [16, 20], [17, 21]] |

## Additional Tools

### determineConflictThreshold
The `determineConflictThreshold` tool helps experimentally determine the value for `threshold`. Pass a JSON config file 
using the `--config` parameter. Set `threshold` to 0 in the JSON config file. The tool repeatedly measures access timings
between same-bank same-row addresses (low latency) and same-bank differing-row addresses (high latency) and logs those
timings to a CSV file (`--output` argument). After analysis of conflict threshold data, e.g., by using 
`tools/visualize_access_timings.py`, update the `threshold` value in the config file.

### determineActsPerRef
The `determineActsPerRef` tool helps in determining the number of row activations between two TRR refresh instructions.
It repeatedly measures the timing between two random addresses which share the same bank with different rows and logs
those timings to a CSV file. After some number of row activations, a REFRESH command will be issued by the memory controller.
This REFRESH command results in a longer access time for the subsequent row activation and can be observed by analyzing
the resulting CSV file. Since two row activations happen per measurement, the expected activations per refresh interval 
can be approximated by the average of twice the number of measurements between timing peaks. The python script in 
`tools/visualize_acts_per_ref.py` can be used to determine the correct number of activations per REFRESH interval.
The number of activations is required for fuzzing using `eccsmith`. You can pass it using the `acts_per_trefi` key in 
the config file. If `acts_per_trefi` is set to zero, `eccsmith` periodically determines the activations per refresh 
cycle while fuzzing.

### checkAddrFunction
The `checkAddrFunction` tool can be used to verify the correctness of reverse-engineered memory mapping. It measures
the average access timing between all rows on all banks for a given JSON configuration passed with the --config parameter. 
If the configuration is correct, all accesses should take at least `threshold` cycles. If the tool measures less than 
`threshold` cycles between addresses accesses, an error is logged. All measurements are logged to the output file 
specified by `--output` for further analysis.

### tools/visualize_acts_per_ref.py
The `visualize_acts_per_ref tool` enables users to visualize data collected using `determineActsPerRef`. By analyzing 
the mean distance between timing peaks in the visualization, one can determine the activations per REFRESH interval. 
It's important to note that since two address accesses are performed for each measurement, one needs to **multiply the 
observed distance by two** to obtain the correct value for `acts_per_trefi`.

### tools/visualize_access_timings.py
This tool can be used to visualize the data collected with `determineConflictThreshold`. The visualization should 
show two piles, one around the average row buffer hit timing, the other around the average row buffer miss timing. The 
conflict `threshold` can be choosen somewhere between those two piles.

