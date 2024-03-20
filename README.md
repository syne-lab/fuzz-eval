# FuzzEval

FuzzEval is a framework to evaluate the performance of different fuzzers on different test subjects for generating context sensitive test cases. This repository contains the docker files for the test subjects and the fuzzers that are used in the evaluation.

# Directory Structure
There are a few high level directories in the repository. The `Fuzzers` directory contains the docker files for the fuzzers. The `TestSubjects` directory contains the docker files for the test subjects. The `Platforms` directory contains the docker files for the platforms. The `FCConfig` directory contains the configuration files for the fuzzing campaign. The `ImageConf` directory contains the configuration files for the docker images for running each fuzzer-test subject fuzzing campaign. Aside from that, there are a few python scripts for running the fuzzing campaign, managing the docker images, and processing the logs.

```
├── campaigner.py
├── image-manager.py
├── README.md
├── run-first.sh
├── FCConfig
│   ├── AFL2.57
│   │   ├── afl2.57-axtls.toml
|   |   .
|   |   .
|   |   .
│   │   └── global.toml
│   ├── AFLPP
│   │   ├── aflpp-axtls.toml
|   |   .
|   |   .
|   |   .
│   │   └── global.toml
│   ├── AFLSMART
│   │   ├── aflsmart-axtls.toml
|   |   .
|   |   .
|   |   .
│   │   └── global.toml
│   ├── DARWIN
│   │   ├── darwin-axtls.toml
|   |   .
|   |   .
|   |   .
│   │   └── global.toml
│   ├── HONGGFUZZ
│   │   ├── global.toml
|   |   .
|   |   .
|   |   .
│   │   └── honggfuzz-wpasupplicant.toml
│   ├── LIBFUZZER
│   │   ├── global.toml
|   |   .
|   |   .
|   |   .
│   │   └── libfuzzer-wpasupplicant.toml
│   ├── MORPHEUS
│   │   ├── global.toml
|   |   .
|   |   .
|   |   .
│   │   └── morpheus-wpasupplicant.toml
│   ├── NAUTILUS
│   │   ├── global.toml
|   |   .
|   |   .
|   |   .
│   │   └── nautilus-wpasupplicant.toml
│   ├── PEACH
│   │   ├── global.toml
|   |   .
|   |   .
|   |   .
│   │   └── peach-wpasupplicant.toml
│   └── SGFUZZ
│       ├── global.toml
|       .
|       .
|       .
│       └── sgfuzz-wpasupplicant.toml
├── Fuzzers
│   ├── afl-2.57
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── afl++-4.07
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── aflsmart
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── buildall.sh
│   ├── darwin
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── honggfuzz
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── isla
│   │   ├── build.sh
│   │   ├── Dockerfile
│   │   ├── fuzz_goat.py
│   │   ├── pkcs.bnf
│   │   ├── pkcs-cons-2.isla
│   │   ├── pkcs-cons.isla
│   │   └── run_fuzz.sh
│   ├── libfuzzer
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── morpheus
│   │   ├── build.sh
│   │   ├── Dockerfile
│   │   └── fuzzer
│   │       ├── cb-tcg.py
│   │       ├── fvi-coq
│   │       └── hb-tcg.py
│   ├── nautilus
│   │   ├── build.sh
│   │   └── Dockerfile
│   ├── peach
│   │   ├── build.sh
│   │   └── Dockerfile
│   └── sgfuzz
│       ├── build.sh
│       └── Dockerfile
|
├── ImageConf
│   ├── afl-2.57.yaml
│   ├── afl++-4.07.yaml
│   ├── aflsmart.yaml
│   ├── darwin.yaml
│   ├── honggfuzz.yaml
│   ├── libfuzzer.yaml
│   ├── morpheus.yaml
│   ├── nautilus.yaml
│   ├── peach.yaml
│   ├── reference.info
│   │   ├── morpheus.yaml
│   │   ├── parallel-groups.txt
│   │   └── peach.yaml
│   └── sgfuzz.yaml
│   
├── Platforms
│   ├── buildall.sh
│   ├── Ubuntu-20.04
│   │   ├── build.sh
│   │   └── Dockerfile
│   │
├── TestSubjects
│   ├── AxTLS
│   │   ├── build-then-fuzz.sh
│   │   ├── config.ron
│   │   ├── default
│   │   │   ├── build-all.sh
│   │   │   ├── build-axtls.sh
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   ├── fcbuilder.sh
│   │   ├── fcrunner.sh
│   ├── Botan
│   │   ├── build-then-fuzz.sh
│   │   ├── config.ron
│   │   ├── default
│   │   │   ├── build-botan.sh
│   │   ├── Dockerfile
│   │   ├── fcbuilder.sh
│   │   ├── fcrunner.sh
│   .
│   .
│   .
│   .
│   └── WpaSupplicant
│       ├── build-then-fuzz.sh
│       ├── config.ron
│       ├── default
│       │   ├── build_wpa_supplicant.sh
│       ├── Dockerfile
│       ├── fcbuilder.sh
│       ├── fcrunner.sh

```

## Files For Running The Fuzzing Campaign
**campainer.py:** This script is used to run the fuzzing campaign. It takes the configuration file for the campaign and runs the campaign using the docker images for the fuzzers and the test subjects. **Note:** Run with --help to see the usage.

**image-manager.py:** This script is used to manage the docker images. It can list and clean fuzzeval related containers and images. **Note:** Run with --help to see the usage.

**run-first.sh:** This script is just creates a Results directory in the root of the repository. This directory is used to store the results of the fuzzing campaign.

## Directories
### FCConfig 
This directory contains the configuration files for the fuzzing campaign. The configuration files are used to run the fuzzing campaign using the campainer.py script. For each fuzzer, there is a separate directory containing the configuration files for all of the test subject to peform the fuzzing campaign for fuzzer-testsubject pair.

The configuration file contains the parameters for the fuzzing campaign, such as the duration of the campaign, the path to the test subject, the path to the seed files, path to the output directory, etc.
Most important line is the **fuzzer_command** line, which contains the command to run the fuzzer on the test subject. Moreover, each directory contains a global.toml file, which contains the global configuration for the fuzzing campaign that can be used to override the default configuration mentioned in the configuration file for each test subject.

### ImageConf
This directory contains the configuration files for the docker images for running each fuzzer-test subject fuzzing campaign. The configuration files are used to build the docker images for the fuzzers-testsubjects campaign.

For each of the fuzzer, there is a separate configuration file for it, and for each test subject there's a configuration block inside the configuration file. 

The configuration block contains the parameters for the docker image, the path to the test subject, the path to the seed files, path to the output directory, number of cpus, memory limit, etc. The campaigner.py script uses these configuration files to build the docker images for the fuzzing campaign.


### Fuzzers
This directory contains the docker files for the fuzzers. The docker files are used to build the docker images for the fuzzers. The build.sh script is used to build the docker image for the fuzzer. The Dockerfile contains the instructions to build the docker image for the fuzzer.

### Platforms
This directory contains the docker files for the platforms. The docker files are used to build the docker images for the platforms. The build.sh script is used to build the docker image for the platform. The Dockerfile contains the instructions to build the docker image for the platform.

### TestSubjects
This directory contains the docker files for the test subjects. The docker files are used to build the docker images for the fuzzing-campaign. Each test subject has a separate directory, and each directory has some common files such as fcbuilder.sh, fcrunner.sh, build-then-fuzz.sh, etc.
Most of these files are used inside the docker container to build the test subject, and run the fuzzing campaign on the test subject. Each test subject directory has a default directory, which contains the default configuration for the test subject which is used for most of the fuzzers. However, to fuzz with a few fuzzers, the test subject needs to be configured differently, and for that, there are separate directories for each fuzzer, which contains the configuration files for the test subject for that fuzzer. This can be extended to add more fuzzers if they require different configuration for the test subject.


## How to run the fuzzing campaigns

### Step 1: Set the required environment variables

`FUZZEVAL_TAG=tag-name`

This is the tag name for the docker images for the fuzzers and the test subjects. This is used to build the docker images for the fuzzers and the test subjects.


### Step 2: Build the platforms
```bash
cd Platforms
./buildall.sh
```

### Step 3: Build the fuzzers
```bash
cd Fuzzers
./buildall.sh
```

### Step 4: Run the fuzzing campaigns
```bash
# Run a single campaign
python3 campaigner.py -f <fuzzer> -t <test-subject> -r # -r is for building and running the campaign, otherwise it will only build the docker images

# Run all the campaigns for a fuzzer
python3 campaigner.py -f <fuzzer> -r # -r is for building and running the campaign, otherwise it will only build the docker images

```

