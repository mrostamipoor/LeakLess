# LeakLess: Selective Data Protection Against Memory Leakage Attacks for Serverless Platforms

## Introduction

This is the repository for the paper ``LeakLess: Selective Data Protection Against Memory Leakage Attacks for Serverless Platforms`` This repository contains all the resources and instructions necessary to demonstrate how LeakLess can be utilized to protect secrets in serverless applications. The instructions provided here guide you through running LeakLess in a local environment.

## Build Instructions

### Requirements

This repository has been tested on Ubuntu 20.04.6 LTS and Ubuntu 22.04.3 LTS. Ensure that your system meets these requirements for optimal compatibility.

### Setup and Dependencies

To download all the dependencies required for this repository, execute the following command:

```
make setup
```
This command will install all necessary dependencies on your system.

### Building the Code
Once the dependencies are set up, you can build the code by running:
```
make build
```
This command compiles the source code and prepares the necessary executables.

### Starting the LeakLess Framework 
After building the code, you can start the LeakLess framework:
 ```
./target/release/leakless
```
The LeakLess binary will be located at ``./target/release/leakless``. This executable is the main entry point for running the leakless framework.
```
export PATH="$PATH:/path/to/leakless"
```


## Additional Information

For more detailed information on how to use LeakLess, refer to the examples provided within ``leakless-examples`` directory.

Also, JSON files related to the datasets, which are mentioned in Table 1, are placed within the ``leakless-dataset`` directory.
