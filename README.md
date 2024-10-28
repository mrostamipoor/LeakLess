# LeakLess: Selective Data Protection Against Memory Leakage Attacks for Serverless Platforms

## Introduction

Welcome to the official repository for "LeakLess: Selective Data Protection Against Memory Leakage Attacks for Serverless Platforms". LeakLess is designed to protect secret data against memory disclosure vulnerabilities and transient execution attacks on serverless computing platforms that use language-level sandboxing to run untrusted code. LeakLess relies on selective in-memory encryption of developer-annotated sensitive data and addresses the limitations of previous selective data protection techniques by combining in-memory encryption with a separate I/O module. This enables the safe transmission of protected data between serverless functions and external hosts. We implemented LeakLess on the Spin serverless platform and evaluated it with real-world serverless applications. This README provides all the necessary resources and instructions to help you deploy and utilize LeakLess effectively.

Read our detailed [research paper](https://mrostamipoor.github.io/files/leakless.pdf) to understand the methodology and the principles guiding the development of LeakLess.
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
