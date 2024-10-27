# LeaKLess' Examples

## Introduction

This repository contains a collection of examples as mentioned in our paper. Each example is designed to illustrate key concepts and implementations discussed in the paper. The examples are prefixed with "leakless" in their names, indicating their relevance to the specific topics covered.

## Getting Started

### Prerequisites

Before running the examples, ensure that you have installed LeakLess from the source code and added the path of this LeakLess to the environment variables.

### Running the Examples

To run any of the examples in this repository, follow these simple steps:

1. **Build the Example**:
This command compiles the example and prepares it for execution.

```
leakless build
```

2. **Start the Example**:
This command starts the example, making it ready for interaction or further operation.

```
leakless up
```
### Calling the Application

Each repository contains a `call_example.sh` script. This script is used to interact with the application. To call the application, simply run the script in the terminal:

```
./call_example.sh
```
### Python Webserver
Some of the examples may require a Python web server, which is located in the `webserver` folder. To run the webserver, use the `run_webserver.sh` script provided in the folder:
```
./webserver/run_webserver.sh
```
## download-from-s3 Example

This example, named `download-from-s3`, downloads a JPG file from an AWS S3 bucket. It showcases LeakLess's functionality in an operational environment and runs and executes similarly to the previous examples in this repository.



