# PKRU-Safe

PKRU-Safe is a new system that uses an MPK aware allocator and set of compiler extensions to protect 
data exclusively used by Rust code from abuse by memory unsafe legacy components.

This is the main repository for the PKRU-Safe project. It contains PKRU-Safe instrumentation, 
a modified Rust compiler, a modified LLVM compiler, test programs, automation scripts, and 
documentation.

PKRU-Safe is distributed under the MIT license, see [LICENSE-MIT](https://github.com/securesystemslab/PKRU-Safe/blob/main/LICENSE-MIT) for details.

## Documentation Quick Links

* [Repository Overview](#repository-overview)
* [Hardware Requirements](#hardware-requirements)
* [Experimental Environment](#experimental-environment)
* [Setup](#setup)
  * [Docker Setup](#docker-setup)
  * [Local Setup](#local-setup)
* [User Guide](#user-guide)
* [Tests](#pkru-tests)
* [Citation](#citation)

## Repository Overview

This project repository is a single point landing page for the collection of works related to the paper [PKRU-Safe: Automatically Locking Down the Heap Between Safe and Unsafe Languages][paper-link] referenced above. The contents of the repository are organized as such:

### Instrumentation

* [mpk-libc](https://github.com/securesystemslab/pkru-safe-mpk-libc) - Rust Intel MPK bindings and helper function library
* [mpk-protector](https://github.com/securesystemslab/pkru-safe-mpk-protector) - Provides a compiler plugin to automatically provide wrapper functions for annotated crate
* [pkalloc](https://github.com/securesystemslab/pkru-safe-pkalloc) - Provides rust bindings to PKRU-Safe version of jemalloc
  * [allocator](https://github.com/securesystemslab/pkru-safe-allocator-helper) - PKRU-Safe allocator helper for pkalloc
  * [jemalloc](https://github.com/securesystemslab/pkru-safe-jemalloc) - PKRU-Safe jemalloc
* [pkmallocator](https://github.com/securesystemslab/pkru-safe-pkmallocator) - Provides a rust interface to a global allocator for PKRU-Safe

### Compiler Extensions

* [cargo](https://github.com/securesystemslab/pkru-safe-cargo) - PKRU-Safe extended Cargo project
* [llvm-project](https://github.com/securesystemslab/llvm-project/tree/pkru-safe) - PKRU-Safe passes and runtime extended LLVM compiler
* [rust](https://github.com/securesystemslab/rust/tree/pkru-safe) - PKRU-Safe extended Rust compiler

### Tests

* [micro-benchmarks](https://github.com/securesystemslab/pkru-safe-bench) - Micro-benchmarks for showing call-gate overhead
* [pkru-safe-example](https://github.com/securesystemslab/pkru-safe-example) - Minimum working example of PKRU-Safe
* Servo
  * Benchmarks
    * [JetStream2](https://github.com/securesystemslab/pkru-safe-JetStream2) - Offline JetStream2 benchmark
    * [Kraken](https://github.com/securesystemslab/pkru-safe-kraken) - Offline Kraken benchmark
    * [Octane2](https://github.com/securesystemslab/pkru-safe-octane2) - Offline Octane2 benchmark
    * [pkru-safe-cve-html](https://github.com/securesystemslab/pkru-safe-cve-html) - Offline Servo Spidermonkey CVE exploit
  * PKRU-Safe Servo
    * [mozjs](https://github.com/securesystemslab/pkru-safe-mozjs) - Rust bindings for SpiderMonkey for use with Servo
    * [rust-mozjs](https://github.com/securesystemslab/pkru-safe-rust-mozjs) - Rust bindings to SpiderMonkey
    * [servo](https://github.com/securesystemslab/pkru-safe-servo) - Web browser engine written in Rust

### Automation

* [Dockerfile][docker-file]
* [setup](https://github.com/securesystemslab/pkru-safe-automation.git)

## Hardware Requirements

This project depends on a Memory Protection Key (MPK) hardware and thus requires a processor 
that supports MPK. To check that your system supports MPK, run the following command:

```sh
cat /proc/cpuinfo | grep pku

# flags       : ... pku ...
```

## Experimental Environment

### Author's System

* Dell Precision 7820 Workstation
  * Ubuntu 18.04.4 LTS Kernel 4.15.0
  * Intel Xeon Silver 4110 (2.10 GHz)
  * 48 GB of DDR4 EEC Memory

### Author Docker Container

All experiments were run in a docker container based on Debian Buster on the Author's system ([DockerImage][docker-image]). If instead you wish to build the docker image yourself, follow along in the instructions under [Docker Setup](#docker-setup). An overview of the author's ([DockerImage][docker-image]) is shown below:

* /root
  * llvm-project - Extended LLVM compiler
  * mpk-test-dir
    * artifacts - Artifact folder containing pre-built Servo artifacts and pkrusafe micro-benchmarks
    * automation - Folder containing handy automation scripts for building and running tests
    * pkru-safe-bench - PKRU-Safe micro-benchmarks
    * pkru-safe-cve-html - Simple html page for Spidermonkey CVE-2019-11707
    * pkru-safe-example - Minimum working example for PKRU-Safe
    * servo-vanilla - Servo 1 commit before author extension
    * servo-step - PKRU-Safe enabled Servo
    * servo-step-no-mpk - PKRU-Safe with mpk-call-gates turned off for overhead comparison
  * rust - Extended Rust compiler

## Setup

It is highly recommended that if you wish to try out the full system that you either use the pre-built
[image][docker-image], or build a clean image yourself from the provided [Dockerfile][docker-file].
PKRU-Safe currently requires an extended version of the Rust compiler and if you additionally want to 
build and run the Servo tests and examples it requires several additional dependencies. If you wish to 
build and test PKRU-Safe on your own system, skip ahead to [Local Setup](#local-setup).


### Docker Setup

If you have downloaded the [pre-built image][docker-image], then skip ahead to the docker run commands.

To build the docker image, you can either download the [Dockerfile][docker-file], or clone the [automation folder](https://github.com/securesystemslab/pkru-safe-automation.git).

1. Clone Automation Repository:
```sh
git clone https://github.com/securesystemslab/pkru-safe-automation.git automation
cd automation
```

2. Build Image:
```sh
docker build -t mpk/dev <folder/containing/Dockerfile>
```

3. Run Docker Image:
```sh
# This project requires access to MPK hardware, so when running the docker image '--security-opt seccomp=unconfined' is required
docker run -it --security-opt seccomp=unconfined --name <container-name> mpk/dev
```

### Local Setup

1. Clone automation repository:
```sh
git clone https://github.com/securesystemslab/pkru-safe-automation.git automation
cd automation
```

2. Download build requirements:
```sh
# Contains requirements for build PKRU-Safe version of LLVM and Rust
./requirements.sh

# Contains additional requirements for building and testing Servo
./servo-requirements.sh
```

3. Download Rust:
Downloading Rust is required to get rustup for setting up our own Rust toolchain. You can either install 
a nightly toolchain or none.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y
source $HOME/.cargo/bin
```

4. Clone and install:

These instructions assume you are working in your `$HOME` directory. You can change
the default folder being used by altering the $INSTALL_DIR variable in  the
[sources.sh](https://github.com/securesystemslab/pkru-safe-automation/blob/main/sources.sh) 
file. Additionally, change the `$SOURCES` variable to the location of the 
[automation](https://github.com/securesystemslab/pkru-safe-automation.git) folder you cloned in [Step 1](#local-setup).

```sh
cd $HOME

# Clone and build LLVM first. A version of Clang from this build is required to build Rust.
git clone https://github.com/securesystemslab/llvm-project.git -b pkru-safe
cd <path/to/automation>
./build_clang.sh

cd $HOME

# Clone and build Rust using Clang from previous instruction. Add Rust toolchain to rustup.
git clone https://github.com/securesystemslab/rust.git -b pkru-safe
cd <path/to/automation>
./build_rust.sh
```

For more information on what these scripts are doing, feel free to take a look at either one:
* [build_clang.sh](https://github.com/securesystemslab/pkru-safe-automation/blob/main/build_clang.sh)
* [build_rust.sh](https://github.com/securesystemslab/pkru-safe-automation/blob/main/build_rust.sh)

## User Guide

### Project Setup

The following user guide will use a [minimum working example][mwe] 
to give an overview of how to use PKRU-Safe in a Rust project. 

To use PKRU-Safe, you will need to have followed the instructions under [Setup](#setup) to use
our extended version of the Rust compiler. Next, you will need to add some dependencies to the 
[Cargo.toml](https://github.com/securesystemslab/pkru-safe-example/blob/main/pkru-unsafe-lib/Cargo.toml) 
of the Rust library you are marking as an untrusted interface (any Rust library that interfaces 
with C code that you do not wish to trust):

```toml
# This should be the Cargo.toml of the library your main project includes, not the main project itself.
[dependencies]
mpk = { git = "https://github.com/securesystemslab/pkru-safe-mpk-libc.git" }
mpk_protector = { git = "https://github.com/securesystemslab/pkru-safe-mpk-protector.git" }
pkmallocator = { git = "https://github.com/securesystemslab/pkru-safe-pkmallocator.git" }
```

After adding the above dependencies, we will annotate the top level file of the library (typically
the [lib.rs](https://github.com/securesystemslab/pkru-safe-example/blob/main/pkru-unsafe-lib/src/lib.rs)):

```rust
#![feature(plugin, custom_attribute)]
#![feature(macros_in_extern)]
#![plugin(mpk_protector)]
#![mpk_protector]
/// (WARNING: Rust requires these annotations to be at the top of the file to work correctly.)
```

The final requirement is that you change the build profiles in the 
[Cargo.toml](https://github.com/securesystemslab/pkru-safe-example/blob/main/Cargo.toml) of 
the root Rust project that depends on the libraries you just modified.

```toml
[profile.dev]
opt-level = 1
lto = true
codegen-units = 1

[profile.release]
opt-level = 1
lto = true
codegen-units = 1
```

### Building A Project

PKRU-Safe disables all sharing between trusted and untrusted compartments, thus if you build and 
run the [minimum working example][mwe] it will crash where the C library attempts to access Rust data.

1. Build initial pkru-safe-example
```sh
cd pkru-safe-example
cargo build --release
./target/release/pkru-safe-example

# output:
# Value of Vec before call: 0
# zsh: segmentation fault (core dumped)  ./target/release/pkru-safe-example
```

Since we know this access was meant to be intended behavior, we will need to profile the application
to inform PKRU-Safe of the shared access of this data.

2. Build profiling binary
```sh
cargo clean

# -C enable-untrusted=dynamic enables LLVM passes for our dynamic approach
# -Zsanitizer=mpk adds the hooks to allocations and enables our runtime
cargo rustc --release -- -C enable-untrusted=dynamic -Zsanitizer=mpk

# Running the generated program will produce a results folder `TestResults` 
# containing all faulting allocations found.
./target/release/pkru-safe-example
```

Running the program will produce a folder in the root directory of the project named `TestResults`.
This folder contains all of the allocation sites found by the runtime that need to be marked as shared 
allocations. Once we have finished all tests we want to run on the profiling version, we will 
build it again and pass the compiler the `TestResults` folder.

3. Build instrumented binary
```sh
cargo clean

# -C mpk_use=TestResults passes the folder location containing all faulting allocations
cargo rustc --release -- -C enable-untrusted=dynamic -C mpk_use=TestResults

./target/release/pkru-safe-example

# output:
# Value of Vec before call: 0
# Value of Vec after call: 1337
```

Now, any access from C code outside of the approved access patterns from profiling will fail and 
generate a segfault.

## PKRU Tests

### PKRU-Safe Example

[PKRU-Safe example](https://github.com/securesystemslab/pkru-safe-example) is a minimum working example to highlight how to set up a Rust project to use PKRU-Safe as well as demonstrate how PKRU-Safe works on a simple example. This programs consists of a single allocation which is shared and then written in a 
simple C library. For a simple walk through of how to build and run this project, see the 
[Building A Project](#building-a-project) section.

### Micro-benchmarks

[Micro-benchmarks](https://github.com/securesystemslab/pkru-safe-bench) is a micro-benchmark for testing and logging the overhead of the `mpk-call-gates` and transitions between safe and unsafe. To build these benchmarks, grab and build the repository:

```sh
# Get pkru-safe-benchmarks
git clone https://github.com/securesystemslab/pkru-safe-bench.git
cd pkru-safe-bench

# Build the profile project (WARNING: This requires the custom compiler referenced in instructions above!)
cargo build --release -- -C enable-untrusted=dynamic -Zsanitizer=mpk

# Run profile
./target/release/pkrusafe-bench -n 10 -p

# Build instrumented version
cargo build --release -- -C enable-untrusted=dynamic -C mpk_use=TestResults
```

This benchmark has a few options available for ease of use and testing:

* `-p` - profile mode for profiling application
* `-s` - run iterations through stepped workload
* `-n` - number of iterations
* `-o` - output location for csv information

An example of running this benchmark after building would be:

```sh
# Run standard test set
./target/release/pkrusafe-bench -n 10 -o test.csv

# Run stepped workload
./target/release/pkrusafe-bench -n 100 -p -o stepped.csv
```

If you do not include an argument for `<-o>` then the results will print to console.

### Servo

[Servo](https://github.com/securesystemslab/pkru-safe-servo) is a web browser engine written in Rust. It is also one of
the largest Rust programs currently available and thus makes for a good target for testing 
PKRU-Safe's abilities. To test PKRU-Safe on Servo, it is highly recommended that you use the 
[pre-built image][docker-image] as it will have artifacts of all of the versions of Servo already
built and ready to test. As a note: on the author's machine, profiling Servo and building a final instrumented copy took around 6 hours. If you wish to build the different versions of Servo yourself,
follow the instructions below, otherwise feel free to skip ahead to the testing scripts instructions.

```sh
# This tutorial once again assumes some default folder locations,
# primarily that everything is taking place in $HOME/mpk-test-dir.
# You can change the given directories you want to work with by
# altering the BASE_PATH variable in automation/sources.sh

cd automation

# (OPTIONAL: If you did not grab requirements for running Servo above, grab them now)
./servo-requirements.sh

# Grabbing the Servo Repositories
./grab_servo.sh

# Build Servo Folders (optional flag -b will also benchmark all 
# versions of servo after building them)
./build_servo.sh -t all

# Run benchmarks if you did not above
./run_benchmarks.sh -t all
```

The [pre-built image][docker-image] will contain a folder of pre-built artifacts that you 
can test as well. For an overview of the docker container layout, see reference in 
[Author's Docker Container](#author-docker-container). Within the artifacts folder will
be the following Servo artifacts:

* artifacts
  * servo-vanilla - Unmodified Servo from commit just before
  * servo-step - Servo PKRU-Safe step version
  * servo-step-no-mpk - Servo PKRU-Safe step with PKRU turned off (no access restrictions)
  * servo-exploitable - Servo PKRU-Safe with PKRU turned off and additional allocation for showing html cve exploit
  * servo-pkru - Servo PKRU-Safe with additional allocation to show defense on html cve exploit

To run these pre-built artifacts instead of building your own from the instructions above:

1. Bench artifacts
```sh
# Move to automation folder
cd automation

# Benchmark artifacts (by default puts results into mpk-test-dir folder)
./bench_artifacts.sh

# Separate benchmarking script for dromaeo as it takes significantly longer than the other test suites
./bench_artifacts_dromaeo.sh

# Gather benchmark results into data folder
./gather_benchmarks.sh

# Generate normalized overhead table output (to stdout) and graphs in the `graphs` folder
# (WARNING: This step requires running the `python-requirements.sh` script to update Python3 with the required packages)
python3 pkru_runner.py
```

It is possible that while running the Dromaeo artifact benchmark it will trigger a spurious bug causing a Rust runtime exception:

```
DomRefCell<T> already mutably borrowed: BorrowError (thread ScriptThread PipelineId { namespace_id: PipelineNamespaceId(1), index: PipelineIndex(1) }, at src/libcore/result.rs:999)
[2022-02-15T19:28:38Z ERROR servo] DomRefCell<T> already mutably borrowed: BorrowError
Pipeline failed in hard-fail mode.  Crashing!
```

This issue is present in the unmodified version of Servo that we branched from and appears to depend largely
on hardware configuration. We have found that reducing the number of iterations the Dromaeo test bench 
runs will significantly reduce the likelihood of encountering this issue. To reduce the iterations, you will
need to alter the `numTests` variable in the 
[webrunner.js](https://github.com/notriddle/dromaeo/blob/0df04c071f49dce9ecf578c4e152706aacc886f1/dep/web/webrunner.js#L8) 
file. In the docker container, this will be 
located at `$HOME/mpk-test-dir/servo-step-no-mpk/tests/dromaeo/dromaeo/web/webrunner.js`.

```
# “numTests” on Line 8 controls the number of iterations for a test.
# Reducing it to 4 (or lower) should allow the benchmark suite to complete. 
Var numTests = 5;
```

2. Test exploit on artifacts
```sh
# Test exploit protection. This runs the exploit 3 times as Servo does not always grab the correct 
# memory range for the simplified exploit to work.
./test_exploit.sh
```

## Acknowledgements

This material is based upon work partially supported by the
Defense Advanced Research Projects Agency (DARPA) under
contracts W31P4Q-20-C-0052 and W912CG-21-C-0020. Any
opinions, findings, and conclusions or recommendations ex-
pressed in this material are those of the authors and do not
necessarily reflect the views of the Defense Advanced Re-
search Projects Agency (DARPA), its Contracting Agents, or
any other agency of the U.S. Government. We also thank the
Donald Bren School of Information and Computer Science
at UCI for an ICS Research Award.

## Citation

If you find this work useful, please cite our work as follows:

```
@inproceedings{kirth2022pkrusafe,
author = {Kirth, Paul and Dickerson, Mitchel and Crane, Stephen and Larsen, Per and Dabrowski, Adrian and Gens, David and Na, Yeoul and Volckaert, Stijn and Franz, Michael},
title = {{PKRU}-Safe: Automatically Locking Down the Heap Between Safe and Unsafe Languages},
year = {2022},
doi = {https://doi.org/10.1145/3492321.3519582},
booktitle = {Proceedings of the Seventeenth European Conference on Computer Systems},
location = {Rennes, France},
series = {EuroSys '22}
}
```

[docker-image]: https://hub.docker.com/r/mgdickerson/pkru-safe
[docker-file]: https://github.com/securesystemslab/pkru-safe-automation/blob/main/Dockerfile
[paper-link]: https://doi.org/10.1145/3492321.3519582
[mwe]: https://github.com/securesystemslab/pkru-safe-example
