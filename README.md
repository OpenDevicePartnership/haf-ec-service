# Hafnium EC Service in Rust

## Overview

This is a sample implementation of the EC service which runs under a dedicated secure partition in Hafnium.
It is written in Rust and has dependencies on FF-A, MU UEFI, Hafnium and TFA.

## Documentation

Project documentation is maintained in the [mdBook source](docs/src/SUMMARY.md)
and published through GitHub Pages.

## Feature Status

The following components are available within this crate:

```
ec-service-lib - Common code used in implementation of EC SP
platform       - Contains target specific code for supported platforms
```

## Customizations

Update memory map definitions in platforms/plat/linker folder to match the definition from your dts config file.

```
	load-address = <0x0 0x20400000>;
	entrypoint-offset = <0x10000>;
	image-size = <0x0 0x40000>;
```

```
MEMORY
{
	image : ORIGIN = 0x20410000, LENGTH = 2M
	rxtx_buf : ORIGIN = 0x100600A0000, LENGTH = 8K
	smem : ORIGIN = 0x10060000000, LENGTH = 8K
}
```

## Build Instructions

From the root folder you can build all platforms using
`cargo build`

To build for aarch64 target use
`cargo build --target=aarch64-unknown-none`

To convert the output ELF to binary run
`cargo objcopy --target=aarch64-unknown-none -- -O binary output.bin`

## Build Validation

Before submission, run the precommit hook to validate the code.

```
.husky/pre-commit
```
