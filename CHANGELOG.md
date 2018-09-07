v 0.3
- Added functionality to test wolfSSL using auto-conf build system. See
  README.md for USAGE of ```a``` option
- Added functionality to re-run a SINGLE failing pre-processor specific test.
  See README.md for USAGE of ```s``` option.

v 0.2
- Added Pre-Processor detection. See README.md for USAGE of ```m``` and ```e```
  options
- Added functionality to test single Pre Processor (PP) Macros scrubbed
  from the wolfSSL source directory
- Added user-input functionality
- Added custom tool-chain framework
- Added custom builds functionality. See README.md for USAGE of ```c``` option


v 0.1
- Initial work on a "Configurator Tool" Goals are:

- Ability to benchmark various builds in comparison to the default build.
  This will allow for comparison of footprint expected by a feature being
  enabled

- PHP server to display results of benchmark builds for customers evaluating
  adding a feature to their wolfSSL builds

- Test all Quality Assurance cases from a central local to avoid excessive
  cloning in nightly and pull request testing

- Build with various toolchains for embedded systems

- A way to quickly build specific submodules only such as "aes-only" or
  "rsa-only" etc. while removing un-needed sources from the build directory.

- A solution to detect and test new pre-processor macros added to wolfSSL that
  are not documented explicitly for followup testing.

- Other goals may be added over time.

- v 0.1 added initial functionality for:
    - "Benchmarking footprints". See README.md for USAGE of ```b``` option.
    - API's for executing system commands like in a shell environment

