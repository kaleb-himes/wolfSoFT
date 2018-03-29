Beta v0.1

Use provided makefile to build sources.
Execute program with ./run

Program will clone, autogen, and configure the wolfSSL library using the default
configuration as a baseline for comparison.

Program will always use static and not shared to ensure compiled applications
reflect library + program code side.

Program will sum and average the three apps example client and server and
unit.test the idea being that between those three we should hit most of the
code functionality getting an accurate build impact on footprint regardless of
optimizations.

Intended use: Support gets many questions about how a configuration will impact
footprint. This program will allow Jenkins to crank out some numbers each night
and a support engineer can check the output log to answer customer questions of
this nature.


