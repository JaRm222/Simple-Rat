# Simple-Rat

This is a very simple rat. I made this to learn rust and go as well as some simple concepts of RAT's and malware techniques.

The source is pretty terrible it hasn't been cleaned up.

## Rat
This is the implant. To build this edit the data file in builder directory and then provide this as an argument to "add_section.py". Then run build_debug.bat. Providing -sectname as an argument.

## Rat Client
This is a python implementation of a client so that you can interact with the implant

## Rat server
The listener for commands and where the implant checks in.
