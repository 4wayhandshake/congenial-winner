# congenial-winner
Known plaintext attack utilizing MD5 hashing performed by a predefined binary

This tool is used for reading privileged files, by abusing the capabilities assigned to the `scanner` binary in a certain HTB box.

## Instructions

Just run the python file. Supply the required arguments:
```
known-plaintext.py [-h] [--hex] target length
```
`-h` to see the help text

`--hex` to read a target that contains hexadecimal characters only (like an HTB flag)

`target`: required. The absolute filepath of the file to read

`length`: required. An estimate of the length of the file to read. If unknown, overestimate. 


![known-plaintext-screenshot](known-plaintext-screenshot.gif)

