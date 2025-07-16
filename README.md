# tinyflex <img align="right" src="https://i.imgur.com/GMhpOXw.png" />
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-8af7ff.svg)](https://opensource.org/licenses/Unlicense)
[![Build Status](https://github.com/Theldus/tinyflex/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Theldus/tinyflex/actions/workflows/c-cpp.yml)
<br/>
<br/>
tinyflex is a **single-header**, dependency-free FLEX™ protocol encoder written
in ISO C89. It produces fully-valid FLEX paging messages with zero dynamic
allocations, no I/O, and no platform-specific dependencies, making it suitable
for freestanding environments.

## Features
As a compact library (given the protocol's complexity), tinyflex doesn't attempt
to implement the entire FLEX specification but focuses on a subset that provides
'good enough' functionality for most use cases:

- **Speed**: 1600bps / 2-FSK
- **Frame:** Single-frame support
- **Messages type**: Alphanumeric messages (ASCII) up to 251 characters
- **Capcode**: 7-digit capcode support (9-digit on roadmap!)

## Usage
Usage is straightforward and centers around a single public function:

```c
size_t
tf_encode_flex_message(const char *msg, uint32_t cap_code,
    uint8_t *flex_pckt, size_t flex_size, int *error);
```

as follows:
```c
#include "tinyflex.h"

int main(void) {
    uint8_t vec[FLEX_BUFFER_SIZE] = {0};
    size_t size;
    int err;

    size = tf_encode_flex_message(
        "HELLO, WORLD!", 1234567, vec, sizeof vec, &err);

    if (!err)
        /* error. */
    else
        /* do something with your output. */
}
```

The main concept is simple: once you obtain the FLEX-encoded packet, you can use
any external tool to transmit it, such as [GNURadio] or [ttgo-fsk-tx].

[GNURadio]: https://www.gnuradio.org/about/
[ttgo-fsk-tx]: https://github.com/rlaneth/ttgo-fsk-tx/

## Companion programs
The `demo/` directory contains two companion programs to facilitate library
usage: `encode_file` and `send_ttgo`.

### `encode_file`
Designed for transmission tools that work with file input and/or communicate
via pipes, `encode_file` provides an easy way to generate FLEX packets:

```bash
./encode_file <capcode> <message> <output_file>
or:
./encode_file [-l] (from stdin/stdout)

Stdin/stdout mode:
   -l Loop mode (optional): stays open receiving new lines of messages
                            until EOF
   Example:
     printf '1234567:MY MESSAGE'               | ./encode_file (no loop mode)
     printf '1234567:MY MSG1\n1122334:MY MSG2' | ./encode_file -l (loop mode)
   (binary output goes to stdout!)

   Note: On loop mode, each output is preceded by a line indicating
         how many bytes follows, ex:
   795\n   <binary output>
   600\n   <binary output>

Normal mode:
   ./encode_file 1234567 'MY MESSAGE' output.bin
```

`encode_file` allows you to save packets to an output file or generate new
packets continuously via stdin/stdout, enabling seamless integration with
external tools.

### send_ttgo
`send_ttgo` is a companion tool designed to work with [ttgo-fsk-tx] firmware,
enabling transmission of FLEX packets to pagers through a Lilygo TTGO LoRa32-OLED
development board.

Its usage is similar to `encode_file`, supporting both command-line arguments
and pipes:

```bash
./send_ttgo [options] <capcode> <message>
or:
./send_ttgo [options] [-l] (from stdin)

Options:
   -d <device>    Serial device (default: /dev/ttyACM0)
   -b <baudrate>  Baudrate (default: 115200)
   -f <frequency> Frequency in MHz (default: 929.937500)
   -p <power>     TX power (default: 2, 2-17)

Stdin mode:
   -l Loop mode (optional): stays open receiving new lines
                            until EOF
   Example:
     printf '1234567:MY MESSAGE'               | ./send_ttgo
     printf '1234567:MY MSG1\n1122334:MY MSG2' | ./send_ttgo -l

Normal mode:
   ./send_ttgo 1234567 'MY MESSAGE'
   ./send_ttgo -d /dev/ttyUSB0 -f 915.5 1234567 'MY MESSAGE'
```

## Acknowledgements
This project came from discussions and experiments on paging that I have worked
on along with @rlaneth. He's gifted me a Motorola Advisor Elite pager and a
TTGO LoRa32-OLED board that have made this project possible.

[@rlaneth]: https://github.com/rlaneth

## Contributing
tinyflex welcomes community contributions of all kinds, including issues,
documentation improvements, testing, new features, bug fixes, typos, and more.
Welcome aboard!

## License
tinyflex is released into the public domain under the Unlicense license.
