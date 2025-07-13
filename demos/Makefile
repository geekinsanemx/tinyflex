#
# tinyflex: A minimal, dependency-free, single-header library, FLEX encoder.
# Written by Davidson Francis (aka Theldus) - 2025.
#
# This is free and unencumbered software released into the public domain.
#

CC     ?= cc
CFLAGS  = -Wall -Wextra
CFLAGS += -I$(CURDIR)/..

.PHONY: all clean
all: encode_file send_ttgo

encode_file: encode_file.o $(CURDIR)/../tinyflex.h
send_ttgo:   send_ttgo.o   $(CURDIR)/../tinyflex.h

clean:
	rm -f *.o
	rm -f encode_file
	rm -f send_ttgo
