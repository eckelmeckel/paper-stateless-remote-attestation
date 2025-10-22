CC = gcc

CFLAGS =     -std=c99 -g -pedantic -Wall -Wextra -Wimplicit-fallthrough \
             -Wno-missing-field-initializers -Wl,--gc-sections \
             -fdata-sections -ffunction-sections

LIBINCLUDE = -I/usr/include \
             -I/usr/local/include

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu

LDFLAGS = -lm -lmbedcrypto

TARGET = stateless_ra_demo
SRC = stateless_ra_demo.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean

