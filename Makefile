CC=gcc
CFLAGS=-g -Wall
LDFLAGS=
SOURCES := $(wildcard *.c)
OBJS=$(SOURCES:.cc=.o)
EXECUTABLE=aes

all: $(EXECUTABLE) $(SOURCES)
.PHONY: all

# link
$(EXECUTABLE) : $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@
# compile
%.o : %.cc
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm *.o $(EXECUTABLE)
