CC=gcc
CFLAGS=-I. -DUSE_SSL
LIBS=-lcrypto


%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

mfh-tool: mfh-tool.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f mfh-tool.o mfh-tool
