CC = gcc

CFLAGS = -I../liboqs/build/include
LDFLAGS = -L../liboqs/build/lib
LDLIBS = -loqs -lcrypto -lssl

TARGET = pqc_sig
SOURCE = pqc_sig.c

BENCH = pqc_bench
BENCH_SOURCE = pqc_bench.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCE) $(LDLIBS) -o $(TARGET)

$(BENCH): $(BENCH_SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) $(BENCH_SOURCE) $(LDLIBS) -o $(BENCH)

clean:
	rm -f $(TARGET) $(BENCH)
