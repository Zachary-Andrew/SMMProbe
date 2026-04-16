CFLAGS = -O2 -Wall -Wextra -std=c11 -I include
LDFLAGS = 

OBJS = src/smm_probe.o src/smi_fuzzer.o src/main.o

smm_probe: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f smm_probe src/*.o
