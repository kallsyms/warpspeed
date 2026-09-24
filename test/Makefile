.PHONY: all
all: echo multithread time rand mmap_shared threads exec preempt

echo: echo.c
	$(CC) -o $@ $^

multithread: multithread.c
	$(CC) -o $@ $^

time: time.c time.S
	$(CC) -o $@ $^

rand: rand.c
	$(CC) -o $@ $^

mmap_shared: mmap_shared.c
	$(CC) -o $@ $^

threads: threads.c
	$(CC) -o $@ $^

exec: exec.c
	$(CC) -o $@ $^

preempt: preempt.c
	$(CC) -O1 -o $@ $^

.PHONY: clean
clean:
	rm -f echo multithread time rand mmap_shared threads exec preempt
