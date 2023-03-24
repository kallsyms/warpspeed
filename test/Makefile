.PHONY: all
all: echo multithread time

echo: echo.c
	$(CC) -o $@ $^

multithread: multithread.c
	$(CC) -o $@ $^

time: time.c time.S
	$(CC) -o $@ $^

.PHONY: clean
clean:
	rm -f echo multithread time
