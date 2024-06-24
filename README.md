# Warpspeed
_A super work in progress record/replay debugger for macOS_

Originally presented at REcon 2023 ([talk](https://www.youtube.com/watch?v=KYkHDQYJ6fg), [slides](https://nickgregory.me/files/talks/warpspeed.pdf))

And see my (long delayed) [corresponding blog post](https://nickgregory.me/post/2024/06/23/warpspeed/).

## Building

`make build-release`

There's also `make build-debug`, but debug builds are significantly slower.

## Sample Usage
```
$ ./target/release/warpspeed record /tmp/trace /bin/ls -l
$ ./target/release/warpspeed replay /tmp/trace
```
