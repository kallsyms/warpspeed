This is Warpspeed, a record+replay debugger for macOS.
It heavily relies on [AppBox](../appbox) to provide the isolation and introspection required to work. Read ../appbox/AGENTS.md for details if details about the lower level VM architecture are required, and make changes to the project as necessary to support new features in Warpspeed.

## Prior work
The `rr` project is probably the best reference for how previous projects have implemented record+replay systems. Do not copy their work, but if scoping out how something could/should behave, web search for how `rr` does it, or clone the [source](https://github.com/rr-debugger/rr) and inspect it in a sub agent.

## Core components
Given AppBox provides most of the base requirements for VM operation, Warpspeed's main components are purely for recording syscall side-effects, replaying those side-effects during replay, and ensuring replay stays on track.
Warpspeed saves the target spawn information and the event history (syscall, mach trap, etc.) in protobuf as defined in [recordable.proto](./src/recordable/recordable.proto)

## Debugging
It's very rare to have a crash in the Rust code that composes AppBox+Warpspeed. If that does happen, normal Rust debugging applies: use `RUST_BACKTRACE=full` to get a backtrace, `lldb` to debug the process if necessary, etc. `println!` debugging is probably the easiest to debug things which may result from VM misconfiguration (keeping memory maps aligned for example).

Most of the time issues will manifest as a VM trap (instruction/data abort).
Given we have a GDB stub in AppBox (and exposed in the Warpspeed CLI) it may be possible to debug some things going on in the guest by using GDB/LLDB on that target stub (e.g. a syscall handler is misimplemented returning NULL somewhere causing an eventual NULL deref in the VM).
Lastly, the lower level debug utilities exposed in AppBox (for dumping register state etc.) can be called directly as part of an iterative debug process.

## Development loop
Always `cargo build` to verify your changes compile. If running to test behavior, use release builds as they are much faster.
