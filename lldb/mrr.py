import lldb
import os

import pathlib
import shlex

from src.recordable import recordable_pb2

TRACE_KEY = "trace"
TARGET_KEY = "target"
PROCESS_KEY = "process"
CURRENT_ENTRY_KEY = "cur"


def load(debugger, command, _result, internal_dict):
    args = shlex.split(command)
    if not args:
        print("Usage: mrr /path/to/trace")
        return

    trace_filename = args[0]
    if not pathlib.Path(trace_filename).exists():
        print("No such trace file {}", trace_filename)
        return

    if TRACE_KEY in internal_dict:
        print("Warning: trace already loaded, overwriting")

    with open(trace_filename, "rb") as tracef:
        trace = recordable_pb2.Trace()
        try:
            trace.ParseFromString(tracef.read())
        except IOError:
            print("Invalid or corrupt trace file")
            return

    print(trace.target)
    target = debugger.CreateTarget(trace.target.path)

    # debugger.SetInternalVariable(
    #     "target.run-args", " ".join(trace.target.arguments), debugger.GetInstanceName()
    # )
    # debugger.SetInternalVariable(
    #     "target.env-vars",
    #     " ".join(trace.target.environment),
    #     debugger.GetInstanceName(),
    # )

    # TODO: cwd
    launch_info = target.GetLaunchInfo()
    launch_info.SetArguments(list(trace.target.arguments), False)
    launch_info.SetEnvironmentEntries(list(trace.target.environment), False)
    launch_info.SetLaunchFlags(
        lldb.eLaunchFlagStopAtEntry | lldb.eLaunchFlagDisableASLR
    )
    error = lldb.SBError()
    process = target.Launch(launch_info, error)
    print(f"Launch {error=}")

    # process = target.LaunchSimple(
    #     trace.target.arguments, trace.target.environment, os.getcwd()
    # )

    internal_dict[TRACE_KEY] = trace
    internal_dict[TARGET_KEY] = target
    internal_dict[PROCESS_KEY] = process
    internal_dict[CURRENT_ENTRY_KEY] = 0

    reg_bp(target, trace.events[0])

    print("Successfully loaded trace")


def reg_bp(target: lldb.SBTarget, event: recordable_pb2.LogEvent):
    bp = target.BreakpointCreateByAddress(event.pc)
    bp.SetOneShot(True)
    bp.SetAutoContinue(True)
    bp.SetScriptCallbackFunction("mrr.handle_bp")
    bp.AddName("mrr")


def handle_bp(frame, bp_loc, extra_args, internal_dict):
    # print(f"BP at {bp_loc}")
    trace = internal_dict[TRACE_KEY]
    process = internal_dict[PROCESS_KEY]
    event_idx = internal_dict[CURRENT_ENTRY_KEY]
    cur_event = trace.events[event_idx]

    assert frame.pc == cur_event.pc

    if cur_event.WhichOneof("event") == "syscall":
        if cur_event.syscall.WhichOneof("data") == "return_only":
            # Show child stdout/stderr writes
            if cur_event.syscall.syscall_number in (4, 397) and frame.register[
                "x0"
            ].unsigned in (1, 2):
                error = lldb.SBError()
                out = process.ReadMemory(
                    frame.register["x1"].unsigned,
                    cur_event.syscall.return_only.rv0,
                    error,
                )
                print(f"Child wrote to fd {frame.register['x0'].unsigned}: {out}")

            frame.register["x0"].value = str(cur_event.syscall.return_only.rv0)
            frame.register["x1"].value = str(cur_event.syscall.return_only.rv1)
            frame.SetPC(frame.pc + 4)

        elif cur_event.syscall.WhichOneof("data") == "read":
            if cur_event.syscall.read.WhichOneof("result") == "data":
                error = lldb.SBError()
                process.WriteMemory(
                    frame.register["x1"].unsigned, cur_event.syscall.read.data, error
                )
                print(f"read {error=}")
                frame.register["x0"].value = str(len(cur_event.syscall.read.data))
                frame.register["x1"].value = "0"
            else:
                frame.register["x0"].value = str(cur_event.syscall.read.error)
                frame.register["x1"].value = "0"
            frame.SetPC(frame.pc + 4)

        else:
            print(f"Unhandled syscall {cur_event.syscall.syscall_number}")
    elif cur_event.WhichOneof("event") == "mach_trap":
        if cur_event.mach_trap.WhichOneof("data") == "return_only":
            frame.register["x0"].value = str(cur_event.mach_trap.return_only)
            frame.SetPC(frame.pc + 4)
        # TODO
        # elif cur_event.mach_trap.WhichOneof("data") == "timebase":
        #     frame.SetPC(frame.pc + 4)
        else:
            print(f"Unhandled mach_trap {cur_event.mach_trap.trap_number}")
    elif cur_event.WhichOneof("event") == "scheduling":
        # TODO
        pass

    event_idx += 1
    internal_dict[CURRENT_ENTRY_KEY] = event_idx
    if event_idx < len(trace.events):
        print(f"Registering next bp at {trace.events[event_idx].pc}")
        reg_bp(internal_dict[TARGET_KEY], trace.events[event_idx])


def rev_continue(debugger, command, _result, _internal_dict):
    pass


def __lldb_init_module(debugger, _internal_dict):
    debugger.HandleCommand("command script add -f mrr.load mrr")
    debugger.HandleCommand("command script add -f mrr.rev_continue reverse-continue")
