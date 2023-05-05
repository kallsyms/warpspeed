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

    first_bp = target.BreakpointCreateByAddress(trace.events[0].pc)

    print("Successfully loaded trace")


def rev_continue(debugger, command, _result, _internal_dict):
    pass


def __lldb_init_module(debugger, _internal_dict):
    debugger.HandleCommand("command script add -f mrr.load mrr")
    debugger.HandleCommand("command script add -f mrr.rev_continue reverse-continue")
