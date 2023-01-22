syscall::write:entry,
syscall::write_nocancel:entry
/* /execname == strstr(execname, "testbin")/ */
/pid == 16075/
{
    printf("stopping");
    raise(SIGSTOP);
}
