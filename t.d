syscall::write:entry,
syscall::write_nocancel:entry
/execname == strstr(execname, "testbin")/
{
   self->arg0 = arg0;
   self->arg1 = arg1;
   self->arg2 = arg2;
   raise(SIGTRAP);
}

syscall::write:return,
syscall::write_nocancel:return,
syscall::read:return,
syscall::read_nocancel:return
/execname == strstr(execname, "testbin")/
{
   printf("%s(0x%X, \"%S\", 0x%X)\t\t = %d %d\n",probefunc,self->arg0,
       arg0 == -1 ? "" : stringof(copyin(self->arg1,arg0)),self->arg2,(int)arg0,
       (int)errno);
}
