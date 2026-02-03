from pwnie import *

context.binary = exe = ELF('/mnt/d/sec/research_v8/v8/out/x64_level7_chall.release/d8', checksec=False)

gdbscript = r'''
init-pwndbg
debug_v8
c
'''


def start(argv=None, *a, **kw):
	argv = argv or []
	full_argv = [exe.path, '--allow-natives-syntax', './exp.js', *argv]
	if args.GDB:
		return gdb.debug(full_argv, gdbscript=gdbscript, *a, **kw, aslr=False)
	return process(full_argv, *a, **kw)


p = start()
interactive()
