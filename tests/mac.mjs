import fs from 'fs'; import {execSync} from 'child_process'; import vm from 'vm';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,toHex,retailMac,padBytes};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0;
const sh = c => execSync(c, {shell: '/bin/bash'}).toString().trim();
const ossl = (args, data) => sh(`echo ${data} | xxd -r -p | openssl enc -provider legacy -provider default ${args} -nopad | xxd -p -c 1000`).toUpperCase();
const rnd = n => X.toHex(Array.from(crypto.getRandomValues(new Uint8Array(n))));
for(let t = 0; t < 15; t++){
  const key = rnd(16), iv = t % 2 ? rnd(8) : '0000000000000000', pad = ['M1','M2','NONE'][t % 3];
  let data = rnd(t % 3 === 2 ? 8 * (1 + t % 4) : 1 + t * 3);
  const padded = data + X.toHex(X.padBytes(H(data), 8, pad));
  const cbc = ossl(`-des-cbc -K ${key.slice(0,16)} -iv ${iv}`, padded), hn = cbc.slice(-16);
  const d = ossl(`-d -des-ecb -K ${key.slice(16)}`, hn), want = ossl(`-des-ecb -K ${key.slice(0,16)}`, d);
  const got = X.toHex(X.retailMac(H(key), H(data), {iv: H(iv), padding: pad}).mac);
  if(got !== want){ fail++; console.log('FAIL', key, data, pad, got, want); }
}
console.log('ISO 예제(방법1):', X.toHex(X.retailMac(H('0123456789ABCDEFFEDCBA9876543210'), H('4E6F77206973207468652074696D6520666F7220616C6C20'), {iv: H('0000000000000000'), padding: 'M1'}).mac));
console.log(fail ? fail + ' FAILED' : 'MAC ALL OK');
