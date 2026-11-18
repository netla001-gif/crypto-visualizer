import fs from 'fs'; import {execSync} from 'child_process'; import vm from 'vm';
const html = fs.readFileSync(process.argv[2], 'utf8');
const core = html.match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto, console}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,toHex,runCipher,desBlock,tdesBlock,aesBlock,seedBlock,rsaGen,rsaOp,rsaDerive,derBuild,biHex,kcv,pkcs1Pad,pkcs1Unpad,byteLen};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0;
const eq = (name, a, b) => { const ok = a.toUpperCase() === b.toUpperCase(); if(!ok){ fail++; console.log('FAIL', name, a, b); } };
eq('DES', X.toHex(X.desBlock(H('133457799BBCDFF1'), H('0123456789ABCDEF')).out), '85E813540F0AB405');
eq('DES dec', X.toHex(X.desBlock(H('133457799BBCDFF1'), H('85E813540F0AB405'), true).out), '0123456789ABCDEF');
eq('AES128', X.toHex(X.aesBlock(H('000102030405060708090a0b0c0d0e0f'), H('00112233445566778899aabbccddeeff')).out), '69c4e0d86a7b0430d8cdb78070b4c55a');
eq('AES192', X.toHex(X.aesBlock(H('000102030405060708090a0b0c0d0e0f1011121314151617'), H('00112233445566778899aabbccddeeff')).out), 'dda97ca4864cdfe06eaf70a0ec0d7191');
eq('AES256', X.toHex(X.aesBlock(H('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), H('00112233445566778899aabbccddeeff')).out), '8ea2b7ca516745bfeafc49904b496089');
eq('AES256 dec', X.toHex(X.aesBlock(H('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), H('8ea2b7ca516745bfeafc49904b496089'), true).out), '00112233445566778899aabbccddeeff');
eq('SEED1', X.toHex(X.seedBlock(H('00000000000000000000000000000000'), H('000102030405060708090A0B0C0D0E0F')).out), '5EBAC6E0054E166819AFF1CC6D346CDB');
eq('SEED2', X.toHex(X.seedBlock(H('000102030405060708090A0B0C0D0E0F'), H('00000000000000000000000000000000')).out), 'C11F22F201405050844835 97E4370F43'.replace(/ /g,''));
eq('SEED3', X.toHex(X.seedBlock(H('4706480851E61BE85D74BFB3FD956185'), H('83A2F8A288641FB9A4E9A5CC2F131C7D')).out), 'EE54D13EBCAE706D226BC3142CD40D4A');
const r1 = X.seedBlock(H('000102030405060708090A0B0C0D0E0F'), H('00000000000000000000000000000000')).trace.ks.rounds[0];
eq('SEED K1', r1.K0.toString(16)+r1.K1.toString(16), 'c119f5845ae033a0');
// 무작위 비교 vs openssl (CBC, 여러 블록)
const rnd = n => X.toHex(Array.from(crypto.getRandomValues(new Uint8Array(n))));
const ossl = (cipher, key, iv, data, dec) => execSync(`echo ${data} | xxd -r -p | openssl enc -provider legacy -provider default ${dec?'-d':''} -${cipher} -K ${key} ${iv?'-iv '+iv:''} -nopad | xxd -p -c 1000`).toString().trim();
for(let t = 0; t < 20; t++){
  for(const [alg, cipher, kl, bs] of [['DES','des-cbc',8,8],['3DES','des-ede3-cbc',24,8],['3DES','des-ede-cbc',16,8],['SEED','seed-cbc',16,16],['AES','aes-128-cbc',16,16],['AES','aes-192-cbc',24,16],['AES','aes-256-cbc',32,16]]){
    const key = rnd(kl), iv = rnd(bs), data = rnd(bs * (1 + t % 4));
    const mine = X.runCipher(alg, H(key), H(data), {decrypt:false, mode:'CBC', iv:H(iv), padding:'NONE'});
    eq(`${cipher} enc`, X.toHex(mine.out), ossl(cipher, key, iv, data));
    const back = X.runCipher(alg, H(key), mine.out, {decrypt:true, mode:'CBC', iv:H(iv), padding:'NONE'});
    eq(`${cipher} dec`, X.toHex(back.out), data);
    const e2 = X.runCipher(alg, H(key), H(data).slice(0, bs*(1+t%4) - 3), {decrypt:false, mode:'ECB', iv:[], padding:'PKCS7'});
    const d2 = X.runCipher(alg, H(key), e2.out, {decrypt:true, mode:'ECB', iv:[], padding:'PKCS7'});
    eq(`${alg} pkcs7 roundtrip`, X.toHex(d2.unpadded.data), data.slice(0, (bs*(1+t%4)-3)*2));
    const e3 = X.runCipher(alg, H(key), H(data), {decrypt:false, mode:'CBC', iv:H(iv), padding:'M2'});
    const d3 = X.runCipher(alg, H(key), e3.out, {decrypt:true, mode:'CBC', iv:H(iv), padding:'M2'});
    eq(`${alg} M2 roundtrip`, X.toHex(d3.unpadded.data), data);
  }
}
// 3DES 2-key KCV 알려진 값: key 0123456789ABCDEFFEDCBA9876543210 → KCV 08D7B4
eq('KCV', X.toHex(X.kcv('3DES', H('0123456789ABCDEFFEDCBA9876543210'))), '08D7B4');
// RSA
const small = X.rsaDerive(61n, 53n, 17n);
eq('small d', small.d.toString(), '2753'); eq('small qinv', small.qinv.toString(), '38');
eq('small enc', X.rsaOp(small, 'encrypt', H('41'), {padding:'NONE'}).r.toString(), '2790');
eq('small dec crt', X.rsaOp(small, 'decrypt', H('0AE6'), {padding:'NONE', crt:true}).r.toString(), '65');
let t0 = Date.now(); const K = X.rsaGen(1024, 65537n); console.log('gen1024 ms', Date.now()-t0, 'nbits', K.n.toString(2).length);
for(const [a, b, pad] of [['encrypt','decrypt','PKCS1'],['sign','verify','PKCS1'],['encrypt','decrypt','NONE']]){
  const m = H('48656C6C6F');
  const c = X.rsaOp(K, a, m, {padding:pad});
  for(const crt of [false, true]){ const p = X.rsaOp(K, b, c.outBytes, {padding:pad, crt});
    eq(`rsa ${a}/${b} ${pad} crt=${crt}`, X.toHex(p.outSegs ? p.outSegs.at(-1).b : p.outBytes).replace(/^0+/,''), '48656C6C6F'); }
}
// DER 공개키를 openssl로 파싱해서 N 확인
const der = X.derBuild([{label:'n',val:K.n},{label:'e',val:K.e}]);
const bytes = [...der.head, ...der.items.flatMap(i=>[...i.tl,...i.lead,...i.v])];
fs.writeFileSync(process.argv[3]+'/pub.der', Buffer.from(bytes));
const priv = X.derBuild([{label:'v',val:0n}, ...['n','e','d','p','q','dp','dq','qinv'].map(k=>({label:k,val:K[k]}))]);
fs.writeFileSync(process.argv[3]+'/priv.der', Buffer.from([...priv.head, ...priv.items.flatMap(i=>[...i.tl,...i.lead,...i.v])]));
fs.writeFileSync(process.argv[3]+'/n.txt', X.biHex(K.n));
t0 = Date.now(); X.rsaGen(2048, 65537n); console.log('gen2048 ms', Date.now()-t0);
console.log(fail ? `${fail} FAILED` : 'ALL OK');
