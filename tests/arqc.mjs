import fs from 'fs'; import vm from 'vm'; import {execSync} from 'child_process';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,toHex,emvDeriveMK,emvSessionKey,emvArqc,emvArpc1,padBytes};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0;
const o = (args, d) => execSync(`echo ${d} | xxd -r -p | openssl enc -provider legacy -provider default ${args} -nopad | xxd -p -c 1000`).toString().trim().toUpperCase();
const ede = (k, d) => o(`-des-ede-ecb -K ${k}`, d);
const xorH = (a, b) => a.match(/../g).map((x, i) => ((parseInt(x, 16) ^ parseInt(b.substr(2 * i, 2), 16)) & 255).toString(16).padStart(2, '0')).join('').toUpperCase();
const par = h => h.match(/../g).map(x => { let b = parseInt(x, 16) & 0xFE; let c = b.toString(2).split('1').length - 1; return ((c % 2) ? b : b | 1).toString(16).padStart(2, '0'); }).join('').toUpperCase();
const rnd = n => X.toHex(Array.from(crypto.getRandomValues(new Uint8Array(n))));
for(let t = 0; t < 10; t++){
  const imk = rnd(16), pan = t % 2 ? '4761739001010119' : '541333008960001F', psn = '0' + (t % 10), atc = rnd(2), arc = '3030';
  const data = rnd(29 + t * 3), pad = t % 2 ? 'M2' : 'M1';
  // OpenSSL 기준값
  const digits = pan.replace(/F+$/, '') + psn, Y = digits.padStart(16, '0').slice(-16);
  const mk = par(ede(imk, Y) + ede(imk, xorH(Y, 'FFFFFFFFFFFFFFFF')));
  const sk = ede(mk, atc + 'F00000000000') + ede(mk, atc + '0F0000000000');
  const padded = data + X.toHex(X.padBytes(H(data), 8, pad));
  const hn = o(`-des-cbc -K ${sk.slice(0, 16)} -iv 0000000000000000`, padded).slice(-16);
  const arqc = o(`-des-ecb -K ${sk.slice(0, 16)}`, o(`-d -des-ecb -K ${sk.slice(16)}`, hn));
  const arpc = ede(sk, xorH(arqc, arc + '000000000000'));
  // 페이지 구현
  const M = X.emvDeriveMK(H(imk), H(pan), H(psn)), S = X.emvSessionKey(M.mk, H(atc));
  const A = X.emvArqc(S.sk, H(data), pad), P = X.emvArpc1(S.sk, A.mac, H(arc));
  const got = [X.toHex(M.mk), X.toHex(S.sk), X.toHex(A.mac), X.toHex(P.arpc)], want = [mk, sk, arqc, arpc];
  if(got.join() !== want.join()){ fail++; console.log('FAIL', got, want); }
}
console.log(fail ? fail + ' FAILED' : 'ARQC ALL OK');
