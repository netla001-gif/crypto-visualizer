import fs from 'fs'; import vm from 'vm'; import {execSync} from 'child_process';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,toHex,emvSkF,emvSessionKey,emvScriptBuild,cardScriptProcess,scriptTlv,pinBlock,randBytes};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0; const ok = (n, c) => { if(!c){ fail++; console.log('FAIL', n); } };
const ede = (k, d) => execSync(`echo ${d} | xxd -r -p | openssl enc -provider legacy -provider default -des-ede-ecb -K ${k} -nopad | xxd -p`).toString().trim().toUpperCase();
const mk = X.toHex(X.randBytes(16)), R = X.toHex(X.randBytes(8));
const F = X.emvSkF(H(mk), H(R));
ok('skF', X.toHex(F.sk) === ede(mk, R.slice(0, 4) + 'F0' + R.slice(6)) + ede(mk, R.slice(0, 4) + '0F' + R.slice(6)));
const atc = H('0002');
ok('skF==sessionKey for ATC', X.toHex(X.emvSkF(H(mk), [...atc, 0, 0, 0, 0, 0, 0]).sk) === X.toHex(X.emvSessionKey(H(mk), atc).sk));
const smi = X.randBytes(16), smc = X.randBytes(16), arqc = X.randBytes(8);
for(const [enc, plain, macLen, w] of [[true, X.pinBlock('5678'), 4, true], [false, [], 4, true], [false, H('05'), 8, false], [true, H('0102030405'), 4, true]]){
  const o = {smcKey: smc, smiKey: smi, atc, arqc, withAcAtc: w, macLen};
  const b = X.emvScriptBuild({ins: 0x24, p1: 0, p2: 2, plain, encrypt: enc, ...o});
  const r = X.cardScriptProcess(b.apdu, {...o, encrypted: enc});
  ok('roundtrip ' + enc + macLen, r.sw === '9000' && (enc ? X.toHex(r.plain).startsWith(X.toHex(plain)) : X.toHex(r.plain) === X.toHex(plain)));
  const t2 = b.apdu.slice(); t2[t2.length - macLen - 1 > 4 ? t2.length - macLen - 1 : 2] ^= 1;
  ok('tamper ' + enc, X.cardScriptProcess(t2, {...o, encrypted: enc}).sw !== '9000');
  if(w) ok('replay ' + enc, X.cardScriptProcess(b.apdu, {...o, arqc: X.randBytes(8), encrypted: enc}).sw === '6988');
}
const tl = X.scriptTlv(0x72, H('00000001'), [H('841E000004AABBCCDD')]);
ok('tlv', X.toHex(tl) === '72129F180400000001' + '8609841E000004AABBCCDD');
console.log(fail ? fail + ' FAILED' : 'SCRIPT ALL OK');
