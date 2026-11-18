import fs from 'fs'; import vm from 'vm';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,toHex,emvDemoIssue,emvCertStep,pinBlock,pinEncipher,cardVerifyEnciphered,randBytes};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0; const ok = (n, c) => { if(!c){ fail++; console.log('FAIL', n); } };
ok('pinblock', X.toHex(X.pinBlock('1234')) === '241234FFFFFFFFFF');
ok('pinblock12', X.toHex(X.pinBlock('123456789012')) === '2C123456789012FF');
const pan = H('4761739001010119'), D = X.emvDemoIssue(pan, H('5A08'), [1984, 1408, 1152]);
const s1 = X.emvCertStep('issuer', D.iss.cert, {n: D.CA.n, e: D.CA.e}, {rem: D.iss.rem, exp: D.iss.exp, pan});
const pe = X.emvCertStep('pe', D.PE.cert.cert, s1.key, {rem: D.PE.cert.rem, exp: D.PE.cert.exp, pan, sdata: []});
ok('pe cert ok', pe.ok && pe.key.n === D.PE.key.n);
for(const [name, pub, priv] of [['ICC', {n: D.IC.n, e: D.IC.e}, D.IC], ['PE', pe.key, D.PE.key]]){
  const ch = X.randBytes(8), e = X.pinEncipher(pub, X.pinBlock('1234'), ch);
  let r = X.cardVerifyEnciphered(priv, e.cipher, ch, '1234', 3); ok(name + ' good', r.sw === '9000' && r.ptc === 3);
  r = X.cardVerifyEnciphered(priv, X.pinEncipher(pub, X.pinBlock('9999'), ch).cipher, ch, '1234', 3); ok(name + ' wrong', r.sw === '63C2' && r.ptc === 2);
  r = X.cardVerifyEnciphered(priv, e.cipher, X.randBytes(8), '1234', 2); ok(name + ' replay', r.sw === '63C1' && !r.checks[1].ok);
  r = X.cardVerifyEnciphered(priv, e.cipher, ch, '1234', 1); ok(name + ' last ok resets', r.sw === '9000' && r.ptc === 3);
  r = X.cardVerifyEnciphered(priv, X.pinEncipher(pub, X.pinBlock('0000'), ch).cipher, ch, '1234', 1); ok(name + ' block', r.sw === '6983' && r.ptc === 0);
  r = X.cardVerifyEnciphered(priv, e.cipher, ch, '1234', 0); ok(name + ' blocked', r.sw === '6983');
  ok(name + ' cipher varies', X.toHex(e.cipher) !== X.toHex(X.pinEncipher(pub, X.pinBlock('1234'), ch).cipher));
}
console.log(fail ? fail + ' FAILED' : 'PIN ALL OK');
