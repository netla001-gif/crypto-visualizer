import fs from 'fs'; import vm from 'vm';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,emvDemoIssue,emvCertStep,emvSdaStep,emvDynStep,emvCardDynSign};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0, n = 0;
const pan = H('4761739001010119'), sd = H('5A0847617390010101195F24032812315F2503240101'), un = H('01020304'), tx = H('00112233');
const L = [128, 144, 176, 248], combos = [];
for(const a of L) for(const b of L) for(const c of L) if(c <= b && b <= a) combos.push([a, b, c]);
combos.push([176, 140, 98], [176, 141, 99], [248, 212, 170], [248, 213, 171], [248, 248, 248]); // 자리 정확히 맞음 / 1바이트 넘침
for(const [a, b, c] of combos){
  const D = X.emvDemoIssue(pan, sd, [a * 8, b * 8, c * 8]);
  const s1 = X.emvCertStep('issuer', D.iss.cert, {n: D.CA.n, e: D.CA.e}, {rem: D.iss.rem, exp: D.iss.exp, pan});
  const s2 = X.emvCertStep('icc', D.icc.cert, s1.key, {rem: D.icc.rem, exp: D.icc.exp, pan, sdata: sd});
  const sda = X.emvSdaStep(D.ssad, s1.key, sd);
  const dyn = [false, true].map(cda => X.emvDynStep(X.emvCardDynSign(D.IC, {ddol: un, cda, tx}), s2.key, {ddol: un, cda, tx}).ok);
  const bad = X.emvDynStep(X.emvCardDynSign(D.IC, {ddol: un, cda: false, tx}), s2.key, {ddol: H('01020305'), cda: false, tx}).ok;
  const ok = s1.ok && s2.ok && s1.key.n === D.IS.n && s2.key.n === D.IC.n && sda.ok && dyn[0] && dyn[1] && !bad && s1.sig.length === a && s2.sig.length === b;
  n++; if(!ok) fail++;
  console.log(`CA ${a} / I ${b} / IC ${c}: 90=${s1.sig.length}B 92=${D.iss.rem.length}B 9F46=${s2.sig.length}B 9F48=${D.icc.rem.length}B → ${ok ? 'OK' : 'FAIL'}`);
}
console.log(fail ? `${fail}/${n} FAILED` : `ALL ${n} COMBOS OK`);
