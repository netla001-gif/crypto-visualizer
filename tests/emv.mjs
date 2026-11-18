import fs from 'fs'; import vm from 'vm'; import nc from 'crypto'; import {execSync} from 'child_process';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={parseHex,toHex,sha1,emvDemoIssue,emvCertStep,emvSdaStep,emvDynStep,emvCardDynSign,derBuild,biHex};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0;
const ok = (n, c) => { if(!c){ fail++; console.log('FAIL', n); } };
for(const len of [0, 1, 55, 56, 63, 64, 65, 200, 1000]){ const b = nc.randomBytes(len);
  ok('sha1 ' + len, X.toHex(X.sha1([...b])) === nc.createHash('sha1').update(b).digest('hex').toUpperCase()); }
const pan = H('4761739001010119'), sd = H('5A0847617390010101195F24032812315F25032401015F3401019F0702FF008E0C000000000000000042031E03');
let t0 = Date.now(); const D = X.emvDemoIssue(pan, sd); console.log('issue ms', Date.now() - t0);
const capk = {n: D.CA.n, e: D.CA.e};
const s1 = X.emvCertStep('issuer', D.iss.cert, capk, {rem: D.iss.rem, exp: D.iss.exp, pan});
ok('issuer ok', s1.ok); ok('issuer key', s1.key.n === D.IS.n); console.log('issuer room', s1.room, 'NI', s1.NI, 'rem', s1.rem.length);
const s2 = X.emvCertStep('icc', D.icc.cert, s1.key, {rem: D.icc.rem, exp: D.icc.exp, pan, sdata: sd});
ok('icc ok', s2.ok); ok('icc key', s2.key.n === D.IC.n); console.log('icc room', s2.room, 'NI', s2.NI, 'rem', s2.rem.length);
ok('sda ok', X.emvSdaStep(D.ssad, s1.key, sd).ok);
const un = H('1A2B3C4D'), tx = H('000000001000000000000000041000');
for(const cda of [false, true]){ const sig = X.emvCardDynSign(D.IC, {ddol: un, cda, tx});
  const s3 = X.emvDynStep(sig, s2.key, {ddol: un, cda, tx}); ok('dyn ok cda=' + cda, s3.ok);
  ok('dyn wrong UN fails', !X.emvDynStep(sig, s2.key, {ddol: H('1A2B3C4E'), cda, tx}).ok);
  if(cda) ok('cda tx tamper fails', !X.emvDynStep(sig, s2.key, {ddol: un, cda, tx: H('00')}).ok); }
const sd2 = sd.slice(); sd2[5] ^= 1;
ok('static tamper icc fails', !X.emvCertStep('icc', D.icc.cert, s1.key, {rem: D.icc.rem, exp: D.icc.exp, pan, sdata: sd2}).ok);
ok('static tamper sda fails', !X.emvSdaStep(D.ssad, s1.key, sd2).ok);
ok('pan mismatch fails', !X.emvCertStep('issuer', D.iss.cert, capk, {rem: D.iss.rem, exp: D.iss.exp, pan: H('5555555555554444')}).ok);
// OpenSSL로 CA 공개키 raw 복원 → 6A ... BC 인지 (서명 방향 독립 검증)
const der = X.derBuild([{label: 'n', val: D.CA.n}, {label: 'e', val: D.CA.e}]);
fs.writeFileSync(process.argv[3] + '/ca.der', Buffer.from([...der.head, ...der.items.flatMap(i => [...i.tl, ...i.lead, ...i.v])]));
fs.writeFileSync(process.argv[3] + '/90.bin', Buffer.from(D.iss.cert));
const rec = execSync(`openssl rsa -RSAPublicKey_in -inform DER -in ${process.argv[3]}/ca.der -pubout -out ${process.argv[3]}/ca.pem 2>/dev/null && openssl pkeyutl -verifyrecover -pubin -inkey ${process.argv[3]}/ca.pem -pkeyopt rsa_padding_mode:none -in ${process.argv[3]}/90.bin | xxd -p -c 1000`).toString().trim().toUpperCase();
ok('openssl recover', rec === X.toHex(s1.X)); console.log('recovered head/tail', rec.slice(0, 30), '…', rec.slice(-4));
console.log(fail ? fail + ' FAILED' : 'EMV ALL OK');
