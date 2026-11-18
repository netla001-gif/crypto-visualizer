import fs from 'fs'; import vm from 'vm'; import {execSync} from 'child_process';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={visaIad,visaCvr,visaArqcVerify,parseHex,toHex,tlvParse};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0; const ok = (n, c, i = '') => { if(!c){ fail++; console.log('FAIL', n, i); } };
const sh = c => execSync(c).toString().trim().toUpperCase();
const ede = (k, d) => sh(`echo ${d} | xxd -r -p | openssl enc -provider legacy -provider default -des-ede-ecb -K ${k} -nopad | xxd -p`);
// 독립 계산: OpenSSL로 MK(Option A) → (CSK) → Retail MAC
function ref(imk, pan, psn, data, cvn18, atc){
  const y = (pan + psn).slice(-16), yx = X.toHex(H(y).map(b => b ^ 0xFF));
  let mk = ede(imk, y) + ede(imk, yx);
  mk = X.toHex(H(mk).map(b => (b & 0xFE) | (((b >> 1).toString(2).split('1').length - 1) % 2 ? 0 : 1)));
  const key = cvn18 ? ede(mk, atc + 'F00000000000') + ede(mk, atc + '0F0000000000') : mk;
  let d = data; if(cvn18) d += '80'; while(d.length % 16) d += '00';
  const K = key.slice(0, 16), K2 = key.slice(16);
  const cbc = sh(`echo ${d} | xxd -r -p | openssl enc -provider legacy -provider default -des-cbc -K ${K} -iv 0000000000000000 -nopad | xxd -p | tr -d '\\n'`);
  const last = cbc.slice(-16);
  const r = sh(`echo ${last} | xxd -r -p | openssl enc -provider legacy -provider default -des-ecb -d -K ${K2} -nopad | xxd -p`);
  return sh(`echo ${r} | xxd -r -p | openssl enc -provider legacy -provider default -des-ecb -K ${K} -nopad | xxd -p`);
}
const tags = {'9F02': '000000100000', '9F03': '000000000000', '9F1A': '0410', '95': '0000008000', '5F2A': '0410', '9A': '261118', '9C': '00', '9F37': '1A2B3C4D', '82': '7C00', '9F36': '002A'};
const imk = '0123456789ABCDEFFEDCBA9876543210', pan = '4761739001010119', psn = '01';
for(const [iad, cvn18] of [['06010A03A00000', false], ['06011203A000000F0100000000000000000000000000000000'.slice(0, 64), true], ['06011203A00000', true]]){
  const ORDER = ['9F02','9F03','9F1A','95','5F2A','9A','9C','9F37','82','9F36']; const data = ORDER.map(k => tags[k]).join('') + (cvn18 ? iad : iad.slice(6, 14));
  const ac = ref(imk, pan, psn, data, cvn18, tags['9F36']);
  const T = Object.fromEntries(Object.entries({...tags, '9F10': iad, '9F26': ac}).map(([k, v]) => [k, H(v)]));
  const r = X.visaArqcVerify({imk: H(imk), pan: H(pan), psn: H(psn), tags: T});
  ok('verify ' + iad.slice(0, 8), r.ok, X.toHex(r.A.mac) + ' vs ' + ac);
  T['9F02'] = H('000000800000'); ok('tamper ' + iad.slice(0, 8), !X.visaArqcVerify({imk: H(imk), pan: H(pan), psn: H(psn), tags: T}).ok);
  console.log('sample', cvn18 ? 'CVN18' : 'CVN10', iad, ac);
}
const c = X.visaCvr(H('A00000')); ok('cvr arqc', c[0].includes('요청 안 됨') && c[1].includes('ARQC'), c.join());
ok('cvr bits', X.visaCvr(H('6C1028')).join().includes('오프라인 PIN 검증 수행') && X.visaCvr(H('6C1028')).join().includes('신규 카드') && X.visaCvr(H('6C1028')).join().includes('SM 스크립트 명령 2개'));
const i = X.visaIad(H('06011203A000000F01020304')); ok('iad', i.cvn === 0x12 && i.dki === 1 && i.iddLen === 0x0F && X.toHex(i.cvr) === 'A00000');
let thrown = ''; try { X.visaArqcVerify({imk: H(imk), pan: H(pan), psn: H(psn), tags: {'9F10': H('06011603A00000')}}); } catch(e){ thrown = e.message; } ok('cvn unsupported', thrown.includes('22'), thrown);
console.log(fail ? fail + ' FAILED' : 'VISA ALL OK');
