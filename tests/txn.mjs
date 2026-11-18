import fs from 'fs'; import vm from 'vm';
const core = fs.readFileSync(process.argv[2], 'utf8').match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = {crypto: globalThis.crypto}; vm.createContext(ctx);
vm.runInContext(core + ';this.X={emvTxn,parseHex,toHex,emvDeriveMK,emvSessionKey,emvArqc};', ctx);
const X = ctx.X, H = s => X.parseHex(s, 't'); let fail = 0; const ok = (n, c, info='') => { if(!c){ fail++; console.log('FAIL', n, info); } };
const base = {sel: 'PSE', oda: 'DDA', odaOk: true, expiry: '291231', effective: '240101', txDate: H('261118'), cvm: 'OFFPIN', pin: 'OK', amount: 10000, floor: 5000, random: false,
  online: 'APPROVE', arpcOk: true, script: true, tac: {d: H('0010000000'), o: H('DC4004F800'), f: H('DC4000A800')}, iac: {d: H('0000000000'), o: H('F470049800'), f: H('F470049800')},
  imk: H('0123456789ABCDEFFEDCBA9876543210'), imkSmi: H('F1E2D3C4B5A69788796A5B4C3D2E1F00'), pan: '4761739001010119', un: H('1A2B3C4D'), atc: 42};
const run = o => X.emvTxn({...base, ...o});
const lc = r => r.steps.flatMap(s => s.apdus).every(a => { const h = a.c[0].b; if(h.length < 5) return true; const sum = a.c.slice(1).filter(p => p.l !== 'Le').reduce((s, p) => s + (p.n ?? p.b.length), 0); return h[4] === sum; });
let r = run({}); ok('online approve', r.outcome.ok && r.cid === 0x40, r.outcome.text); ok('tvr floor', X.toHex(r.tvr) === '0000008000', X.toHex(r.tvr)); ok('tsi', X.toHex(r.tsi) === 'FC00', X.toHex(r.tsi)); ok('lc', lc(r));
r = run({amount: 100}); ok('offline TC', r.cid === 0x40 && r.outcome.text.includes('오프라인 승인'), r.outcome.text); ok('tsi offl', X.toHex(r.tsi) === 'E800', X.toHex(r.tsi));
r = run({expiry: '251231'}); ok('expired -> online', r.steps.find(s => s.phase === 'TAA').checks[0][1].includes('ARQC') && (r.tvr[1] & 0x40));
r = run({expiry: '251231', iac: {...base.iac, d: H('0040000000')}}); ok('expired denial', r.cid === 0 && !r.outcome.ok, r.outcome.text);
r = run({oda: 'CDA', odaOk: false}); ok('cda fail', !r.outcome.ok && (r.tvr[0] & 0x04), r.outcome.text);
r = run({oda: 'SDA', odaOk: false, amount: 100}); ok('sda fail->online', r.tvr[0] === 0x42 && r.steps.some(s => s.phase === 'ONLINE'), X.toHex(r.tvr));
r = run({oda: 'NONE', amount: 100}); ok('no oda', r.tvr[0] === 0x80);
r = run({pin: 'BLOCKED'}); ok('pin blocked', r.tvr[2] === 0xA0 && X.toHex(r.cvmResults) === '040301', X.toHex(r.tvr));
r = run({pin: 'WRONG'}); ok('pin wrong', r.steps.find(s => s.phase === 'CVM').apdus.length === 5 && r.tvr[2] === 0, ''); ok('lc2', lc(r));
r = run({cvm: 'ONPIN'}); ok('online pin', r.tvr[2] === 0x04);
r = run({online: 'DECLINE'}); ok('decline', r.cid === 0 && !r.outcome.ok);
r = run({arpcOk: false}); ok('arpc fail', r.cid === 0 && (r.tvr[4] & 0x40), r.outcome.text);
r = run({online: 'NOCOMM'}); ok('nocomm default', r.outcome.text.includes('Z3'), r.outcome.text);
r = run({online: 'NOCOMM', tac: {...base.tac, f: H('0000000000')}, iac: {...base.iac, f: H('0000000000')}}); ok('nocomm Y3', r.cid === 0x40, r.outcome.text);
r = run({sel: 'AID', cvm: 'NOCVM', script: false}); ok('aid path', r.steps[0].apdus.length === 3 && !r.steps.some(s => s.phase === 'SCRIPT'));
// ARQC from txn matches ARQC tab math: CDOL1 + AIP + ATC
r = run({}); const g = r.steps.find(s => s.phase === 'GAC1').apdus[0]; const data = g.c.slice(1, -1).flatMap(p => p.b);
const sk = X.emvSessionKey(X.emvDeriveMK(base.imk, H(base.pan), [1]).mk, [0, 42]).sk; const mac = X.emvArqc(sk, [...data, 0x7C, 0x00, 0x00, 42], 'M2').mac;
ok('arqc consistent', g.r.some(p => p.l === 'AC (암호문)' && X.toHex(p.b) === X.toHex(mac)));
console.log(fail ? fail + ' FAILED' : 'TXN ALL OK');
