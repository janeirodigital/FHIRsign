/**
 * example invocation:
 sign examples/pubKey.json examples/privKey.json examples/medicationrequest0301-lite.json yourMom > medreq-signed.json
 */

const Fs = require('fs');
import { FHIRSign } from '../src/FHIRsign';

const [pub, priv, input, issuer] = process.argv.slice(2);
const s = new FHIRSign(readJson(pub), readJson(priv));
const signed = s.sign(readJson(input), issuer);
console.log('signed (still a JWS, should be patched resource):', signed);

// Check it now, but this code will go in bin/check.ts.
const checked = s.check(signed);
console.log(JSON.stringify(checked, null, 2));

function readJson(filePath: string) {
    return JSON.parse(Fs.readFileSync(filePath));
}

