/**
 * (eventual) example invocation:
 sign examples/privKey.json examples/medicationrequest0301-lite.json yourMom > medreq-signed.json
 check examples/pubKey.json medreq-signed.json
 */

const Fs = require('fs');
import { FHIRSign } from '../src/FHIRsign';

const [pub, priv, resourceFile, issuer] = process.argv.slice(2);
const s = new FHIRSign(readJson(pub), readJson(priv));
const signed = s.sign(readJson(resourceFile), issuer).replace(/\.[^.]+\./, '..');
console.log('signed (still a JWS, should be patched resource):', signed);

// Check it now, but this code will go in bin/check.ts.
const checkMe = JSON.parse(JSON.stringify(resourceFile)); // copy it
const checked = s.check(readJson(resourceFile), signed);
console.log(JSON.stringify(checked, null, 2));

function readJson(filePath: string) {
    return JSON.parse(Fs.readFileSync(filePath));
}

