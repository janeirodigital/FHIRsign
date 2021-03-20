/**
 * (eventual) example invocation:
 sign examples/privKey.json examples/medicationrequest0301-lite.json yourMom > medreq-signed.json
 check examples/pubKey.json medreq-signed.json
 */

const Fs = require('fs');
import { FHIRSign } from '../src/FHIRsign';

const [pub, priv, resourceFile, issuer] = process.argv.slice(2);
const s = new FHIRSign(readJson(pub), readJson(priv));
const resource = readJson(resourceFile);
const signed = s.sign(resource, issuer);
const [encodedHeader, encodedPayload, encodedSignature] = signed.split('.');
const detachedSignature = encodedHeader + '..' + encodedSignature;
console.log('signed (still a JWS, should be patched resource):', detachedSignature);

// Check it now, but this code will go in bin/check.ts.
const resource2 = readJson(resourceFile);
// resource2.status = "completed999";
const checked = s.check(resource2, detachedSignature);
console.log(JSON.stringify(checked, null, 2));

function readJson(filePath: string) {
    return JSON.parse(Fs.readFileSync(filePath));
}

