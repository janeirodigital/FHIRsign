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

// Check it now, but this code will go in bin/check.ts.
const resource2 = readJson(resourceFile);
// resource2.status = "completed999";
const checked = s.check(resource2, detachedSignature);

if (checked.content.match(/[^\x20-\x7e]/))
  (<any>checked.content) = [checked.content.split("").reduce(
    (hex:string ,c:string) =>
      hex += c.charCodeAt(0).toString(16).padStart(2,"0")
    ,""
  )];


console.log(JSON.stringify(checked, null, 2));

function readJson(filePath: string) {
    return JSON.parse(Fs.readFileSync(filePath));
}

