/**
 * example invocation:
 sign examples/pubKey.json examples/privKey.json examples/medicationrequest0301-lite.json yourMom > medreq-signed.json
 */

const Fs = require('fs');
import { FHIRSign } from '../src/FHIRsign';

const [pub, priv, input, issuer] = process.argv.slice(2);
const s = new FHIRSign(readJson(pub), readJson(priv));
const signed = s.sign(readJson(input), issuer);

function readJson(filePath: string) {
    return JSON.parse(Fs.readFileSync(filePath));
}

