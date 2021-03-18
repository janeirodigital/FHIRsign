const chilkat = require('@chilkat/ck-node14-linux64');

interface ProtectedHeaders { [name: string]: string }

class FHIRSign {
    private iz: Array<number> = [1, 2];
    private pubKey = new chilkat.PublicKey();
    private privKey = new chilkat.PrivateKey();

    constructor(pubKeyParm: any, privKeyParm: any) {
        if (this.pubKey.LoadFromString(JSON.stringify(pubKeyParm)) !== true)
            throw Error(`public key error: ${this.pubKey.LastErrorText}`);

        if (this.privKey.LoadJwk(JSON.stringify(privKeyParm)) !== true)
            throw Error(`private key error: ${this.privKey.LastErrorText}`);
    }

    encJwsEcdsa(payloadStr: string, headers: ProtectedHeaders = {}) {
        // Create the JWS Protected Header
        var jwsProtHdr = new chilkat.JsonObject();
        Object.keys(headers).forEach(
            key => jwsProtHdr.AppendString(key, headers[key])
        );

        var jws = new chilkat.Jws();

        var signatureIndex = 0;
        jws.SetProtectedHeader(signatureIndex, jwsProtHdr);
        jws.SetPrivateKey(signatureIndex, this.privKey);
        jws.SetPayload(payloadStr, "utf-8", false /* don't include BOM */);
        var jwsCompact = jws.CreateJws(); // default to compact serialization
        if (jws.LastMethodSuccess !== true)
            throw Error(`CreateJws error: ${jws.LastErrorText}`);
        return jwsCompact;
    }

    decJwsEcdsa(last: string) {
        var jws = new chilkat.Jws();

        // Set the ECC public key:
        var signatureIndex = 0;
        jws.SetPublicKey(signatureIndex, this.pubKey);

        // Load the JWS.
        var sbJws = new chilkat.StringBuilder();
        sbJws.Append(last)

        let success = jws.LoadJwsSb(sbJws);
        if (success !== true)
            throw Error(`LoadJwsSb error: ${jws.LastErrorText}`);

        // Validate the 1st (and only) signature at index 0..
        var v = jws.Validate(signatureIndex);
        if (v < 0)
            throw Error(`Validate error: ${jws.LastErrorText}`);

        if (v == 0)
            throw Error("Invalid signature.  The ECC key was incorrect, the JWS was invalid, or both.");

        // Examine the protected header:
        // joseHeader: JsonObject
        var joseHeader = jws.GetProtectedHeader(signatureIndex);
        if (jws.LastMethodSuccess !== true)
            throw Error("No signature header found.");

        joseHeader.EmitCompact = false;
        return {
            valid: true,
            content: jws.GetPayload("utf-8"),
            header: JSON.parse(joseHeader.Emit()),
        };
    }
}
// (global-set-key (kbd "<backtab>") 'company-complete)
const s = new FHIRSign({
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}, {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
})

const resource = {
    "resourceType": "CodeSystem",
    "id": "medicationrequest-intent",
    "meta": {
        "lastUpdated": "2019-11-16T11:53:58.181+01:00",
        "profile": ["http://hl7.org/fhir/StructureDefinition/shareablecodesystem"]
    },
}

const headers = { "alg": "ES256", "issuer": "adsf" };
const payload = JSON.stringify(resource);
const sig = s.encJwsEcdsa(payload, headers);
console.log('sig:', sig);
const got = s.decJwsEcdsa(sig);
console.log('got:', JSON.stringify(got, null, 2));

// const sigString = s.encJwsEcdsa("In our village, folks say God crumbles up the old moon into stars.", headers);
// console.log('sigstring:', sigString);
// const sig2 = s.decJwsEcdsa(sig2)
// console.log('result:', JSON.stringify(sig2, null, 2));
