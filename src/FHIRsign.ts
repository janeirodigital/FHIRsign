
const chilkat = require('@chilkat/ck-node14-linux64'); // { PublicKey,PrivateKey,JsonObject,Jws,StringBuilder }
const canonicalize = require('canonicalize');
import { Base64 } from '../src/Base64';

interface ProtectedHeaders { [name: string]: string }

export class FHIRSign {
  private iz: Array<number> = [1, 2];
  private pubKey = new chilkat.PublicKey();
  private privKey = new chilkat.PrivateKey();

  // Pretend to parameterize this (but leave explicit code for debuggability).
  private static Algorithms = {
    "ES256": {
      hash: {
        HashAlgorithm: "sha256",
        Charset: "utf-8",
      },
      encode: "encodeJwsEcdsa",
      decode: "decodeJwsEcdsa",
    }
  };

  /** Construct a FHIRsign with the pub and priv key as JSON
   * objects. (See ../examples/privKey.json for an example.)
   */
  constructor(pubKeyParm: object, privKeyParm: object) {
    if (this.pubKey.LoadFromString(JSON.stringify(pubKeyParm)) !== true)
      throw Error(`public key error: ${this.pubKey.LastErrorText}`);

    if (this.privKey.LoadJwk(JSON.stringify(privKeyParm)) !== true)
      throw Error(`private key error: ${this.privKey.LastErrorText}`);
  }

  /** Sign a FHIR Resource.
   *
   * TODO: return a resource with the signature injected in the
   * meta.
   */
  sign(resource: object, issuer: string) {

    // Hash resource.
    const hashString = this.hash(resource, "sha256");

    // JWS protected headers:
    const headers = { "alg": "ES256", "issuer": issuer };
    const sig = this.encodeJwsEcdsa(hashString, headers);

    return sig; // !! Should be signed resource.
  }

  /** Check a FHIR Resource signature.
   *
   * TODO: return orig resource
   */
  check(resource: object, detachedSignature: string): object {
    const [encodedHeader, encodedSignature] = detachedSignature.split('..');
    const payload = this.hash(resource, "sha256");
    const encodedPayload = Base64.encode(payload).replace(/=/g, '');
    const signed = encodedHeader + '.' + encodedPayload + '.' + encodedSignature;

    const validity = this.decodeJwsEcdsa(signed);
    validity.hashValidity = validity.content === payload;
    return validity;
  }

  hash(resource: object, algorithm: string) {
    const payload = canonicalize(resource);
    const crypt = new chilkat.Crypt2();
    crypt.HashAlgorithm = algorithm;
    crypt.Charset = "utf-8";
    const hashBytes = crypt.HashString(payload);

    // Hex-encode bytes with an arbitrary prefix string to give warm fuzzies.
    const sb = new chilkat.StringBuilder();
    sb.AppendEncoded(hashBytes, "hex");
    return "SHA256:" + sb.GetAsString()
  }

  encodeJwsEcdsa(payloadStr: string, headers: ProtectedHeaders = {}) {
    // Create the JWS Protected Header
    var jwsProtHdr = new chilkat.JsonObject();
    Object.keys(headers).forEach(
      key => jwsProtHdr.AppendString(key, headers[key])
    );

    var jws = new chilkat.Jws();

    var signatureIndex = 0; debugger
    jws.SetProtectedHeader(signatureIndex, jwsProtHdr);
    jws.SetPrivateKey(signatureIndex, this.privKey);
    jws.SetPayload(payloadStr, "utf-8", false /* don't include BOM */);

    // I don't see a CreateDetachedJws. Should I be able to strip
    // out the text between the '..'s and reproduce it given the
    // signed entity and the public key?

    var jwsCompact = jws.CreateJws(); // default to compact serialization
    if (jws.LastMethodSuccess !== true)
      throw Error(`CreateJws error: ${jws.LastErrorText}`);
    return jwsCompact;
  }

  decodeJwsEcdsa(last: string) {
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
      sigValidity: true,
      hashValidity: false, // not yet tested
      content: jws.GetPayload("utf-8"),
      header: JSON.parse(joseHeader.Emit()),
    };
  }
}

