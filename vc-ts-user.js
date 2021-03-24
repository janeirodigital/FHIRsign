const Fs = require('fs');
const { Ed25519KeyPair } = require('crypto-ld');
const jsigs = require('jsonld-signatures');
const vc = require('vc-js');
const util = require('jsonld-signatures/lib/util.js');
const fileIntegrituyHash = 'https://xformativ.pub/as/terms#fileIntegrityHash';

main().catch(e => console.warn(e));

async function main() {
  let keyPair = await Ed25519KeyPair.generate({
    id: 'https://example.edu/issuers/keys/1',
    controller: 'https://example.edu/issuers/565049'
  });
  const myDate = new Date('2020-01-01T00:00:00Z'); // always generate the same hash for easy debugging
  const myIsoDate = myDate.toISOString().replace(/\.\d\d\dZ$/, 'Z'); // trim msecs
  let suite = new jsigs.suites.Ed25519Signature2018({
    verificationMethod: 'https://example.edu/issuers/keys/1',
    key: keyPair, date: myDate
  });
  let myCredential = {
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://my.example/v1"],
    "id": "http://example.edu/credentials/1872",
    "type": ["VerifiableCredential", "FileIntegrityCredential"],
    "issuer": "https://example.edu/issuers/565049",
    "issuanceDate": "2020-01-01T01:23:45Z",
    "credentialSubject": {
      "id": "https://a.example/Bob/ebfeb1f712ebc6f1c276e12ec21",
      "fileIntegrityHash": "0123456789abcdef"
    }
  };

  const LoadableDocuments = Object.entries({
    'https://www.w3.org/2018/credentials/v1': 'docLoader/credentials_v1.json',
    'https://my.example/v1': 'docLoader/examples_v1.json',
    'https://www.w3.org/ns/odrl.jsonld': 'docLoader/odrl.json',
    'https://w3id.org/security/v1': 'docLoader/security_v1.json',
    'https://w3id.org/security/v2': 'docLoader/security_v2.json',
  }).reduce((acc, [name, path]) => {
    acc[name] = JSON.parse(Fs.readFileSync(path));
    return acc;
  }, {});
  function documentLoader(url) {
    if (url in LoadableDocuments)
      return {
        contextUrl: null,
        documentUrl: url,
        document: LoadableDocuments[url]
      };
    console.warn('Failed to load document:', url); // 'cause the code loses the throw
    throw Error(`not found ${url}`);
  }

  let verifiableCredential = await vc.issue({
    credential: myCredential,
    suite, documentLoader, compactProof: false
  });
  console.log(verifiableCredential);
  // myCredential.credentialSubject.fileIntegrityHash = "0123456789abcdef";


  const assertionController = {
    '@context': 'https://w3id.org/security/v2',
    id: 'https://example.edu/issuers/565049',
    // actual keys are going to be added in the test suite before() block
    assertionMethod: [],
    authentication: []
  };
  assertionController.assertionMethod.push(keyPair.id);
  const result = await vc.verifyCredential({
    credential: verifiableCredential,
    controller: assertionController,
    suite,
    documentLoader
  });
  console.log(result);

  function expansionMap(info) { throw Error('no expansion map for ' + info); }
  if (false) {
    /*
      | true  | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||     |
      |       | BASE64URL(JWS Payload))                                   |
      |       |                                                           |
      | false | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||    |
      |       | JWS Payload                                               |
    */
    const header = {
      b64: false,
      alg: 'EdDSA',
      crit: ['b64']
    };
    const encodedHeader = util.encodeBase64Url(JSON.stringify(header)); // eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19

    const proof = {
      "@context": "https://w3id.org/security/v2",
      "type": "Ed25519Signature2018",
      "created": "2019-12-31T23:00:00Z",
      "verificationMethod": "https://example.edu/issuers/keys/1",
      "proofPurpose": "assertionMethod"
    };

    const CredentialIssuancePurpose = require('vc-js/lib/CredentialIssuancePurpose');
    const purpose = new CredentialIssuancePurpose();
    const credential = {};
    const options = {
      credential: myCredential,
      suite, documentLoader, compactProof: false
    };
    // const vc2 = await jsigs.sign(credential, { purpose, documentLoader, suite, ...options });
    const ProofSet = require('jsonld-signatures/lib/ProofSet');
    const compactProof = false;
    const cred2 = { ...myCredential };
    const vc3 = await new ProofSet().add(cred2, { suite, purpose, documentLoader, expansionMap, compactProof });
    const input = { ...cred2 };
    const proofProperty = 'proof';
    const proof2 = await suite.createProof({ document: input, purpose, documentLoader, expansionMap, compactProof });
    delete proof2['@context'];
    cred2.proof = proof2;
    console.log(cred2);
  }

  const proof3 = {
    '@context': 'https://w3id.org/security/v2',
    type: 'Ed25519Signature2018',
    created: myIsoDate,
    verificationMethod: 'https://example.edu/issuers/keys/1',
    proofPurpose: 'assertionMethod',
  };
  const c14nProofOptions = await suite.canonize(
    proof3, { documentLoader, expansionMap });
  const cred3 = { ...myCredential };
  const c14nDocument = await suite.canonize(cred3, {
    documentLoader,
    expansionMap
  });
  const verifyData = util.concat(
    util.sha256(c14nProofOptions),
    util.sha256(c14nDocument)
  );
  await suite.sign({ verifyData, document: cred3, proof: proof3, documentLoader, expansionMap });
  console.log(cred3);

  const result3 = await vc.verifyCredential({
    credential: cred3,
    controller: assertionController,
    suite,
    documentLoader
  });
  console.log(JSON.stringify(result3, null, 2));
}
