const Fs = require('fs');
const { Ed25519KeyPair } = require('crypto-ld');
const jsigs = require('jsonld-signatures');
const vc = require('vc-js');
const fileIntegrituyHash = 'https://xformativ.pub/as/terms#fileIntegrityHash';

main().catch(e => console.warn(e));

async function main() {
  let keyPair = await Ed25519KeyPair.generate({
    id: 'https://example.edu/issuers/keys/1',
    controller: 'https://example.edu/issuers/565049'
  });
  let suite = new jsigs.suites.Ed25519Signature2018({
    verificationMethod: 'https://example.edu/issuers/keys/1',
    key: keyPair
  });
  let mockCredential = {
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://my.example/v1"],
    "id": "http://example.edu/credentials/1872",
    "type": ["VerifiableCredential", "FileIntegrityCredential"],
    "issuer": "https://example.edu/issuers/565049",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject": {
      "id": "https://a.example/Bob/ebfeb1f712ebc6f1c276e12ec21",
      "fileIntegrityHash": "0123456789abcdef"
    }
  };

  const LoadableDocuments = Object.entries({
    'https://www.w3.org/2018/credentials/v1': 'docLoader/credentials_v1.json',
    'https://my.example/v1': 'docLoader/examples_v1.json',
    'https://www.w3.org/ns/odrl.jsonld': 'docLoader/odrl.json'
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
    credential: mockCredential,
    suite,
    documentLoader
  });
  console.log(verifiableCredential);
  mockCredential.credentialSubject.fileIntegrityHash = "0123456789abcdef";


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
}
