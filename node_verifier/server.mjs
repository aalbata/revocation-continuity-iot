// Verification service built on the Digital Bazaar verifiable credential libraries.
// It exposes credential, presentation, and status list verification over local HTTP
// so that the benchmark can run the same fixtures through this stack and the Python stack.
import http from 'node:http';
import {readFileSync} from 'node:fs';
import didContext from 'did-context';
import multikeyContext from '@digitalbazaar/multikey-context';
import * as vc from '@digitalbazaar/vc';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  createSignCryptosuite, createVerifyCryptosuite
} from '@digitalbazaar/eddsa-jcs-2022-cryptosuite';
import {checkStatus} from '@digitalbazaar/vc-bitstring-status-list';

const MULTIKEY_CONTEXT = multikeyContext.CONTEXT_URL;
const EXT_CONTEXT_URL =
  'https://raw.githubusercontent.com/aalbata/revocation-continuity-iot/main/contexts/rcbench-v1.jsonld';
const LOCAL_CONTEXTS = new Map([...didContext.contexts, ...multikeyContext.contexts]);
LOCAL_CONTEXTS.set(EXT_CONTEXT_URL, JSON.parse(
  readFileSync(new URL('../contexts/rcbench-v1.jsonld', import.meta.url), 'utf8')));
// Status is evaluated by the /check-status route, so proof verification accepts any status entry.
const statusDeferred = async () => ({verified: true});

// Resolves only documents supplied with the request and bundled contexts; no network access.
function makeLoader(documents = {}) {
  return async url => {
    if(documents[url]) {
      return {contextUrl: null, documentUrl: url, document: documents[url]};
    }
    const base = url.split('#')[0];
    if(url.includes('#') && documents[base]) {
      const method = (documents[base].verificationMethod || []).find(m => m.id === url);
      if(method) {
        return {contextUrl: null, documentUrl: url,
          document: {'@context': MULTIKEY_CONTEXT, ...method}};
      }
    }
    if(LOCAL_CONTEXTS.has(url)) {
      return {contextUrl: null, documentUrl: url, document: LOCAL_CONTEXTS.get(url)};
    }
    return vc.defaultDocumentLoader(url);
  };
}

function verifySuite() {
  return new DataIntegrityProof({cryptosuite: createVerifyCryptosuite()});
}

function describe(error) {
  if(!error) {
    return [];
  }
  const nested = [...(error.errors || []), ...(error.cause ? [error.cause] : [])];
  if(nested.length === 0) {
    return [String(error.message ? error.message : error)];
  }
  return nested.flatMap(describe);
}

function classify(messages) {
  const text = messages.join(' | ').toLowerCase();
  if(text.length === 0) {
    return 'OK';
  }
  if(text.includes('validuntil') || text.includes('expired')) {
    return 'EXPIRED';
  }
  if(text.includes('validfrom') || text.includes('not yet valid')) {
    return 'NOT_YET_VALID';
  }
  if(text.includes('invalid signature') || text.includes('verification method') ||
    text.includes('not authorized') || text.includes('proof') ||
    text.includes('challenge') || text.includes('domain')) {
    return 'PROOF';
  }
  return 'MALFORMED';
}

async function verifyCredential({credential, documents, now}) {
  const result = await vc.verifyCredential({
    credential, suite: verifySuite(), documentLoader: makeLoader(documents),
    checkStatus: statusDeferred, now: now ? new Date(now) : undefined
  });
  const messages = result.verified ? [] : describe(result.error);
  return {verified: result.verified, category: classify(messages), messages};
}

async function verifyPresentation({presentation, documents, challenge, domain, now}) {
  const result = await vc.verify({
    presentation, suite: verifySuite(), challenge, domain, checkStatus: statusDeferred,
    documentLoader: makeLoader(documents), now: now ? new Date(now) : undefined
  });
  const messages = [];
  if(!result.verified) {
    messages.push(...describe(result.error));
    for(const r of (result.credentialResults || [])) {
      messages.push(...describe(r.verified ? null : r.error));
    }
    if(result.presentationResult && !result.presentationResult.verified) {
      messages.push(...describe(result.presentationResult.error));
    }
  }
  const unique = [...new Set(messages)];
  return {verified: result.verified, category: classify(unique), messages: unique};
}

async function statusCheck({credential, statusListCredentials, documents}) {
  const all = {...documents};
  for(const list of statusListCredentials) {
    all[list.id] = list;
  }
  try {
    const result = await checkStatus({
      credential, suite: verifySuite(), documentLoader: makeLoader(all),
      verifyBitstringStatusListCredential: true, verifyMatchingIssuers: true
    });
    if(!result.verified) {
      return {verified: false, messages: describe(result.error), statuses: []};
    }
    const statuses = (result.results || []).map(r => ({
      purpose: r.credentialStatus.statusPurpose, status: r.status === true
    }));
    return {verified: true, messages: [], statuses};
  } catch(e) {
    return {verified: false, messages: describe(e), statuses: []};
  }
}

async function issue({document, key, purpose, challenge, domain, created}) {
  const keyPair = await Ed25519Multikey.from({'@context': MULTIKEY_CONTEXT, type: 'Multikey', ...key});
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(), cryptosuite: createSignCryptosuite(), date: created
  });
  const documentLoader = makeLoader({});
  if(purpose === 'authentication') {
    return vc.signPresentation({presentation: document, suite, challenge, domain, documentLoader});
  }
  return vc.issue({credential: document, suite, documentLoader, now: created});
}

const routes = {
  '/verify-credential': verifyCredential,
  '/verify-presentation': verifyPresentation,
  '/check-status': statusCheck,
  '/issue': issue,
  '/health': async () => ({ok: true})
};

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const handler = routes[req.url];
    let status = 200;
    let body;
    try {
      if(!handler) {
        status = 404;
        body = {error: 'unknown route'};
      } else {
        const input = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        body = await handler(input);
      }
    } catch(e) {
      status = 500;
      body = {error: String(e && e.message ? e.message : e)};
    }
    const text = JSON.stringify(body);
    res.writeHead(status, {'content-type': 'application/json', 'content-length': Buffer.byteLength(text)});
    res.end(text);
  });
});

const port = Number(process.argv[2] || 0);
server.listen(port, '127.0.0.1', () => {
  console.log(JSON.stringify({listening: server.address().port}));
});
