// Fixture for test/api-key-internal-defaults.test.js (M-07). Run as its own
// child process (spawned with a fresh DATA_DIR/SECRET, like every other test
// in this repo boots the real server) so it gets a private module registry -
// importing src/lib/apikeys.js (and the src/db.js/src/config.js it pulls in)
// in the shared test-runner process would read whichever DATA_DIR/SECRET env
// happened to be set by the FIRST test file to import that chain, not this
// process's own (see test/route-policy.test.js's header comment).
//
// Calls the INTERNAL createApiKey()/updateApiKey() library functions directly
// with a limits object that omits every allow/scope field - the shape no
// admin-facing caller ever produces (routes/admin.js always runs the request
// through sanitizeLimits() first, which fills in explicit 0/1 values) - and
// prints back the resulting stored scopes as JSON so the test can assert the
// library itself now defaults an omitted field to disabled, not allowed.

import { createApiKey, updateApiKey, getApiKey } from '../../src/lib/apikeys.js';

const created = createApiKey('probe-created', null, {});
const afterCreate = getApiKey(created.id).limits;

// Also exercise updateApiKey with omitted fields, on a key that started out
// full-access - the same deny-by-default should apply to an update, not just
// a create.
const seeded = createApiKey('probe-updated', null, {
	allow_slug: 1,
	allow_password: 1,
	scope_create: 1,
	scope_write: 1,
	scope_read: 1,
	scope_delete: 1,
});
updateApiKey(seeded.id, 'probe-updated', {});
const afterUpdate = getApiKey(seeded.id).limits;

console.log(JSON.stringify({ afterCreate, afterUpdate }));
