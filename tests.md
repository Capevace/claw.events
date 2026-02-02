# Comprehensive Test Cases for claw.events

**Total Estimated Test Cases: 350+**

This document contains every single test case to be implemented, organized by phase and priority.

---

## Legend

- **Priority**: P0 (Critical - Security/Core), P1 (High - Feature), P2 (Medium - Edge Cases), P3 (Low - Nice to Have)
- **Type**: Unit (isolated), Integration (multiple components), E2E (full workflow)
- **Status**: Pending, In Progress, Complete
- **Why**: Explanation of importance

---

## Phase 1: Server Authentication Endpoints

### File: `packages/api/src/auth.test.ts`

#### Test 1.1: POST /auth/init - Happy Path
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { username: "testuser" }
- **Expected**: 200, { username, signature: "claw-sig-...", instructions }
- **Why**: Core auth flow - must work for all registrations
- **Verify**: Signature format starts with "claw-sig-", is base64url, 10 min TTL in Redis

#### Test 1.2: POST /auth/init - Missing Username
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { }
- **Expected**: 400, { error: "username required" }
- **Why**: Input validation prevents abuse

#### Test 1.3: POST /auth/init - Empty Username
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { username: "" }
- **Expected**: 400, { error: "username required" }
- **Why**: Empty strings should be rejected

#### Test 1.4: POST /auth/init - Whitespace-only Username
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { username: "   " }
- **Expected**: 400, { error: "username required" }
- **Why**: Trimming should handle whitespace

#### Test 1.5: POST /auth/init - Very Long Username
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { username: "a".repeat(1000) }
- **Expected**: 200 (or 400 if max length enforced)
- **Why**: Boundary test for username length

#### Test 1.6: POST /auth/init - Special Characters in Username
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { username: "test@user#123" }
- **Expected**: 200 (or 400 if validation enforced)
- **Why**: Determine if special chars allowed in usernames

#### Test 1.7: POST /auth/init - Signature Uniqueness
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: Multiple calls with same username
- **Expected**: Different signatures each time
- **Why**: Prevent signature collision attacks

#### Test 1.8: POST /auth/init - Redis TTL Verification
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: POST { username: "testuser" }
- **Expected**: Redis key authsig:testuser expires in ~600 seconds
- **Why**: Security - signatures must expire

#### Test 1.9: POST /auth/init - Signature Overwrites Previous
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: Two init calls for same username
- **Expected**: Only most recent signature valid
- **Why**: Prevent confusion with multiple pending signatures

---

### Test 2.x: POST /auth/verify

#### Test 2.1: POST /auth/verify - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock MaltBook API to return profile with signature, init auth first
- **Input**: POST { username: "testuser" }
- **Expected**: 200, { token: valid_jwt }
- **Why**: Completes auth flow - critical for access

#### Test 2.2: POST /auth/verify - JWT Token Structure
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: Verify token from successful auth
- **Expected**: HS256 alg, sub: username, issuedAt present, exp: 7 days
- **Why**: Token must have correct claims for authorization

#### Test 2.3: POST /auth/verify - Missing Username
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { }
- **Expected**: 400, { error: "username required" }
- **Why**: Input validation

#### Test 2.4: POST /auth/verify - No Pending Signature
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { username: "nosiguser" } (without calling init first)
- **Expected**: 400, { error: "no pending signature" }
- **Why**: Cannot verify without initiating auth

#### Test 2.5: POST /auth/verify - Expired Signature
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Manually set Redis key with expired TTL or wait 10+ minutes
- **Input**: POST { username: "expireduser" }
- **Expected**: 400, { error: "no pending signature" }
- **Why**: Expired signatures must not work

#### Test 2.6: POST /auth/verify - Signature Not in MaltBook Profile
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock MaltBook to return profile without signature
- **Input**: POST { username: "testuser" }
- **Expected**: 401, { error: "signature not found" }
- **Why**: Must verify signature is actually posted

#### Test 2.7: POST /auth/verify - MaltBook API Key Missing
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Temporarily remove MOLTBOOK_API_KEY env var
- **Input**: POST { username: "testuser" }
- **Expected**: 500, { error: "MOLTBOOK_API_KEY not configured" }
- **Why**: Server config error should be clear

#### Test 2.8: POST /auth/verify - MaltBook API Failure (502)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock MaltBook to return 500 error
- **Input**: POST { username: "testuser" }
- **Expected**: 502, { error: "profile fetch failed (500)" }
- **Why**: External service failures handled gracefully

#### Test 2.9: POST /auth/verify - MaltBook Returns 404
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock MaltBook to return 404 (user not found)
- **Input**: POST { username: "nonexistent" }
- **Expected**: 502, { error: "profile fetch failed (404)" }
- **Why**: User must exist in MaltBook

#### Test 2.10: POST /auth/verify - Redis Cleanup After Success
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Init auth, verify, then check Redis
- **Expected**: authsig:username key deleted after successful verify
- **Why**: Prevent signature reuse (replay attack)

#### Test 2.11: POST /auth/verify - Cannot Reuse Signature
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Init → Verify (success) → Verify again
- **Expected**: Second verify returns 400 (no pending signature)
- **Why**: One-time use signatures

#### Test 2.12: POST /auth/verify - Wrong Username
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Init for user A, try to verify as user B
- **Expected**: 400 (no pending signature for B)
- **Why**: Cannot use A's signature for B

#### Test 2.13: POST /auth/verify - Partial Signature Match
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Post partial signature to MaltBook (e.g., "claw-sig" without random part)
- **Input**: POST { username: "testuser" }
- **Expected**: 401 (signature not found)
- **Why**: Must match entire signature exactly

---

### Test 3.x: POST /auth/dev-register

#### Test 3.1: POST /auth/dev-register - Happy Path
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: CLAW_DEV_MODE=true
- **Input**: POST { username: "devuser" }
- **Expected**: 200, { token: valid_jwt }
- **Why**: Development workflow must work

#### Test 3.2: POST /auth/dev-register - Dev Mode Disabled
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: CLAW_DEV_MODE=false or undefined
- **Input**: POST { username: "devuser" }
- **Expected**: 404, { error: "not available" }
- **Why**: Dev mode should not work in production

#### Test 3.3: POST /auth/dev-register - Missing Username
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Setup**: CLAW_DEV_MODE=true
- **Input**: POST { }
- **Expected**: 400, { error: "username required" }
- **Why**: Input validation

#### Test 3.4: POST /auth/dev-register - Dev Token Same Structure
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Setup**: CLAW_DEV_MODE=true
- **Input**: POST { username: "devuser" }
- **Expected**: Token has same structure as production (HS256, sub, exp, etc.)
- **Why**: Dev tokens should be indistinguishable from prod tokens

---

## Phase 2: Proxy Endpoints (Centrifugo Integration)

### File: `packages/api/src/proxy.test.ts`

#### Test 4.1: POST /proxy/subscribe - Public Channel (public.*)
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "public.townsquare", user: "anyone" }
- **Expected**: 200, { result: {} } (allow)
- **Why**: Public channels should be open to all

#### Test 4.2: POST /proxy/subscribe - Public Channel Anonymous
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "public.test", user: "" }
- **Expected**: 200, { result: {} }
- **Why**: Anonymous users can subscribe to public

#### Test 4.3: POST /proxy/subscribe - System Channel (system.*)
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "system.timer.minute", user: "anyone" }
- **Expected**: 200, { result: {} }
- **Why**: System channels are readable by all

#### Test 4.4: POST /proxy/subscribe - Unlocked Agent Channel
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create agent.alice.updates (do not lock)
- **Input**: POST { channel: "agent.alice.updates", user: "bob" }
- **Expected**: 200, { result: {} }
- **Why**: Unlocked agent channels are publicly readable

#### Test 4.5: POST /proxy/subscribe - Unlocked Agent Channel Anonymous
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.updates", user: "" }
- **Expected**: 200, { result: {} }
- **Why**: Anonymous can subscribe to unlocked agent channels

#### Test 4.6: POST /proxy/subscribe - Locked Agent Channel Owner
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private
- **Input**: POST { channel: "agent.alice.private", user: "alice" }
- **Expected**: 200, { result: {} }
- **Why**: Owner always has access to own locked channels

#### Test 4.7: POST /proxy/subscribe - Locked Agent Channel Granted User
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private, grant bob
- **Input**: POST { channel: "agent.alice.private", user: "bob" }
- **Expected**: 200, { result: {} }
- **Why**: Granted users can subscribe to locked channels

#### Test 4.8: POST /proxy/subscribe - Locked Agent Channel Non-Granted User
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private, do not grant charlie
- **Input**: POST { channel: "agent.alice.private", user: "charlie" }
- **Expected**: 200, { error: { code: 403, message: "permission denied" } }
- **Why**: Non-granted users denied access to locked channels

#### Test 4.9: POST /proxy/subscribe - Locked Agent Channel Anonymous
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private
- **Input**: POST { channel: "agent.alice.private", user: "" }
- **Expected**: 200, { error: { code: 403, message: "permission denied" } }
- **Why**: Anonymous users cannot subscribe to locked channels

#### Test 4.10: POST /proxy/subscribe - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { user: "alice" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: Missing channel should be denied

#### Test 4.11: POST /proxy/subscribe - Invalid Channel Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "invalid-channel", user: "alice" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: Unknown channel formats denied

#### Test 4.12: POST /proxy/subscribe - Agent Channel Wrong Owner
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.bob.test", user: "alice" } (alice trying to access bob's)
- **Expected**: If unlocked: allow. If locked: check grants.
- **Why**: Verify owner extracted correctly from channel name

---

### Test 5.x: POST /proxy/publish

#### Test 5.1: POST /proxy/publish - Public Channel Anyone
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "public.townsquare", user: "anyone" }
- **Expected**: 200, { result: {} }
- **Why**: Anyone can publish to public channels

#### Test 5.2: POST /proxy/publish - System Channel Denied
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "system.timer.minute", user: "alice" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: System channels are server-only for publishing

#### Test 5.3: POST /proxy/publish - Agent Channel Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.updates", user: "alice" }
- **Expected**: 200, { result: {} }
- **Why**: Owner can publish to own agent channels

#### Test 5.4: POST /proxy/publish - Agent Channel Non-Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.updates", user: "bob" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: Non-owners cannot publish to agent channels

#### Test 5.5: POST /proxy/publish - Locked Agent Channel Owner Can Still Publish
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private
- **Input**: POST { channel: "agent.alice.private", user: "alice" }
- **Expected**: 200, { result: {} }
- **Why**: Lock does NOT affect publish permissions

#### Test 5.6: POST /proxy/publish - Locked Agent Channel Non-Owner Still Denied
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private, grant bob subscribe access
- **Input**: POST { channel: "agent.alice.private", user: "bob" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: Grant gives subscribe, not publish access

#### Test 5.7: POST /proxy/publish - Anonymous to Agent Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.updates", user: "" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: Anonymous cannot publish to agent channels

#### Test 5.8: POST /proxy/publish - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { user: "alice" }
- **Expected**: 200, { error: { code: 403 } }
- **Why**: Missing channel denied

---

## Phase 3: Permission Management Endpoints

### File: `packages/api/src/permissions.test.ts` (extends existing)

#### Test 6.1: POST /api/lock - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Authenticate as alice
- **Input**: POST { channel: "agent.alice.private" }, Bearer token
- **Expected**: 200, { ok: true, locked: true, channel }
- **Why**: Owner can lock their channel

#### Test 6.2: POST /api/lock - Redis Key Created
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock channel, check Redis
- **Expected**: Key `locked:alice:private` exists with value "1"
- **Why**: Lock state persisted in Redis

#### Test 6.3: POST /api/lock - No Auth Token
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.private" } (no Authorization header)
- **Expected**: 401, { error: "Missing bearer token" }
- **Why**: Locking requires authentication

#### Test 6.4: POST /api/lock - Invalid Token
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.private" }, Bearer invalid_token
- **Expected**: 401, { error: "..." }
- **Why**: Invalid tokens rejected

#### Test 6.5: POST /api/lock - Non-Owner Tries to Lock
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Authenticate as bob
- **Input**: POST { channel: "agent.alice.private" }, Bearer bob_token
- **Expected**: 403, { error: "can only lock your own channels" }
- **Why**: Cannot lock others' channels

#### Test 6.6: POST /api/lock - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { }, Bearer token
- **Expected**: 400, { error: "channel required" }
- **Why**: Input validation

#### Test 6.7: POST /api/lock - Empty Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "" }, Bearer token
- **Expected**: 400, { error: "channel required" }
- **Why**: Empty channel rejected

#### Test 6.8: POST /api/lock - Invalid Channel Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "invalid" }, Bearer token
- **Expected**: 403, { error: "can only lock your own channels" }
- **Why**: Non-agent channels cannot be locked

#### Test 6.9: POST /api/lock - public.* Channel
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "public.test" }, Bearer token
- **Expected**: 403, { error: "can only lock your own channels" }
- **Why**: Public channels cannot be locked

#### Test 6.10: POST /api/lock - system.* Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "system.timer.test" }, Bearer token
- **Expected**: 403, { error: "can only lock your own channels" }
- **Why**: System channels cannot be locked

#### Test 6.11: POST /api/lock - Already Locked (Idempotent)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock channel twice
- **Expected**: Both return 200 success
- **Why**: Locking should be idempotent

#### Test 6.12: POST /api/lock - Channel Belongs to Different Owner in Name
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Authenticate as alice
- **Input**: POST { channel: "agent.bob.test" }, Bearer alice_token
- **Expected**: 403
- **Why**: Channel name owner must match token owner

---

### Test 7.x: POST /api/unlock

#### Test 7.1: POST /api/unlock - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock then unlock
- **Input**: POST { channel: "agent.alice.private" }, Bearer token
- **Expected**: 200, { ok: true, unlocked: true, channel }
- **Why**: Owner can unlock

#### Test 7.2: POST /api/unlock - Redis Key Deleted
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock, unlock, check Redis
- **Expected**: `locked:alice:private` key removed
- **Why**: Unlock removes lock state

#### Test 7.3: POST /api/unlock - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Requires auth

#### Test 7.4: POST /api/unlock - Non-Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Bob tries to unlock alice's channel
- **Expected**: 403
- **Why**: Cannot unlock others'

#### Test 7.5: POST /api/unlock - Not Locked (Graceful)
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Setup**: Try to unlock channel that was never locked
- **Expected**: 200 (graceful handling) or 400
- **Why**: Should not error on already-unlocked

#### Test 7.6: POST /api/unlock - Grants Remain After Unlock
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock, grant bob, unlock, check Redis
- **Expected**: `perm:alice:private` still exists (but ignored)
- **Why**: Grants persist but are inactive when unlocked

---

### Test 8.x: POST /api/grant

#### Test 8.1: POST /api/grant - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock channel as alice
- **Input**: POST { target: "bob", channel: "agent.alice.private" }, Bearer token
- **Expected**: 200, { ok: true, granted: true, target, channel }
- **Why**: Owner can grant access

#### Test 8.2: POST /api/grant - Redis Set Updated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Grant bob
- **Expected**: `perm:alice:private` set contains "bob"
- **Why**: Grant persisted in Redis

#### Test 8.3: POST /api/grant - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Requires auth

#### Test 8.4: POST /api/grant - Non-Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Bob tries to grant on alice's channel
- **Expected**: 403
- **Why**: Cannot grant on others'

#### Test 8.5: POST /api/grant - Missing Target
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "agent.alice.private" }
- **Expected**: 400, { error: "target and channel required" }
- **Why**: Input validation

#### Test 8.6: POST /api/grant - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { target: "bob" }
- **Expected**: 400
- **Why**: Input validation

#### Test 8.7: POST /api/grant - Grant on Unlocked Channel
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Do not lock, try to grant
- **Expected**: 200 (grant stored but has no effect until locked)
- **Why**: Grants can be created proactively

#### Test 8.8: POST /api/grant - Duplicate Grant (Idempotent)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Grant bob twice
- **Expected**: Both succeed, bob in set only once
- **Why**: Grants idempotent

#### Test 8.9: POST /api/grant - Grant to Self
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Alice grants alice
- **Expected**: 200 (redundant but allowed) or 400
- **Why**: Edge case - owner already has access

#### Test 8.10: POST /api/grant - Multiple Grants
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Grant bob, charlie, dave
- **Expected**: All in `perm:alice:private` set
- **Why**: Multiple grants supported

---

### Test 9.x: POST /api/revoke

#### Test 9.1: POST /api/revoke - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock, grant bob, revoke bob
- **Input**: POST { target: "bob", channel: "agent.alice.private" }
- **Expected**: 200, { ok: true, revoked: true, target, channel }
- **Why**: Owner can revoke access

#### Test 9.2: POST /api/revoke - Redis Set Updated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Grant bob, revoke bob
- **Expected**: "bob" removed from `perm:alice:private`
- **Why**: Revoke persisted

#### Test 9.3: POST /api/revoke - Centrifugo Disconnect Called
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock Centrifugo API, revoke user
- **Expected**: POST to Centrifugo /api with disconnect method
- **Why**: Revoke immediately kicks user

#### Test 9.4: POST /api/revoke - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Requires auth

#### Test 9.5: POST /api/revoke - Non-Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Bob tries to revoke
- **Expected**: 403
- **Why**: Cannot revoke on others'

#### Test 9.6: POST /api/revoke - Target Not Granted (Graceful)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Revoke bob without ever granting
- **Expected**: 200 (graceful)
- **Why**: Should not error if already not granted

#### Test 9.7: POST /api/revoke - Missing Target or Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Expected**: 400
- **Why**: Input validation

---

### Test 10.x: POST /api/request

#### Test 10.1: POST /api/request - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Alice locks channel, bob authenticates
- **Input**: POST { channel: "agent.alice.private", reason: "Need access" }, Bearer bob_token
- **Expected**: 200, { ok: true, message: "Access request sent...", request: {...} }
- **Why**: Users can request access to locked channels

#### Test 10.2: POST /api/request - Publishes to public.access
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock Centrifugo or capture publish
- **Expected**: POST to Centrifugo with channel "public.access"
- **Why**: Request broadcasted publicly

#### Test 10.3: POST /api/request - Request Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Expected payload**: { type: "access_request", requester, targetChannel, targetAgent, reason, timestamp }
- **Why**: Request format standardized for automation

#### Test 10.4: POST /api/request - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Requires auth

#### Test 10.5: POST /api/request - Channel Not Locked
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Try to request unlocked channel
- **Expected**: 400, { error: "channel is not locked, access is public" }
- **Why**: Cannot request access to public channels

#### Test 10.6: POST /api/request - Already Granted
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock, grant bob, bob requests
- **Expected**: 400, { error: "you already have access to this channel" }
- **Why**: Cannot request if already have access

#### Test 10.7: POST /api/request - Own Channel
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Alice requests access to agent.alice.private
- **Expected**: 400 (or graceful error)
- **Why**: Cannot request access to own channel

#### Test 10.8: POST /api/request - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Expected**: 400
- **Why**: Input validation

#### Test 10.9: POST /api/request - Invalid Channel Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "invalid" }
- **Expected**: 400, { error: "invalid channel format" }
- **Why**: Only agent.* channels can be requested

#### Test 10.10: POST /api/request - public.* Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "public.test" }
- **Expected**: 400
- **Why**: Cannot request access to public channels

#### Test 10.11: POST /api/request - system.* Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "system.timer.test" }
- **Expected**: 400
- **Why**: Cannot request access to system channels

#### Test 10.12: POST /api/request - Centrifugo Not Configured
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Remove CENTRIFUGO_API_KEY
- **Expected**: 500, { error: "CENTRIFUGO_API_KEY not configured" }
- **Why**: Cannot send request without Centrifugo

#### Test 10.13: POST /api/request - Centrifugo Publish Fails
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock Centrifugo to return 500
- **Expected**: 502, { error: "failed to send request" }
- **Why**: External failure handling

#### Test 10.14: POST /api/request - Statistics Tracked
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Request access
- **Expected**: Agent tracked, message count incremented
- **Why**: Requests count as messages for stats

---

## Phase 4: Publishing Endpoint

### File: `packages/api/src/publish.test.ts`

#### Test 11.1: POST /api/publish - Public Channel
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Authenticate as alice
- **Input**: POST { channel: "public.test", payload: { msg: "hello" } }
- **Expected**: 200, { ok: true, result: ... }
- **Why**: Can publish to public channels

#### Test 11.2: POST /api/publish - Own Agent Channel
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: POST { channel: "agent.alice.updates", payload: {...} }
- **Expected**: 200
- **Why**: Owner can publish to own channels

#### Test 11.3: POST /api/publish - Centrifugo Publish Called
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock Centrifugo
- **Expected**: POST to Centrifugo /api with publish method
- **Why**: Message forwarded to Centrifugo

#### Test 11.4: POST /api/publish - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Publishing requires auth

#### Test 11.5: POST /api/publish - System Channel
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "system.timer.test" }
- **Expected**: 403, { error: "cannot publish to system channels" }
- **Why**: System channels read-only

#### Test 11.6: POST /api/publish - Non-Owner Agent Channel
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Authenticate as bob
- **Input**: POST { channel: "agent.alice.updates" }
- **Expected**: 403, { error: "only the channel owner can publish to agent.* channels" }
- **Why**: Cannot publish to others' agent channels

#### Test 11.7: POST /api/publish - Locked Channel Still Allows Owner Publish
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private
- **Input**: POST { channel: "agent.alice.private" }
- **Expected**: 200
- **Why**: Lock affects subscribe, not publish

#### Test 11.8: POST /api/publish - Locked Channel Still Denies Non-Owner
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Lock agent.alice.private, authenticate as bob
- **Input**: POST { channel: "agent.alice.private" }
- **Expected**: 403
- **Why**: Grant gives subscribe, not publish

#### Test 11.9: POST /api/publish - Rate Limit Redis Key Created
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: First publish request
- **Expected**: 200, Redis key ratelimit:alice created with 1s TTL
- **Why**: Rate limit tracking initialized

#### Test 11.10: POST /api/publish - Rate Limit 6th Request Within 1s
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Publish 5 times, then try to publish again within 1s
- **Expected**: 429, { error: "rate limit exceeded...", retry_after, retry_timestamp }
- **Why**: Rate limit enforced after 5 requests per second

#### Test 11.11: POST /api/publish - Rate Limit Resets After 1s
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Publish 5 times, wait 1+ seconds, publish again
- **Expected**: 200
- **Why**: Rate limit resets after 1 second window

#### Test 11.12: POST /api/publish - Rate Limit retry_after Accuracy
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Publish 5 times, try to publish again immediately
- **Expected**: retry_after between 0-1 seconds (approx)
- **Why**: Client needs accurate retry timing

#### Test 11.13: POST /api/publish - Rate Limit Different Users Independent
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Alice publishes, immediately Bob publishes
- **Expected**: Both succeed (different rate limit keys)
- **Why**: Rate limits per user, not global

#### Test 11.14: POST /api/publish - Payload Size Under Limit (16KB)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: payload ~15KB
- **Expected**: 200
- **Why**: Within limits accepted

#### Test 11.15: POST /api/publish - Payload Size At Limit (16KB)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: payload exactly 16384 bytes
- **Expected**: 200 or 413 (boundary test)
- **Why**: Test exact boundary

#### Test 11.16: POST /api/publish - Payload Size Over Limit (16KB)
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: payload >16KB
- **Expected**: 413, { error: "payload too large (max 16384 bytes)" }
- **Why**: Payload limits enforced

#### Test 11.17: POST /api/publish - Empty Payload (Null)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: POST { channel: "public.test", payload: null }
- **Expected**: 200
- **Why**: Null payload allowed

#### Test 11.18: POST /api/publish - No Payload Field
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: POST { channel: "public.test" }
- **Expected**: 200
- **Why**: Payload optional

#### Test 11.19: POST /api/publish - Invalid Channel Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "invalid" }
- **Expected**: 400, { error: "invalid channel format" }
- **Why**: Channel format validation

#### Test 11.20: POST /api/publish - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { payload: {...} }
- **Expected**: 400, { error: "channel required" }
- **Why**: Channel required

#### Test 11.21: POST /api/publish - Centrifugo Not Configured
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Remove CENTRIFUGO_API_KEY
- **Expected**: 500, { error: "CENTRIFUGO_API_KEY not configured" }
- **Why**: Cannot publish without Centrifugo

#### Test 11.22: POST /api/publish - Centrifugo Publish Fails
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Mock Centrifugo to return 500
- **Expected**: 502, { error: "centrifugo publish failed" }
- **Why**: External failure handling

#### Test 11.23: POST /api/publish - Statistics Tracked
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Clear stats, publish message
- **Expected**: stats:agents includes alice, stats:total_messages incremented, per-minute bucket incremented
- **Why**: Stats tracking verified

#### Test 11.24: POST /api/publish - Circular JSON Payload
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Input**: POST with circular object (if possible in JSON)
- **Expected**: 400 or handled gracefully
- **Why**: Edge case - malformed JSON

---

## Phase 5: Channel Advertising Endpoints

### File: `packages/api/src/advertise.test.ts`

#### Test 12.1: POST /api/advertise - Happy Path with Description
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Authenticate as alice
- **Input**: POST { channel: "agent.alice.updates", description: "My updates" }
- **Expected**: 200, { ok: true, data: {...} }
- **Why**: Can advertise channel

#### Test 12.2: POST /api/advertise - With Schema
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: POST { channel, description, schema: { type: "object" } }
- **Expected**: 200, schema stored
- **Why**: Can document channel schema

#### Test 12.3: POST /api/advertise - Redis Storage
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create advertisement
- **Expected**: Key `advertise:alice:updates` with JSON value
- **Why**: Persisted in Redis

#### Test 12.4: POST /api/advertise - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Requires auth

#### Test 12.5: POST /api/advertise - Non-Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Bob tries to advertise alice's channel
- **Expected**: 403, { error: "can only advertise your own channels" }
- **Why**: Cannot advertise others'

#### Test 12.6: POST /api/advertise - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Expected**: 400
- **Why**: Input validation

#### Test 12.7: POST /api/advertise - Invalid Channel Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel: "invalid" }
- **Expected**: 403
- **Why**: Non-agent channels cannot be advertised

#### Test 12.8: POST /api/advertise - Description Too Long (>5000)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: description = "a".repeat(5001)
- **Expected**: 413, { error: "description too long (max 5000 chars)" }
- **Why**: Size limits enforced

#### Test 12.9: POST /api/advertise - Description At Limit (5000)
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Input**: description = "a".repeat(5000)
- **Expected**: 200 (boundary test)
- **Why**: Exact boundary

#### Test 12.10: POST /api/advertise - Invalid Description Type
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: POST { channel, description: 123 }
- **Expected**: 400, { error: "description must be a string" }
- **Why**: Type validation

#### Test 12.11: POST /api/advertise - Schema Too Large (>32KB)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: schema = large object >32768 bytes when JSON.stringify'd
- **Expected**: 413, { error: "schema too large (max 32768 bytes)" }
- **Why**: Schema size limits

#### Test 12.12: POST /api/advertise - Updates Existing
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Create advertisement, then update with different description
- **Expected**: 200, Redis key updated with new value
- **Why**: Updates work like create

---

### Test 13.x: DELETE /api/advertise

#### Test 13.1: DELETE /api/advertise - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create, then delete
- **Input**: DELETE { channel: "agent.alice.updates" }
- **Expected**: 200, { ok: true, removed: true }
- **Why**: Can remove advertisement

#### Test 13.2: DELETE /api/advertise - Redis Key Deleted
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create, delete, check Redis
- **Expected**: Key `advertise:alice:updates` removed
- **Why**: Cleanup verified

#### Test 13.3: DELETE /api/advertise - No Auth
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Expected**: 401
- **Why**: Requires auth

#### Test 13.4: DELETE /api/advertise - Non-Owner
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Bob tries to delete alice's advertisement
- **Expected**: 403
- **Why**: Cannot delete others'

#### Test 13.5: DELETE /api/advertise - Not Found (Graceful)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Try to delete non-existent advertisement
- **Expected**: 200 (or 404 if strict)
- **Why**: Graceful handling

---

### Test 14.x: GET /api/advertise/search

#### Test 14.1: GET /api/advertise/search - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create several advertisements
- **Input**: GET /api/advertise/search?q=updates
- **Expected**: 200, { ok: true, query, count, total, results: [...] }
- **Why**: Can search channels

#### Test 14.2: GET /api/advertise/search - By Channel Name
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create "agent.alice.updates", "agent.bob.data"
- **Input**: GET ?q=alice
- **Expected**: Results include alice's channel
- **Why**: Search by agent name

#### Test 14.3: GET /api/advertise/search - By Description
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create with description "weather station data"
- **Input**: GET ?q=weather
- **Expected**: Results include weather channel
- **Why**: Search by description

#### Test 14.4: GET /api/advertise/search - Case Insensitive
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Create "agent.Alice.Updates"
- **Input**: GET ?q=alice (lowercase)
- **Expected**: Results include Alice's channel
- **Why**: Case-insensitive search

#### Test 14.5: GET /api/advertise/search - Missing Query
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: GET /api/advertise/search
- **Expected**: 400, { error: "search query required (use ?q=<query>)" }
- **Why**: Query required

#### Test 14.6: GET /api/advertise/search - Empty Query
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: GET ?q=
- **Expected**: 400
- **Why**: Empty query rejected

#### Test 14.7: GET /api/advertise/search - Limit Parameter
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Create 25 advertisements
- **Input**: GET ?q=test&limit=10
- **Expected**: Results length <= 10
- **Why**: Limit enforced

#### Test 14.8: GET /api/advertise/search - Default Limit (20)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Create 25 advertisements
- **Input**: GET ?q=test (no limit)
- **Expected**: Results length <= 20
- **Why**: Default limit applied

#### Test 14.9: GET /api/advertise/search - Max Limit (100)
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: GET ?q=test&limit=200
- **Expected**: Results length <= 100 (or limited to 100)
- **Why**: Max limit enforced

#### Test 14.10: GET /api/advertise/search - No Results
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: GET ?q=nonexistentxyz123
- **Expected**: 200, { count: 0, results: [] }
- **Why**: Empty results handled

#### Test 14.11: GET /api/advertise/search - Sorted by updatedAt
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Create ads with delays
- **Expected**: Results sorted newest first
- **Why**: Recent channels first

---

### Test 15.x: GET /api/advertise/list

#### Test 15.1: GET /api/advertise/list - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create several advertisements
- **Expected**: 200, { ok: true, channels: [...], count }
- **Why**: Can list all channels

#### Test 15.2: GET /api/advertise/list - Empty List
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Clear all advertisements
- **Expected**: 200, { channels: [], count: 0 }
- **Why**: Empty list handled

#### Test 15.3: GET /api/advertise/list - Sorted by updatedAt
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Expected**: Newest first
- **Why**: Sorting verified

---

### Test 16.x: GET /api/advertise/:agent

#### Test 16.1: GET /api/advertise/:agent - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create alice's advertisements
- **Input**: GET /api/advertise/alice
- **Expected**: 200, { ok: true, agent: "alice", advertisements: [...] }
- **Why**: Can list agent's channels

#### Test 16.2: GET /api/advertise/:agent - Empty Result
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: GET /api/advertise/nonexistent
- **Expected**: 200, { advertisements: [] }
- **Why**: No advertisements = empty array

---

### Test 17.x: GET /api/advertise/:agent/:topic

#### Test 17.1: GET /api/advertise/:agent/:topic - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create alice's updates channel
- **Input**: GET /api/advertise/alice/updates
- **Expected**: 200, { ok: true, channel, description, schema, updatedAt }
- **Why**: Can get specific channel details

#### Test 17.2: GET /api/advertise/:agent/:topic - Not Found
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Input**: GET /api/advertise/alice/nonexistent
- **Expected**: 404, { error: "not found" }
- **Why**: 404 for non-existent

#### Test 17.3: GET /api/advertise/:agent/:topic - Multi-part Topic
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Create "agent.alice.data.sensor1"
- **Input**: GET /api/advertise/alice/data.sensor1
- **Expected**: 200
- **Why**: Multi-part topics work

---

## Phase 6: Profile and Locks Endpoints

### File: `packages/api/src/profile.test.ts`

#### Test 18.1: GET /api/profile/:agent - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Create alice's advertisements
- **Input**: GET /api/profile/alice
- **Expected**: 200, { ok: true, agent, channels: [...], count }
- **Why**: Can view agent profile

#### Test 18.2: GET /api/profile/:agent - Empty Profile
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: GET /api/profile/newuser
- **Expected**: 200, { channels: [] }
- **Why**: New agents have empty profile

#### Test 18.3: GET /api/profile/:agent - Sorted by updatedAt
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Expected**: Newest channels first
- **Why**: Sorting verified

---

### File: `packages/api/src/locks.test.ts`

#### Test 19.1: GET /api/locks/:agent - Happy Path
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Alice locks several channels
- **Input**: GET /api/locks/alice
- **Expected**: 200, { ok: true, agent, lockedChannels: [...], count }
- **Why**: Can list locked channels

#### Test 19.2: GET /api/locks/:agent - No Locked Channels
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: GET /api/locks/newuser
- **Expected**: 200, { lockedChannels: [] }
- **Why**: Empty result handled

#### Test 19.3: GET /api/locks/:agent - Full Channel Names
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Expected**: lockedChannels = ["agent.alice.private1", "agent.alice.private2"]
- **Why**: Returns full channel names

---

## Phase 7: Utility Endpoints

### File: `packages/api/src/utils.test.ts`

#### Test 20.1: GET /health - Returns OK
**Priority**: P2 | **Type**: Unit | **Status**: Pending
- **Expected**: 200, { ok: true }
- **Why**: Health check for monitoring

#### Test 20.2: GET /health - No Auth Required
**Priority**: P2 | **Type**: Unit | **Status**: Pending
- **Expected**: Works without any token
- **Why**: Public endpoint

#### Test 20.3: GET /og.jpeg - Returns Image
**Priority**: P3 | **Type**: Unit | **Status**: Pending
- **Expected**: 200, Content-Type: image/jpeg
- **Why**: OpenGraph image served

#### Test 20.4: GET /og.jpeg - Cache Headers
**Priority**: P3 | **Type**: Unit | **Status**: Pending
- **Expected**: Cache-Control header present
- **Why**: Caching configured

#### Test 20.5: GET /og.jpeg - Not Found Handling
**Priority**: P3 | **Type**: Unit | **Status**: Pending
- **Setup**: Remove og.jpeg file
- **Expected**: 404
- **Why**: Graceful 404

#### Test 20.6: GET / (homepage) - Returns HTML
**Priority**: P3 | **Type**: Integration | **Status**: Pending
- **Expected**: 200, HTML content
- **Why**: Homepage served

#### Test 20.7: GET / - Stats Included
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Expected**: HTML contains stats placeholders
- **Why**: Stats displayed

#### Test 20.8: GET /docs - Returns Documentation
**Priority**: P3 | **Type**: Unit | **Status**: Pending
- **Expected**: 200, HTML documentation
- **Why**: Docs served

---

## Phase 8: Security and Edge Cases

### File: `packages/api/src/security.test.ts`

#### Test 21.1: JWT Token - Expired Token Rejected
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Create expired token (exp in past)
- **Expected**: 401 on protected endpoint
- **Why**: Expired tokens invalid

#### Test 21.2: JWT Token - Wrong Signature
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Create token with wrong secret
- **Expected**: 401
- **Why**: Invalid signature rejected

#### Test 21.3: JWT Token - Tampered Payload
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Modify payload of valid token
- **Expected**: 401
- **Why**: Tampering detected

#### Test 21.4: JWT Token - Malformed Token
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Send "not.a.token" as Bearer
- **Expected**: 401
- **Why**: Malformed rejected

#### Test 21.5: JWT Token - Missing Bearer Prefix
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Setup**: Send raw token without "Bearer " prefix
- **Expected**: 401
- **Why**: Must use Bearer scheme

#### Test 21.6: JWT Token - User A Token for User B Operations
**Priority**: P0 | **Type**: Unit | **Status**: Pending
- **Setup**: Use alice's token for bob's channel operations
- **Expected**: 403 (owner check fails)
- **Why**: Token scoped to user

#### Test 21.7: Injection - SQL in Channel Name
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: channel: "agent.alice.'; DROP TABLE users; --"
- **Expected**: 403 or 400 (not executed)
- **Why**: SQL injection prevention

#### Test 21.8: Injection - NoSQL in Redis Keys
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Input**: username: "alice{$ne:null}"
- **Expected**: Redis key literal, no injection
- **Why**: NoSQL injection prevention

#### Test 21.9: Injection - XSS in Description
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: description: "<script>alert('xss')</script>"
- **Expected**: Stored literally or escaped
- **Why**: XSS prevention

#### Test 21.10: Path Traversal - Double Dot in Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Input**: channel: "agent.alice/../../../etc/passwd"
- **Expected**: Rejected or literal (no file access)
- **Why**: Path traversal prevention

#### Test 21.11: Null Bytes in Strings
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Input**: username: "alice\x00injected"
- **Expected**: Rejected or handled
- **Why**: Null byte injection prevention

#### Test 21.12: Unicode - Emoji in Username
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Input**: username: "test😀user"
- **Expected**: 200 or 400 (depends on support)
- **Why**: Unicode handling

#### Test 21.13: Unicode - Right-to-Left Characters
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Input**: username with RTL override characters
- **Expected**: Handled safely
- **Why**: RTL injection prevention

#### Test 21.14: Unicode - Confusable Characters
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Input**: username with homoglyphs (а vs a - Cyrillic vs Latin)
- **Expected**: Treated as different users
- **Why**: Unicode confusables

---

## Phase 9: CLI Tool - Global Options

### File: `packages/cli/src/global-options.test.ts`

#### Test 22.1: --config with Custom File
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events --config /tmp/myconfig.json whoami`
- **Expected**: Uses /tmp/myconfig.json
- **Why**: Custom config file works

#### Test 22.2: --config with Custom Directory
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events --config /tmp/mydir whoami`
- **Expected**: Uses /tmp/mydir/config.json
- **Why**: Custom config directory works

#### Test 22.3: --config Creates Directory
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events --config /tmp/newdir/subdir config --server http://test`
- **Expected**: Directories created, config saved
- **Why**: Auto-creation

#### Test 22.4: --config Falls Back to Default
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events whoami` (no --config)
- **Expected**: Uses ~/.config/.claw.events/config.json
- **Why**: Default path works

#### Test 22.5: --server Overrides Config
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Config has serverA, use --server serverB
- **Command**: `claw.events --server serverB whoami`
- **Expected**: Shows serverB
- **Why**: CLI flag overrides config

#### Test 22.6: --server Derives WS URL (HTTPS)
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `--server https://example.com`
- **Expected**: WS URL = wss://example.com/connection/websocket
- **Why**: WS derived correctly

#### Test 22.7: --server Derives WS URL (HTTP)
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `--server http://localhost:3000`
- **Expected**: WS URL = ws://localhost:3000/connection/websocket
- **Why**: WS derived correctly

#### Test 22.8: --token Overrides Config
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Config has tokenA, use --token tokenB
- **Command**: `claw.events --token tokenB whoami`
- **Expected**: Authenticated with tokenB
- **Why**: CLI flag overrides config

#### Test 22.9: --token Not Saved to Config
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events --token newtoken pub test hello`
- **Verify**: Config file still has old token
- **Why**: Temporary override only

#### Test 22.10: Global Options with Invalid Config Path
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events --config /nonexistent/read-only/ config --show`
- **Expected**: Error about unable to write config
- **Why**: Invalid paths handled

---

## Phase 10: CLI Authentication Commands

### File: `packages/cli/src/auth-commands.test.ts`

#### Test 23.1: login --user - Initiates Auth
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events login --user testuser`
- **Expected**: JSON output with username, signature, instructions
- **Why**: Auth flow starts

#### Test 23.2: login --user - Saves Username to Config
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events login --user testuser`
- **Verify**: Config file has username: "testuser"
- **Why**: Username persisted

#### Test 23.3: login --user - Network Error Handling
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Server unreachable
- **Command**: `claw.events login --user testuser`
- **Expected**: Error JSON with fixes array
- **Why**: Network failures handled

#### Test 23.4: login --user - Missing Username
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events login`
- **Expected**: Error: "Missing --user or --token flag"
- **Why**: Validation

#### Test 23.5: login --token - Saves Token
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events login --token eyJ...`
- **Verify**: Config has token
- **Why**: Direct token save works

#### Test 23.6: login --token with Username
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Command**: `claw.events login --user test --token eyJ...`
- **Verify**: Config has both username and token
- **Why**: Both saved

#### Test 23.7: verify - Completes Auth Flow
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: login first (mock MaltBook), verify
- **Command**: `claw.events verify`
- **Expected**: Success JSON with token saved
- **Why**: Auth completes

#### Test 23.8: verify - No Username in Config
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Clear username from config
- **Command**: `claw.events verify`
- **Expected**: Error: "No username found in configuration"
- **Why**: Need username to verify

#### Test 23.9: verify - No Pending Signature
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Never call login, or wait for expiry
- **Command**: `claw.events verify`
- **Expected**: Error: "Authentication verification failed"
- **Why**: No signature to verify

#### Test 23.10: verify - Signature Not in MaltBook
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Login but don't post signature
- **Command**: `claw.events verify`
- **Expected**: Error about signature not found
- **Why**: Verification requires signature in profile

#### Test 23.11: dev-register --user - Dev Mode Success
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Server in dev mode
- **Command**: `claw.events dev-register --user devuser`
- **Expected**: Success JSON with token
- **Why**: Dev registration works

#### Test 23.12: dev-register --user - Production Mode Rejected
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Server in production mode
- **Command**: `claw.events dev-register --user devuser`
- **Expected**: Error: "Dev registration failed: not available"
- **Why**: Dev mode only

#### Test 23.13: dev-register --user - Missing Username
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events dev-register`
- **Expected**: Error: "Missing --user flag"
- **Why**: Validation

#### Test 23.14: whoami - Authenticated State
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Login with token
- **Command**: `claw.events whoami`
- **Expected**: JSON with authenticated: true, username, serverUrl
- **Why**: Shows auth status

#### Test 23.15: whoami - Not Authenticated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Logout or fresh install
- **Command**: `claw.events whoami`
- **Expected**: JSON with authenticated: false
- **Why**: Shows unauthenticated

#### Test 23.16: whoami - Detects --token Override
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Config has no token, use --token
- **Command**: `claw.events --token eyJ... whoami`
- **Expected**: authenticated: true
- **Why**: CLI flag detected

#### Test 23.17: logout - Clears Auth
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Login first
- **Command**: `claw.events logout`
- **Verify**: Config has no token, no username
- **Why**: Auth cleared

#### Test 23.18: logout - Already Logged Out
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Fresh install
- **Command**: `claw.events logout`
- **Expected**: "Already logged out" message
- **Why**: Graceful handling

---

## Phase 11: CLI Publishing Commands

### File: `packages/cli/src/publish-commands.test.ts`

#### Test 24.1: pub - String Message
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events pub public.townsquare "hello world"`
- **Expected**: Success JSON
- **Why**: Basic publish works

#### Test 24.2: pub - JSON Message Auto-Parsed
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events pub agent.test.data '{"key":"value"}'`
- **Expected**: Success, JSON parsed and sent
- **Why**: JSON messages work

#### Test 24.3: pub - No Message (Null Payload)
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events pub public.townsquare`
- **Expected**: Success, null payload
- **Why**: Empty publish works

#### Test 24.4: pub - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events pub`
- **Expected**: Error: "Missing channel parameter"
- **Why**: Validation

#### Test 24.5: pub - Not Authenticated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Logout
- **Command**: `claw.events pub agent.test.data hello`
- **Expected**: Error: "Authentication required"
- **Why**: Auth enforced

#### Test 24.6: pub - Rate Limited (429)
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Publish twice within 5 seconds
- **Command**: Second publish
- **Expected**: Error with retry_after, retry_timestamp
- **Why**: Rate limit shown

#### Test 24.7: pub - Permission Denied (403)
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Try to publish to another's agent channel
- **Command**: `claw.events pub agent.other.data hello`
- **Expected**: Error about permission
- **Why**: Auth enforced

#### Test 24.8: pub - System Channel Denied
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events pub system.timer.test hello`
- **Expected**: Error: "cannot publish to system channels"
- **Why**: System channels protected

#### Test 24.9: pub - Network Error
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Server unreachable
- **Command**: `claw.events pub public.test hello`
- **Expected**: Error with network fixes
- **Why**: Network failures handled

#### Test 24.10: validate - With Inline Schema (Valid)
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events validate '{"temp":25}' --schema '{"type":"object"}'`
- **Expected**: JSON output to stdout (for piping)
- **Why**: Validation passes

#### Test 24.11: validate - With Inline Schema (Invalid)
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events validate '{"temp":"hot"}' --schema '{"type":"object","properties":{"temp":{"type":"number"}}}'`
- **Expected**: Error with validation details
- **Why**: Validation fails correctly

#### Test 24.12: validate - From Channel Schema
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: Advertise channel with schema
- **Command**: `claw.events validate '{"temp":25}' --channel agent.test.data`
- **Expected**: Uses channel's schema
- **Why**: Channel schema fetched

#### Test 24.13: validate - From Stdin
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `echo '{"temp":25}' | claw.events validate --schema '{...}'`
- **Expected**: Validates stdin input
- **Why**: Pipe support

#### Test 24.14: validate - No Data
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events validate --schema '{"type":"object"}'`
- **Expected**: Error: "No input data provided"
- **Why**: Validation requires data

#### Test 24.15: validate - Invalid JSON Input
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events validate 'not json' --schema '{...}'`
- **Expected**: Error about invalid JSON
- **Why**: JSON parsing errors handled

#### Test 24.16: validate - Invalid Schema JSON
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events validate '{"a":1}' --schema 'not json'`
- **Expected**: Error about invalid schema
- **Why**: Schema must be valid JSON

#### Test 24.17: validate - No Schema (Pass Through)
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events validate '{"a":1}'`
- **Expected**: Data passes through unchanged
- **Why**: Schema optional

---

## Phase 12: CLI Subscription Commands

### File: `packages/cli/src/subscription-commands.test.ts`

#### Test 25.1: sub - Single Channel
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events sub public.townsquare` (timeout after 5s)
- **Expected**: Connects, outputs JSON messages
- **Why**: Subscribe works

#### Test 25.2: sub - Multiple Channels
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events sub public.test agent.test.data`
- **Expected**: Subscribes to both
- **Why**: Multiple channels work

#### Test 25.3: sub - No Authentication Required
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Logout
- **Command**: `claw.events sub public.townsquare`
- **Expected**: Works without auth
- **Why**: Subscribe is public

#### Test 25.4: sub - Locked Channel Denied
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Lock agent.alice.private, no grant
- **Command**: `claw.events sub agent.alice.private`
- **Expected**: Error or disconnect
- **Why**: Locked channels protected

#### Test 25.5: sub - Locked Channel With Grant
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Lock, grant bob
- **Command**: `claw.events --token bob_token sub agent.alice.private`
- **Expected**: Success
- **Why**: Granted access works

#### Test 25.6: sub - Verbose Mode
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events sub --verbose public.test`
- **Expected**: Connection info on stderr
- **Why**: Debug output

#### Test 25.7: sub - No Channels Specified
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events sub`
- **Expected**: Error: "No channels specified"
- **Why**: Validation

#### Test 25.8: sub - Connection Failure
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Wrong WS URL
- **Command**: `claw.events --server http://invalid sub public.test`
- **Expected**: Error on stderr, exit 1
- **Why**: Connection errors handled

#### Test 25.9: sub - Output Format
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: Publish message, receive
- **Expected**: Output: { channel, sender, payload, timestamp }
- **Why**: Format correct

#### Test 25.10: subexec - Immediate Mode
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events subexec public.test -- echo "Received:"`
- **Expected**: Echo runs on each message
- **Why**: Immediate execution works

#### Test 25.11: subexec - With Buffer
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events subexec --buffer 3 public.test -- ./process.sh`
- **Setup**: Publish 3 messages
- **Expected**: process.sh called once with batch of 3
- **Why**: Buffering works

#### Test 25.12: subexec - With Timeout (Debounce)
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events subexec --timeout 2000 public.test -- ./process.sh`
- **Setup**: Publish 1 message, wait 2s
- **Expected**: process.sh called after 2s
- **Why**: Debouncing works

#### Test 25.13: subexec - Buffer and Timeout Combined
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events subexec --buffer 5 --timeout 3000 public.test -- ./process.sh`
- **Setup**: Publish 3 messages, wait 3s
- **Expected**: Executed after timeout with 3 messages
- **Why**: Whichever comes first

#### Test 25.14: subexec - Missing -- Separator
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events subexec public.test echo hello`
- **Expected**: Error: "Missing -- separator"
- **Why**: Separator required

#### Test 25.15: subexec - No Command After --
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events subexec public.test --`
- **Expected**: Error: "No command specified after --"
- **Why**: Command required

#### Test 25.16: subexec - No Channels
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events subexec -- echo hello`
- **Expected**: Error: "No channels specified"
- **Why**: Channels required

#### Test 25.17: subexec - Batch Event Format
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: subexec with --buffer 2
- **Expected**: Script receives: { batch: true, count: 2, messages: [...], timestamp }
- **Why**: Batch format correct

#### Test 25.18: subexec - Invalid Buffer Value
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events subexec --buffer 0 public.test -- echo`
- **Expected**: Error: "Invalid --buffer value"
- **Why**: Validation

#### Test 25.19: subexec - Invalid Timeout Value
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events subexec --timeout -1 public.test -- echo`
- **Expected**: Error: "Invalid --timeout value"
- **Why**: Validation

#### Test 25.20: subexec - Command Execution Error
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events subexec public.test -- /nonexistent/command`
- **Expected**: Error logged to stderr, continues running
- **Why**: Command errors handled

---

## Phase 13: CLI Permission Commands

### File: `packages/cli/src/permission-commands.test.ts`

#### Test 26.1: lock - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events lock agent.test.private`
- **Expected**: Success JSON
- **Why**: Lock works

#### Test 26.2: lock - Not Authenticated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Setup**: Logout
- **Command**: `claw.events lock agent.test.private`
- **Expected**: Error: "Authentication required"
- **Why**: Auth required

#### Test 26.3: lock - Non-Owner
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events lock agent.other.private`
- **Expected**: Error: "can only lock your own channels"
- **Why**: Ownership enforced

#### Test 26.4: lock - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events lock`
- **Expected**: Error: "Missing channel parameter"
- **Why**: Validation

#### Test 26.5: unlock - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events unlock agent.test.private`
- **Expected**: Success
- **Why**: Unlock works

#### Test 26.6: unlock - Not Locked (Graceful)
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: Channel not locked
- **Command**: `claw.events unlock agent.test.neverlocked`
- **Expected**: Success (graceful) or error
- **Why**: Graceful handling

#### Test 26.7: grant - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events grant bob agent.test.private`
- **Expected**: Success
- **Why**: Grant works

#### Test 26.8: grant - Not Authenticated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Expected**: Error: "Authentication required"
- **Why**: Auth required

#### Test 26.9: grant - Non-Owner
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events grant bob agent.other.private`
- **Expected**: Error about ownership
- **Why**: Ownership enforced

#### Test 26.10: grant - Missing Target or Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events grant`
- **Expected**: Error about missing parameters
- **Why**: Validation

#### Test 26.11: revoke - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Grant bob first
- **Command**: `claw.events revoke bob agent.test.private`
- **Expected**: Success
- **Why**: Revoke works

#### Test 26.12: revoke - Not Granted (Graceful)
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: Never granted bob
- **Command**: `claw.events revoke bob agent.test.private`
- **Expected**: Success (graceful)
- **Why**: Graceful handling

#### Test 26.13: request - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Alice locks channel, bob requests
- **Command**: `claw.events request agent.alice.private "Need for work"`
- **Expected**: Success, publishes to public.access
- **Why**: Request works

#### Test 26.14: request - Not Authenticated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Expected**: Error: "Authentication required"
- **Why**: Auth required

#### Test 26.15: request - Channel Not Locked
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Channel unlocked
- **Command**: `claw.events request agent.alice.public`
- **Expected**: Error: "channel is not locked"
- **Why**: Cannot request public channels

#### Test 26.16: request - Already Granted
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Setup**: Lock, grant bob, bob requests
- **Expected**: Error: "you already have access"
- **Why**: Cannot request if have access

---

## Phase 14: CLI Advertising Commands

### File: `packages/cli/src/advertising-commands.test.ts`

#### Test 27.1: advertise set - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise set --channel agent.test.data --desc "Test data"`
- **Expected**: Success
- **Why**: Advertise works

#### Test 27.2: advertise set - With Schema
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise set -c agent.test.data -d "Test" -s '{"type":"object"}'`
- **Expected**: Success, schema stored
- **Why**: Schema included

#### Test 27.3: advertise set - Not Authenticated
**Priority**: P0 | **Type**: Integration | **Status**: Pending
- **Expected**: Error: "Authentication required"
- **Why**: Auth required

#### Test 27.4: advertise set - Non-Owner
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise set -c agent.other.data -d "Test"`
- **Expected**: Error about ownership
- **Why**: Ownership enforced

#### Test 27.5: advertise set - Missing Channel
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events advertise set --desc "Test"`
- **Expected**: Error: "Missing --channel parameter"
- **Why**: Validation

#### Test 27.6: advertise delete - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise delete agent.test.data`
- **Expected**: Success
- **Why**: Delete works

#### Test 27.7: advertise list - All Channels
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise list`
- **Expected**: List including system channels + advertised
- **Why**: List works

#### Test 27.8: advertise list - Specific Agent
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise list alice`
- **Expected**: Alice's channels only
- **Why**: Agent filtering works

#### Test 27.9: advertise search - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise search weather`
- **Expected**: Results with weather-related channels
- **Why**: Search works

#### Test 27.10: advertise search - With Limit
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise search test --limit 5`
- **Expected**: Max 5 results
- **Why**: Limit works

#### Test 27.11: advertise search - No Results
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise search xyznonexistent`
- **Expected**: "No channels found" message
- **Why**: Empty results handled

#### Test 27.12: advertise show - Happy Path
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise show agent.test.data`
- **Expected**: Channel details JSON
- **Why**: Show works

#### Test 27.13: advertise show - Not Found
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Command**: `claw.events advertise show agent.nonexistent.data`
- **Expected**: Error: "No advertisement found"
- **Why**: 404 handled

#### Test 27.14: advertise show - Invalid Channel Format
**Priority**: P1 | **Type**: Unit | **Status**: Pending
- **Command**: `claw.events advertise show invalid`
- **Expected**: Error about invalid format
- **Why**: Format validation

---

## Phase 15: E2E Integration Tests

### File: `packages/api/src/e2e.test.ts`

#### Test 28.1: Full Auth Flow - Production
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. login --user test → get signature
  2. Mock MaltBook with signature
  3. verify → get token
  4. whoami → confirm authenticated
  5. pub → publish works
  6. logout → auth cleared
- **Why**: Complete auth workflow

#### Test 28.2: Full Auth Flow - Dev Mode
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. dev-register --user dev → get token
  2. whoami → confirm
  3. pub → works
  4. logout → cleared
- **Why**: Dev workflow

#### Test 28.3: Full Permission Workflow
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. Alice locks agent.alice.private
  2. Bob tries subscribe → denied
  3. Bob requests access
  4. Alice grants bob
  5. Bob subscribes → success
  6. Alice revokes bob
  7. Bob disconnected
- **Why**: Complete permission workflow

#### Test 28.4: Channel Discovery and Subscribe
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. Alice advertises channel with schema
  2. Bob searches for alice
  3. Bob views advertisement
  4. Bob subscribes
  5. Alice publishes
  6. Bob receives
- **Why**: Discovery workflow

#### Test 28.5: Multi-Agent Setup
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. Register 3 agents (A, B, C)
  2. A locks channel, grants B
  3. B subscribes, C denied
  4. C requests, A grants C
  5. C can now subscribe
- **Why**: Multi-user scenario

#### Test 28.6: Pub/Sub Integration
**Priority**: P0 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. Subscribe to channel in background
  2. Publish message
  3. Verify received
- **Why**: Basic pub/sub works

#### Test 28.7: Multiple Subscribers
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. 3 clients subscribe
  2. 1 publish
  3. All 3 receive
- **Why**: Broadcast works

#### Test 28.8: Rate Limit Recovery
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. Publish
  2. Immediately try again → rate limited
  3. Wait 5s
  4. Publish again → success
- **Why**: Rate limit recovers

#### Test 28.9: Batch Processing with subexec
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. subexec with --buffer 5
  2. Publish 5 messages
  3. Verify batch received with count: 5
- **Why**: Buffering works end-to-end

#### Test 28.10: Schema Validation Pipeline
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Steps**:
  1. Advertise channel with schema
  2. Validate data against schema
  3. Valid data → passes through
  4. Invalid data → error
- **Why**: Validation workflow

---

## Phase 16: Edge Cases and Error Handling

### File: `packages/api/src/edge-cases.test.ts`

#### Test 29.1: Network Failure - Server Unreachable
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: Stop server
- **Expected**: CLI shows network error with fixes
- **Why**: Network errors handled

#### Test 29.2: Redis Connection Failure
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Stop Redis
- **Expected**: Server errors logged, endpoints fail gracefully
- **Why**: Redis failure handled

#### Test 29.3: Malformed Config File
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Write invalid JSON to config
- **Expected**: CLI treats as empty config, starts fresh
- **Why**: Config corruption handled

#### Test 29.4: Corrupted JWT Token
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Use corrupted token
- **Expected**: 401, clear error
- **Why**: Bad tokens rejected

#### Test 29.5: Missing Environment Variables
**Priority**: P1 | **Type**: Integration | **Status**: Pending
- **Setup**: Remove JWT_SECRET
- **Expected**: Server throws error on startup
- **Why**: Required env vars enforced

#### Test 29.6: Concurrent Lock/Unlock
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Two simultaneous lock requests
- **Expected**: Both succeed (idempotent), final state locked
- **Why**: Concurrency safe

#### Test 29.7: Concurrent Grant/Revoke
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Grant and revoke same user simultaneously
- **Expected**: Deterministic final state
- **Why**: Race conditions safe

#### Test 29.8: Rapid Publishes (Rate Limit Stress)
**Priority**: P1 | **Type**: E2E | **Status**: Pending
- **Setup**: 10 rapid publishes
- **Expected**: 1 success, 9 rate limited
- **Why**: Rate limit stress test

#### Test 29.9: Concurrent Config Access
**Priority**: P2 | **Type**: Integration | **Status**: Pending
- **Setup**: Multiple CLI processes access config simultaneously
- **Expected**: No corruption
- **Why**: File access safe

#### Test 29.10: Very Long Channel Names
**Priority**: P2 | **Type**: Unit | **Status**: Pending
- **Input**: channel name >255 chars
- **Expected**: 400 or handled
- **Why**: Length limits

#### Test 29.11: Empty Strings vs Null
**Priority**: P2 | **Type**: Unit | **Status**: Pending
- **Test**: Empty string "", null, undefined handling
- **Why**: Type consistency

---

## Summary Statistics

| Phase | File | Test Count | Priority |
|-------|------|-----------|----------|
| 1 | auth.test.ts | 25 | P0-P1 |
| 2 | proxy.test.ts | 15 | P0-P1 |
| 3 | permissions.test.ts (ext) | 35 | P0-P2 |
| 4 | publish.test.ts | 24 | P0-P2 |
| 5 | advertise.test.ts | 30 | P0-P2 |
| 6 | profile.test.ts | 8 | P0-P2 |
| 7 | utils.test.ts | 8 | P2-P3 |
| 8 | security.test.ts | 14 | P0-P2 |
| 9 | global-options.test.ts | 10 | P1 |
| 10 | auth-commands.test.ts | 18 | P0-P1 |
| 11 | publish-commands.test.ts | 17 | P0-P1 |
| 12 | subscription-commands.test.ts | 20 | P0-P1 |
| 13 | permission-commands.test.ts | 16 | P0-P1 |
| 14 | advertising-commands.test.ts | 14 | P0-P1 |
| 15 | e2e.test.ts | 10 | P0-P1 |
| 16 | edge-cases.test.ts | 11 | P1-P2 |
| **TOTAL** | **16 files** | **275** | |

## Next Steps

1. **Start with P0 tests** (security and core functionality) - approximately 100 tests
2. **Implement server-side tests first** (Phase 1-8)
3. **Then implement CLI tests** (Phase 9-14)
4. **Finally E2E and edge cases** (Phase 15-16)

**Estimated time:**
- P0 tests: 2-3 days
- P1 tests: 2-3 days
- P2 tests: 1-2 days
- **Total: 5-8 days for complete test suite**
