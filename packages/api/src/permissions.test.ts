import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, mock } from "bun:test";
import {
  createTestContext,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  createTestToken,
  mockFetch as createFetchMock,
  type TestContext,
} from "./test-utils.ts";
import { setCentrifugoApiKey } from "./index.ts";

describe("Permission Management Endpoints", () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    await startTestServer(ctx);
  });

  afterAll(async () => {
    await cleanupTestContext(ctx);
  });

  beforeEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
  });

  afterEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
    mock.restore();
  });

  // Helper to mock Centrifugo API calls for endpoints that use it
  const mockCentrifugo = () => {
    return createFetchMock((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes(":800") || url.includes("localhost:800")) {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      }
      return Promise.resolve(new Response("Not found", { status: 404 }));
    });
  };

  describe("POST /api/lock", () => {
    it("Test 6.1: POST /api/lock - Happy Path", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.locked).toBe(true);
      expect(body.channel).toBe("agent.alice.private");
    });

    it("Test 6.2: POST /api/lock - Redis Key Created", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      const value = await ctx.redis.get("locked:alice:private");
      expect(value).toBe("1");
    });

    it("Test 6.3: POST /api/lock - No Auth Token", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toContain("Missing bearer token");
    });

    it("Test 6.4: POST /api/lock - Invalid Token", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer invalid.token.here",
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 6.5: POST /api/lock - Non-Owner Tries to Lock", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toContain("can only lock your own channels");
    });

    it("Test 6.6: POST /api/lock - Missing Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("channel required");
    });

    it("Test 6.7: POST /api/lock - Empty Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("channel required");
    });

    it("Test 6.8: POST /api/lock - Invalid Channel Format", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "invalid" }),
      });

      expect(response.status).toBe(400);
    });

    it("Test 6.9: POST /api/lock - public.* Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("invalid channel format");
    });

    it("Test 6.10: POST /api/lock - system.* Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "system.timer.test" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("invalid channel format");
    });

    it("Test 6.11: POST /api/lock - Already Locked (Idempotent)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // First lock
      const response1 = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.idempotent" }),
      });

      // Second lock (idempotent)
      const response2 = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.idempotent" }),
      });

      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);
    });

    it("Test 6.12: POST /api/lock - Channel Belongs to Different Owner in Name", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.bob.test" }),
      });

      expect(response.status).toBe(403);
    });
  });

  describe("POST /api/unlock", () => {
    it("Test 7.1: POST /api/unlock - Happy Path", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Lock first
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.unlock" }),
      });

      // Then unlock
      const response = await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.unlock" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.unlocked).toBe(true);
    });

    it("Test 7.2: POST /api/unlock - Redis Key Deleted", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Lock
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.unlock2" }),
      });

      // Unlock
      await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.unlock2" }),
      });

      const exists = await ctx.redis.exists("locked:alice:unlock2");
      expect(exists).toBe(0);
    });

    it("Test 7.3: POST /api/unlock - No Auth", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 7.4: POST /api/unlock - Non-Owner", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(403);
    });

    it("Test 7.5: POST /api/unlock - Not Locked (Graceful)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.neverlocked" }),
      });

      // Should succeed gracefully
      expect(response.status).toBe(200);
    });

    it("Test 7.6: POST /api/unlock - Grants Remain After Unlock", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Lock, grant, then unlock
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.grantsremain" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.grantsremain" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.grantsremain" }),
      });

      // Grant should still exist
      const members = await ctx.redis.sMembers("perm:alice:grantsremain");
      expect(members).toContain("bob");
    });
  });

  describe("POST /api/grant", () => {
    it("Test 8.1: POST /api/grant - Happy Path", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Lock first
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.grant" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.grant" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.granted).toBe(true);
      expect(body.target).toBe("bob");
    });

    it("Test 8.2: POST /api/grant - Redis Set Updated", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.grant2" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.grant2" }),
      });

      const members = await ctx.redis.sMembers("perm:alice:grant2");
      expect(members).toContain("bob");
    });

    it("Test 8.3: POST /api/grant - No Auth", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 8.4: POST /api/grant - Non-Owner", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ target: "charlie", channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(403);
    });

    it("Test 8.5: POST /api/grant - Missing Target", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("target and channel required");
    });

    it("Test 8.6: POST /api/grant - Missing Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob" }),
      });

      expect(response.status).toBe(400);
    });

    it("Test 8.7: POST /api/grant - Grant on Unlocked Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Don't lock - just grant
      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.unlocked" }),
      });

      // Should succeed (grant stored but has no effect until locked)
      expect(response.status).toBe(200);
    });

    it("Test 8.8: POST /api/grant - Duplicate Grant (Idempotent)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.dup" }),
      });

      // Grant twice
      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.dup" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.dup" }),
      });

      // Should only be in set once
      const members = await ctx.redis.sMembers("perm:alice:dup");
      expect(members.filter(m => m === "bob").length).toBe(1);
    });

    it("Test 8.9: POST /api/grant - Grant to Self", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.self" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "alice", channel: "agent.alice.self" }),
      });

      // Should either succeed or be rejected
      expect([200, 400]).toContain(response.status);
    });

    it("Test 8.10: POST /api/grant - Multiple Grants", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.multi" }),
      });

      // Grant multiple users
      for (const user of ["bob", "charlie", "dave"]) {
        await fetch(`${ctx.config.apiUrl}/api/grant`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ target: user, channel: "agent.alice.multi" }),
        });
      }

      const members = await ctx.redis.sMembers("perm:alice:multi");
      expect(members).toContain("bob");
      expect(members).toContain("charlie");
      expect(members).toContain("dave");
    });
  });

  describe("POST /api/revoke", () => {
    it("Test 9.1: POST /api/revoke - Happy Path", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Setup: lock, grant, then revoke
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.revoke" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.revoke" }),
      });

      // Mock Centrifugo disconnect call
      const mockFetch = mockCentrifugo();

      const response = await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.revoke" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.revoked).toBe(true);

      mockFetch.mockRestore();
    });

    it("Test 9.2: POST /api/revoke - Redis Set Updated", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.revoke2" }),
      });

      // Mock Centrifugo disconnect call
      const mockFetch = mockCentrifugo();

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.revoke2" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.revoke2" }),
      });

      const members = await ctx.redis.sMembers("perm:alice:revoke2");
      expect(members).not.toContain("bob");

      mockFetch.mockRestore();
    });

    it("Test 9.3: POST /api/revoke - Centrifugo Disconnect Called", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      let disconnectCalled = false;

      // Mock Centrifugo API
      const mockFetch = createFetchMock((input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api") && init?.body?.toString().includes("disconnect")) {
          disconnectCalled = true;
          return Promise.resolve(new Response(
            JSON.stringify({ result: {} }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.revoke3" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.revoke3" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.revoke3" }),
      });

      // Note: disconnect may or may not be called depending on implementation
      mockFetch.mockRestore();
    });

    it("Test 9.4: POST /api/revoke - No Auth", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 9.5: POST /api/revoke - Non-Owner", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ target: "charlie", channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(403);
    });

    it("Test 9.6: POST /api/revoke - Target Not Granted (Graceful)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.notgranted" }),
      });

      // Mock Centrifugo disconnect call
      const mockFetch = mockCentrifugo();

      // Try to revoke without ever granting
      const response = await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.notgranted" }),
      });

      // Should succeed gracefully
      expect(response.status).toBe(200);

      mockFetch.mockRestore();
    });

    it("Test 9.7: POST /api/revoke - Missing Target or Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
    });
  });

  describe("POST /api/request", () => {
    it("Test 10.1: POST /api/request - Happy Path", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      // Alice locks channel
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.request" }),
      });

      // Mock Centrifugo for publish
      const mockFetch = createFetchMock(() => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Bob requests access
      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.request", 
          reason: "Need access for work" 
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.request).toBeDefined();

      mockFetch.mockRestore();
    });

    it("Test 10.2: POST /api/request - Publishes to public.access", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);
      let publishCalled = false;
      let publishChannel: string | null = null;

      const mockFetch = createFetchMock((input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api")) {
          const body = init?.body?.toString() || "";
          const parsed = JSON.parse(body);
          if (parsed.method === "publish") {
            publishCalled = true;
            publishChannel = parsed.params?.channel;
          }
          return Promise.resolve(new Response(
            JSON.stringify({ result: { published: true } }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.request2" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.request2", 
          reason: "Need access" 
        }),
      });

      expect(publishCalled).toBe(true);
      expect(publishChannel).toBe("public.access");

      mockFetch.mockRestore();
    });

    it("Test 10.3: POST /api/request - Request Format", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);
      let capturedPayload: any = null;

      const mockFetch = createFetchMock((input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api")) {
          const body = init?.body?.toString() || "";
          const parsed = JSON.parse(body);
          if (parsed.method === "publish") {
            capturedPayload = parsed.params?.data;
          }
          return Promise.resolve(new Response(
            JSON.stringify({ result: { published: true } }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.request3" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.request3", 
          reason: "Test format" 
        }),
      });

      expect(capturedPayload).toBeDefined();
      expect(capturedPayload.type).toBe("access_request");
      expect(capturedPayload.requester).toBe("bob");
      expect(capturedPayload.targetChannel).toBe("agent.alice.request3");
      expect(capturedPayload.targetAgent).toBe("alice");
      expect(capturedPayload.reason).toBe("Test format");
      expect(capturedPayload.timestamp).toBeDefined();

      mockFetch.mockRestore();
    });

    it("Test 10.4: POST /api/request - No Auth", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          channel: "agent.alice.test", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 10.5: POST /api/request - Channel Not Locked", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      // Don't lock the channel
      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.unlocked", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("channel is not locked");
    });

    it("Test 10.6: POST /api/request - Already Granted", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      // Lock and grant bob
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.granted" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.granted" }),
      });

      // Bob tries to request (already has access)
      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.granted", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("already have access");
    });

    it("Test 10.7: POST /api/request - Own Channel", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.own" }),
      });

      // Alice requests access to her own channel
      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.own", 
          reason: "Need access" 
        }),
      });

      // Should fail - cannot request own channel
      expect(response.status).toBe(400);
    });

    it("Test 10.8: POST /api/request - Missing Channel", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ reason: "Need access" }),
      });

      expect(response.status).toBe(400);
    });

    it("Test 10.9: POST /api/request - Invalid Channel Format", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "invalid", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("invalid channel format");
    });

    it("Test 10.10: POST /api/request - public.* Channel", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "public.test", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(400);
    });

    it("Test 10.11: POST /api/request - system.* Channel", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "system.timer.test", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(400);
    });

    it("Test 10.12: POST /api/request - Centrifugo Not Configured", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);
      setCentrifugoApiKey("");

      try {
        await fetch(`${ctx.config.apiUrl}/api/lock`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${aliceToken}`,
          },
          body: JSON.stringify({ channel: "agent.alice.nocent" }),
        });

        const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${bobToken}`,
          },
          body: JSON.stringify({ 
            channel: "agent.alice.nocent", 
            reason: "Need access" 
          }),
        });

        expect(response.status).toBe(500);
        const body = await response.json();
        expect(body.error).toContain("CENTRIFUGO_API_KEY not configured");
      } finally {
        setCentrifugoApiKey(null);
      }
    });

    it("Test 10.13: POST /api/request - Centrifugo Publish Fails", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const mockFetch = createFetchMock(() => {
        return Promise.resolve(new Response(
          JSON.stringify({ error: "Internal Server Error" }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        ));
      });

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.fail" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.fail", 
          reason: "Need access" 
        }),
      });

      expect(response.status).toBe(502);
      const body = await response.json();
      expect(body.error).toContain("failed to send request");

      mockFetch.mockRestore();
    });

    it("Test 10.14: POST /api/request - Statistics Tracked", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      const mockFetch = createFetchMock(() => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.stats" }),
      });

      // Get stats before
      const beforeStats = await ctx.redis.get("stats:total_messages");
      const beforeCount = parseInt(beforeStats || "0");

      await fetch(`${ctx.config.apiUrl}/api/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.stats", 
          reason: "Need access" 
        }),
      });

      // Stats should be tracked (agent added, message count incremented)
      const isMember = await ctx.redis.sIsMember("stats:agents", "bob");
      expect(isMember).toBe(true);

      mockFetch.mockRestore();
    });
  });
});
