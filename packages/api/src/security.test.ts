import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import {
  createTestContext,
  startClawkeyMockServer,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  createTestToken,
  type TestContext,
} from "./test-utils.ts";

describe("Security and Edge Cases Tests", () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    await startClawkeyMockServer(ctx, 9000);
    ctx.publicKeys.set("*", new Map([
      ["main", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForClawTests000000000000000000000000"]
    ]));
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
  });

  describe("JWT Token Security", () => {
    it("Test 21.1: JWT Token - Expired Token Rejected", async () => {
      const expiredToken = await createTestToken("testuser", ctx.config.jwtSecret, { expired: true });

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${expiredToken}`,
        },
        body: JSON.stringify({ channel: "agent.testuser.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.2: JWT Token - Wrong Signature", async () => {
      // Create token with wrong secret
      const wrongToken = await createTestToken("testuser", "wrong-secret-12345");

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${wrongToken}`,
        },
        body: JSON.stringify({ channel: "agent.testuser.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.3: JWT Token - Tampered Payload", async () => {
      const validToken = await createTestToken("alice", ctx.config.jwtSecret);
      
      // Tamper with the token (modify payload)
      const parts = validToken.split(".");
      const tamperedPayload = Buffer.from(parts[1], "base64url").toString();
      const modifiedPayload = tamperedPayload.replace("alice", "bob");
      const tamperedToken = `${parts[0]}.${Buffer.from(modifiedPayload).toString("base64url")}.${parts[2]}`;

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${tamperedToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.4: JWT Token - Malformed Token", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer not.a.token",
        },
        body: JSON.stringify({ channel: "agent.test.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.5: JWT Token - Missing Bearer Prefix", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": token, // Missing "Bearer " prefix
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.6: JWT Token - User A Token for User B Operations", async () => {
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);

      // Try to use alice's token for bob's channel
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.bob.private" }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toContain("can only lock your own channels");
    });
  });

  describe("Injection Prevention", () => {
    it("Test 21.7: Injection - SQL in Channel Name", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.'; DROP TABLE users; --" 
        }),
      });

      // Should not crash or execute SQL, should validate channel format
      expect([200, 400, 403]).toContain(response.status);
    });

    it("Test 21.8: Injection - NoSQL in Redis Keys", async () => {
      // Try to inject special characters that might affect Redis
      const maliciousUsername = "alice{$ne:null}";
      
      const response = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: maliciousUsername, key_name: "main" }),
      });

      // Should treat the key literally
      expect(response.status).toBe(200);

      const body = await response.json();
      const storedKey = await ctx.redis.get(`agent_challenge:${maliciousUsername}:main:${body.nonce}`);
      expect(storedKey).toBeDefined();
    });

    it("Test 21.9: Injection - XSS in Description", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      const xssPayload = "<script>alert('xss')</script>";

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: xssPayload 
        }),
      });

      expect(response.status).toBe(200);
      
      // Verify stored literally (not executed)
      const data = await ctx.redis.get("advertise:alice:updates");
      const parsed = JSON.parse(data!);
      expect(parsed.description).toBe(xssPayload);
    });

    it("Test 21.10: Path Traversal - Double Dot in Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice/../../../etc/passwd" 
        }),
      });

      // Should reject or treat as literal (not cause file access)
      expect([400, 403]).toContain(response.status);
    });

    it("Test 21.11: Null Bytes in Strings", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      const usernameWithNull = "alice\x00injected";

      const response = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: usernameWithNull, key_name: "main" }),
      });

      // Should handle gracefully (200 or reject)
      expect([200, 400]).toContain(response.status);
    });
  });

  describe("Unicode Handling", () => {
    it("Test 21.12: Unicode - Emoji in Username", async () => {
      const emojiUsername = "test😀user";

      const response = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: emojiUsername, key_name: "main" }),
      });

      // Should handle emoji gracefully
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe(emojiUsername);
    });

    it("Test 21.13: Unicode - Right-to-Left Characters", async () => {
      // RTL override character
      const rtlUsername = "test\u202Eevil\u202Cuser";

      const response = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: rtlUsername, key_name: "main" }),
      });

      // Should handle gracefully
      expect(response.status).toBe(200);
    });

    it("Test 21.14: Unicode - Confusable Characters", async () => {
      // Cyrillic 'а' looks like Latin 'a'
      const cyrillicUsername = "test\u0430user"; // Cyrillic а

      const response = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: cyrillicUsername, key_name: "main" }),
      });

      expect(response.status).toBe(200);
      
      // Verify stored as different from Latin version
      const body = await response.json();
      const stored = await ctx.redis.get(`agent_challenge:${cyrillicUsername}:main:${body.nonce}`);
      expect(stored).toBeDefined();
    });
  });
});
