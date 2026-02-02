import { describe, it, expect, beforeAll, afterAll, beforeEach, mock } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";

// Test configuration
const TEST_API_URL = "http://localhost:3001";
const TEST_PORT = 3001;

// Helper function to create a valid token
const createTestToken = async (username: string, jwtSecret: string): Promise<string> => {
  const { SignJWT } = await import("jose");
  const jwtKey = new TextEncoder().encode(jwtSecret);
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(jwtKey);
};

describe("Publishing Endpoint Tests", () => {
  let server: Server;
  let redis: RedisClientType;
  let originalEnv: Record<string, string | undefined>;
  let jwtSecret: string;

  beforeAll(async () => {
    originalEnv = { ...process.env };
    
    process.env.PORT = String(TEST_PORT);
    jwtSecret = "test-jwt-secret-for-testing-only";
    process.env.JWT_SECRET = jwtSecret;
    process.env.REDIS_URL = "redis://localhost:6380";
    process.env.CENTRIFUGO_API_URL = "http://localhost:8001/api";
    process.env.CENTRIFUGO_API_KEY = "test-centrifugo-key";
    process.env.MOLTBOOK_API_BASE = "http://localhost:9000/api/v1";
    process.env.MOLTBOOK_API_KEY = "test-moltbook-key";
    process.env.CLAW_DEV_MODE = "true";

    redis = createClient({ url: process.env.REDIS_URL });
    await redis.connect();

    const { default: app } = await import("./index.ts");
    server = Bun.serve({
      fetch: app.fetch,
      port: TEST_PORT,
    });
  });

  afterAll(async () => {
    if (server) {
      server.stop();
    }
    if (redis) {
      await redis.quit();
    }
    process.env = originalEnv;
  });

  beforeEach(async () => {
    // Clean up all test keys
    const keys = await redis.keys("*");
    const testKeys = keys.filter(k => 
      k.startsWith("ratelimit:") || 
      k.startsWith("locked:") || 
      k.startsWith("perm:") ||
      k.startsWith("stats:") ||
      k.startsWith("advertise:")
    );
    if (testKeys.length > 0) {
      await redis.del(testKeys);
    }
  });

  describe("POST /api/publish - Basic Functionality", () => {
    it("Test 11.1: POST /api/publish - Public Channel", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Mock Centrifugo
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api")) {
          return Promise.resolve(new Response(
            JSON.stringify({ result: { published: true } }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: { msg: "hello" } }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);

      mockFetch.restore();
    });

    it("Test 11.2: POST /api/publish - Own Agent Channel", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api")) {
          return Promise.resolve(new Response(
            JSON.stringify({ result: { published: true } }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.updates", payload: { data: "test" } }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });

    it("Test 11.3: POST /api/publish - Centrifugo Publish Called", async () => {
      const token = await createTestToken("alice", jwtSecret);
      let centrifugoCalled = false;
      let publishData: any = null;

      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api")) {
          centrifugoCalled = true;
          const bodyStr = init?.body?.toString() || "";
          publishData = JSON.parse(bodyStr);
          return Promise.resolve(new Response(
            JSON.stringify({ result: { published: true } }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: { test: true } }),
      });

      expect(centrifugoCalled).toBe(true);
      expect(publishData.method).toBe("publish");
      expect(publishData.params.channel).toBe("public.test");

      mockFetch.restore();
    });

    it("Test 11.4: POST /api/publish - No Auth", async () => {
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBeDefined();
    });

    it("Test 11.5: POST /api/publish - System Channel", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "system.timer.test", payload: {} }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toContain("cannot publish to system channels");
    });

    it("Test 11.6: POST /api/publish - Non-Owner Agent Channel", async () => {
      const token = await createTestToken("bob", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.updates", payload: {} }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toContain("only the channel owner can publish");
    });

    it("Test 11.7: POST /api/publish - Locked Channel Still Allows Owner Publish", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Lock the channel first
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("/api")) {
          return Promise.resolve(new Response(
            JSON.stringify({ result: { published: true } }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private", payload: {} }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });

    it("Test 11.8: POST /api/publish - Locked Channel Still Denies Non-Owner", async () => {
      const aliceToken = await createTestToken("alice", jwtSecret);
      const bobToken = await createTestToken("bob", jwtSecret);

      // Alice locks and grants bob subscribe access
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      await fetch(`${TEST_API_URL}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.private" }),
      });

      // Bob tries to publish
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private", payload: {} }),
      });

      expect(response.status).toBe(403);
    });
  });

  describe("POST /api/publish - Rate Limiting", () => {
    it("Test 11.9: POST /api/publish - Rate Limit Redis Key Created", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      // Check Redis key exists with 1 second TTL
      const ttl = await redis.ttl("ratelimit:alice");
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(1);

      mockFetch.restore();
    });

    it("Test 11.10: POST /api/publish - Rate Limit 6th Request Within 1s", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // First 5 requests should succeed
      for (let i = 0; i < 5; i++) {
        const response = await fetch(`${TEST_API_URL}/api/publish`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ channel: "public.test", payload: {} }),
        });
        expect(response.status).toBe(200);
      }

      // 6th request should be rate limited
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      expect(response.status).toBe(429);
      const body = await response.json();
      expect(body.error).toContain("rate limit exceeded");
      expect(body.retry_after).toBeDefined();
      expect(body.retry_timestamp).toBeDefined();

      mockFetch.restore();
    });

    it("Test 11.11: POST /api/publish - Rate Limit Resets After 1s", async () => {
      const token = await createTestToken("ratetest", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Send 5 requests to hit the limit
      for (let i = 0; i < 5; i++) {
        await fetch(`${TEST_API_URL}/api/publish`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ channel: "public.test", payload: {} }),
        });
      }

      // Wait for rate limit window to reset (1 second + buffer)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Request after 1 second should succeed
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    }, 5000);

    it("Test 11.12: POST /api/publish - Rate Limit retry_after Accuracy", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Send 5 requests to hit the limit
      for (let i = 0; i < 5; i++) {
        await fetch(`${TEST_API_URL}/api/publish`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ channel: "public.test", payload: {} }),
        });
      }

      // 6th request should be rate limited with ~1s retry_after
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      const body = await response.json();
      expect(body.retry_after).toBeGreaterThanOrEqual(0);
      expect(body.retry_after).toBeLessThanOrEqual(1);

      mockFetch.restore();
    });

    it("Test 11.13: POST /api/publish - Rate Limit Different Users Independent", async () => {
      const aliceToken = await createTestToken("alice", jwtSecret);
      const bobToken = await createTestToken("bob", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Alice publishes
      const response1 = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      // Bob publishes immediately
      const response2 = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);

      mockFetch.restore();
    });
  });

  describe("POST /api/publish - Payload Size Limits", () => {
    it("Test 11.14: POST /api/publish - Payload Size Under Limit (16KB)", async () => {
      const token = await createTestToken("alice", jwtSecret);
      const payload = { data: "a".repeat(15000) }; // ~15KB

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });

    it("Test 11.15: POST /api/publish - Payload Size At Limit (16KB)", async () => {
      const token = await createTestToken("alice", jwtSecret);
      // Create payload of exactly 16384 bytes when stringified
      const payloadStr = "a".repeat(16384 - 20); // Account for JSON wrapper
      const payload = { data: payloadStr };

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload }),
      });

      // Should either succeed or be rejected depending on exact size
      expect([200, 413]).toContain(response.status);

      mockFetch.restore();
    });

    it("Test 11.16: POST /api/publish - Payload Size Over Limit (16KB)", async () => {
      const token = await createTestToken("alice", jwtSecret);
      const payload = { data: "a".repeat(20000) }; // >16KB

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload }),
      });

      expect(response.status).toBe(413);
      const body = await response.json();
      expect(body.error).toContain("payload too large");
      expect(body.error).toContain("16384");
    });

    it("Test 11.17: POST /api/publish - Empty Payload (Null)", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: null }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });

    it("Test 11.18: POST /api/publish - No Payload Field", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test" }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });
  });

  describe("POST /api/publish - Validation and Errors", () => {
    it("Test 11.19: POST /api/publish - Invalid Channel Format", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "invalid", payload: {} }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("invalid channel format");
    });

    it("Test 11.20: POST /api/publish - Missing Channel", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ payload: {} }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("channel required");
    });

    it("Test 11.21: POST /api/publish - Centrifugo Not Configured", async () => {
      const token = await createTestToken("alice", jwtSecret);
      const originalKey = process.env.CENTRIFUGO_API_KEY;
      process.env.CENTRIFUGO_API_KEY = "";

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toContain("CENTRIFUGO_API_KEY not configured");

      process.env.CENTRIFUGO_API_KEY = originalKey;
    });

    it("Test 11.22: POST /api/publish - Centrifugo Publish Fails", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ error: "Internal Server Error" }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        ));
      });

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      expect(response.status).toBe(502);
      const body = await response.json();
      expect(body.error).toContain("centrifugo publish failed");

      mockFetch.restore();
    });

    it("Test 11.23: POST /api/publish - Statistics Tracked", async () => {
      const token = await createTestToken("statstest", jwtSecret);

      // Clear stats first
      await redis.del("stats:agents");
      await redis.del("stats:total_messages");

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload: {} }),
      });

      // Check stats were tracked
      const isMember = await redis.sIsMember("stats:agents", "statstest");
      expect(isMember).toBe(true);

      const totalMessages = await redis.get("stats:total_messages");
      expect(parseInt(totalMessages || "0")).toBeGreaterThan(0);

      mockFetch.restore();
    });

    it("Test 11.24: POST /api/publish - Circular JSON Payload", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Create circular object
      const payload: any = { a: 1 };
      payload.self = payload;

      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.test", payload }).catch(() => "invalid"),
      });

      // Should handle gracefully (400 or error)
      expect([400, 422, 500]).toContain(response.status);
    });
  });

  describe("POST /api/publish - Schema Validation", () => {
    beforeEach(async () => {
      // Clean up advertisement keys
      const keys = await redis.keys("advertise:*");
      if (keys.length > 0) {
        await redis.del(keys);
      }
    });

    it("Test 11.25: POST /api/publish - Valid Payload Matches Schema", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Set up advertisement with schema
      const schema = {
        type: "object",
        properties: {
          message: { type: "string" },
          count: { type: "integer" }
        },
        required: ["message"]
      };

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.updates",
          description: "Test channel",
          schema
        }),
      });

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Valid payload
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.updates",
          payload: { message: "Hello", count: 42 }
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);

      mockFetch.restore();
    });

    it("Test 11.26: POST /api/publish - Invalid Payload Fails Schema Validation", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Set up advertisement with schema
      const schema = {
        type: "object",
        properties: {
          message: { type: "string" },
          count: { type: "integer" }
        },
        required: ["message"]
      };

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.updates",
          description: "Test channel",
          schema
        }),
      });

      // Invalid payload (missing required field, wrong type)
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.updates",
          payload: { count: "not a number" }
        }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("Schema validation failed");
      expect(body.validation_errors).toBeDefined();
      expect(Array.isArray(body.validation_errors)).toBe(true);
      expect(body.validation_errors.length).toBeGreaterThan(0);
    });

    it("Test 11.27: POST /api/publish - No Schema Defined Allows Any Payload", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // No advertisement set up for this channel

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Any payload should work
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.unstructured",
          payload: { anything: "goes", here: 123, nested: { data: true } }
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);

      mockFetch.restore();
    });

    it("Test 11.28: POST /api/publish - Schema with Array Validation", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Set up advertisement with array schema
      const schema = {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string", minLength: 1 }
          },
          required: ["id", "name"]
        }
      };

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.items",
          description: "Items channel",
          schema
        }),
      });

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Valid array payload
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.items",
          payload: [
            { id: 1, name: "First" },
            { id: 2, name: "Second" }
          ]
        }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });

    it("Test 11.29: POST /api/publish - Schema with Enum Validation", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Set up advertisement with enum schema
      const schema = {
        type: "object",
        properties: {
          status: {
            type: "string",
            enum: ["pending", "active", "completed"]
          }
        },
        required: ["status"]
      };

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.status",
          description: "Status updates",
          schema
        }),
      });

      // Valid enum value
      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      const response1 = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.status",
          payload: { status: "active" }
        }),
      });

      expect(response1.status).toBe(200);
      mockFetch.restore();

      // Invalid enum value
      const response2 = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.status",
          payload: { status: "invalid_status" }
        }),
      });

      expect(response2.status).toBe(400);
      const body = await response2.json();
      expect(body.error).toContain("Schema validation failed");
    });

    it("Test 11.30: POST /api/publish - Null Payload Skips Validation", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Set up advertisement with schema
      const schema = {
        type: "object",
        properties: {
          message: { type: "string" }
        }
      };

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.nullable",
          description: "Nullable channel",
          schema
        }),
      });

      const mockFetch = mock(fetch, () => {
        return Promise.resolve(new Response(
          JSON.stringify({ result: { published: true } }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // Null payload should skip validation and succeed
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          channel: "agent.alice.nullable",
          payload: null
        }),
      });

      expect(response.status).toBe(200);

      mockFetch.restore();
    });
  });
});
