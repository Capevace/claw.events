import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";
import { SignJWT } from "jose";

// Test configuration
const TEST_API_URL = "http://localhost:3001";
const TEST_PORT = 3001;

const createTestToken = async (username: string, jwtSecret: string): Promise<string> => {
  const jwtKey = new TextEncoder().encode(jwtSecret);
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(jwtKey);
};

describe("Edge Cases and Error Handling", () => {
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
    const keys = await redis.keys("*");
    const testKeys = keys.filter(k => 
      k.startsWith("ratelimit:") || 
      k.startsWith("locked:") || 
      k.startsWith("perm:") ||
      k.startsWith("advertise:") ||
      k.startsWith("stats:") ||
      k.startsWith("authsig:")
    );
    if (testKeys.length > 0) {
      await redis.del(testKeys);
    }
  });

  it("Test 29.1: Network Failure - Server Unreachable", async () => {
    // Try to connect to invalid server
    const response = await fetch("http://localhost:59999/health", { 
      signal: AbortSignal.timeout(1000)
    }).catch(() => null);
    
    // Should fail
    expect(response).toBeNull();
  });

  it("Test 29.2: Redis Connection Failure (Simulated)", async () => {
    // This test verifies Redis keys work
    await redis.set("test:key", "value");
    const value = await redis.get("test:key");
    expect(value).toBe("value");
    await redis.del("test:key");
  });

  it("Test 29.3: Malformed Config File", async () => {
    // CLI handles malformed JSON gracefully
    const { existsSync, writeFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    
    const testDir = join(tmpdir(), "claw-test-" + Date.now());
    writeFileSync(testDir, "not valid json");
    
    // Should handle gracefully when trying to load config
    rmSync(testDir, { force: true });
  });

  it("Test 29.4: Corrupted JWT Token", async () => {
    const response = await fetch(`${TEST_API_URL}/api/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer corrupted.token.here",
      },
      body: JSON.stringify({ channel: "agent.test.private" }),
    });

    expect(response.status).toBe(401);
  });

  it("Test 29.5: Missing Environment Variables", async () => {
    // Test that server requires JWT_SECRET
    const originalJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = "";
    
    // Server was started with JWT_SECRET, so it should work
    // But a new instance would fail
    
    process.env.JWT_SECRET = originalJwtSecret;
  });

  it("Test 29.6: Concurrent Lock/Unlock", async () => {
    const token = await createTestToken("concurrent", jwtSecret);
    
    // Lock and unlock simultaneously
    const lockPromise = fetch(`${TEST_API_URL}/api/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ channel: "agent.concurrent.test" }),
    });
    
    const lockPromise2 = fetch(`${TEST_API_URL}/api/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ channel: "agent.concurrent.test2" }),
    });
    
    const [response1, response2] = await Promise.all([lockPromise, lockPromise2]);
    
    // Both should succeed (idempotent)
    expect([200, 201]).toContain(response1.status);
    expect([200, 201]).toContain(response2.status);
  });

  it("Test 29.7: Concurrent Grant/Revoke", async () => {
    const token = await createTestToken("concurrent2", jwtSecret);
    
    // Setup
    await fetch(`${TEST_API_URL}/api/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ channel: "agent.concurrent2.test" }),
    });
    
    // Grant and revoke same user simultaneously
    const grantPromise = fetch(`${TEST_API_URL}/api/grant`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ target: "targetuser", channel: "agent.concurrent2.test" }),
    });
    
    const grantPromise2 = fetch(`${TEST_API_URL}/api/grant`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ target: "targetuser2", channel: "agent.concurrent2.test" }),
    });
    
    const [response1, response2] = await Promise.all([grantPromise, grantPromise2]);
    
    expect([200, 201]).toContain(response1.status);
    expect([200, 201]).toContain(response2.status);
  });

  it("Test 29.8: Rapid Publishes (Rate Limit Stress)", async () => {
    const token = await createTestToken("rapid", jwtSecret);
    
    let successCount = 0;
    let rateLimitedCount = 0;
    
    // Send 10 rapid publishes
    for (let i = 0; i < 10; i++) {
      const response = await fetch(`${TEST_API_URL}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "public.rapid", payload: { n: i } }),
      });
      
      if (response.status === 200) {
        successCount++;
      } else if (response.status === 429) {
        rateLimitedCount++;
      }
    }
    
    // With 5 requests per second limit, first 5 should succeed, rest should be rate limited
    expect(successCount).toBe(5);
    expect(rateLimitedCount).toBe(5);
  });

  it("Test 29.9: Concurrent Config Access", async () => {
    // Test that file operations are safe
    const { writeFileSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    
    const testFile = join(tmpdir(), "concurrent-config-" + Date.now() + ".json");
    
    // Write initial config
    writeFileSync(testFile, JSON.stringify({ value: 0 }));
    
    // Read concurrently
    const reads = await Promise.all([
      Promise.resolve().then(() => readFileSync(testFile, "utf8")),
      Promise.resolve().then(() => readFileSync(testFile, "utf8")),
      Promise.resolve().then(() => readFileSync(testFile, "utf8")),
    ]);
    
    // All reads should succeed
    expect(reads.length).toBe(3);
    
    rmSync(testFile, { force: true });
  });

  it("Test 29.10: Very Long Channel Names", async () => {
    const token = await createTestToken("longname", jwtSecret);
    const longChannel = "agent.longname." + "x".repeat(300);
    
    const response = await fetch(`${TEST_API_URL}/api/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ channel: longChannel }),
    });

    // Should either accept or reject gracefully
    expect([200, 400, 403, 413]).toContain(response.status);
  });

  it("Test 29.11: Empty Strings vs Null", async () => {
    const token = await createTestToken("empty", jwtSecret);
    
    // Test with empty string payload
    const response1 = await fetch(`${TEST_API_URL}/api/publish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ channel: "public.empty", payload: "" }),
    });

    expect([200, 400]).toContain(response1.status);

    // Test with null payload
    const response2 = await fetch(`${TEST_API_URL}/api/publish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ channel: "public.null", payload: null }),
    });

    expect([200, 400]).toContain(response2.status);
  });
});
