import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import {
  createTestContext,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  createTestToken,
  type TestContext,
} from "./test-utils.ts";

describe("Channel Advertising Endpoints", () => {
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
  });

  describe("POST /api/advertise", () => {
    it("Test 12.1: POST /api/advertise - Happy Path with Description", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "My updates channel" 
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.data).toBeDefined();
      expect(body.data.channel).toBe("agent.alice.updates");
      expect(body.data.description).toBe("My updates channel");
    });

    it("Test 12.2: POST /api/advertise - With Schema", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      const schema = { type: "object", properties: { temp: { type: "number" } } };

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.data", 
          description: "Temperature data",
          schema 
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.data.schema).toEqual(schema);
    });

    it("Test 12.3: POST /api/advertise - Redis Storage", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "Test storage" 
        }),
      });

      // Check Redis
      const data = await ctx.redis.get("advertise:alice:updates");
      expect(data).toBeDefined();
      const parsed = JSON.parse(data!);
      expect(parsed.channel).toBe("agent.alice.updates");
      expect(parsed.description).toBe("Test storage");
    });

    it("Test 12.4: POST /api/advertise - No Auth", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "Test" 
        }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 12.5: POST /api/advertise - Non-Owner", async () => {
      const token = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "Trying to advertise alice's channel" 
        }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toContain("can only advertise your own channels");
    });

    it("Test 12.6: POST /api/advertise - Missing Channel", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ description: "Test" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("channel required");
    });

    it("Test 12.7: POST /api/advertise - Invalid Channel Format", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "invalid-channel", 
          description: "Test" 
        }),
      });

      expect(response.status).toBe(400);
    });

    it("Test 12.8: POST /api/advertise - Description Too Long (>5000)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "a".repeat(5001) 
        }),
      });

      expect(response.status).toBe(413);
      const body = await response.json();
      expect(body.error).toContain("description too long");
    });

    it("Test 12.9: POST /api/advertise - Description At Limit (5000)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "a".repeat(5000) 
        }),
      });

      expect(response.status).toBe(200);
    });

    it("Test 12.10: POST /api/advertise - Invalid Description Type", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: 123 
        }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("description must be a string");
    });

    it("Test 12.11: POST /api/advertise - Schema Too Large (>32KB)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      const largeSchema = { data: "x".repeat(33000) };

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          schema: largeSchema 
        }),
      });

      expect(response.status).toBe(413);
      const body = await response.json();
      expect(body.error).toContain("schema too large");
    });

    it("Test 12.12: POST /api/advertise - Updates Existing", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Create initial advertisement
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "Original description" 
        }),
      });

      // Update it
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "Updated description" 
        }),
      });

      expect(response.status).toBe(200);

      // Verify Redis was updated
      const data = await ctx.redis.get("advertise:alice:updates");
      const parsed = JSON.parse(data!);
      expect(parsed.description).toBe("Updated description");
    });
  });

  describe("DELETE /api/advertise", () => {
    it("Test 13.1: DELETE /api/advertise - Happy Path", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Create first
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "To be deleted" 
        }),
      });

      // Delete
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.updates" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.removed).toBe(true);
    });

    it("Test 13.2: DELETE /api/advertise - Redis Key Deleted", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Create
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "Test" 
        }),
      });

      // Delete
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.updates" }),
      });

      // Verify Redis key is gone
      const exists = await ctx.redis.exists("advertise:alice:updates");
      expect(exists).toBe(0);
    });

    it("Test 13.3: DELETE /api/advertise - No Auth", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 13.4: DELETE /api/advertise - Non-Owner", async () => {
      const token = await createTestToken("bob", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.updates" }),
      });

      expect(response.status).toBe(403);
    });

    it("Test 13.5: DELETE /api/advertise - Not Found (Graceful)", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.nonexistent" }),
      });

      // Should succeed gracefully (or return 404)
      expect([200, 404]).toContain(response.status);
    });
  });

  describe("GET /api/advertise/search", () => {
    beforeEach(async () => {
      // Create several test advertisements
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.weather", 
          description: "Weather station data from my sensors" 
        }),
      });

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ 
          channel: "agent.bob.updates", 
          description: "Daily updates" 
        }),
      });

      // Small delay to ensure different timestamps
      await new Promise((resolve) => setTimeout(resolve, 100));

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "My personal updates" 
        }),
      });
    });

    it("Test 14.1: GET /api/advertise/search - Happy Path", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=updates`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.query).toBe("updates");
      expect(body.results).toBeDefined();
      expect(Array.isArray(body.results)).toBe(true);
    });

    it("Test 14.2: GET /api/advertise/search - By Channel Name", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=alice`);

      const body = await response.json();
      const channels = body.results.map((r: any) => r.channel);
      expect(channels.some((c: string) => c.includes("alice"))).toBe(true);
    });

    it("Test 14.3: GET /api/advertise/search - By Description", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=weather`);

      const body = await response.json();
      const channels = body.results.map((r: any) => r.channel);
      expect(channels).toContain("agent.alice.weather");
    });

    it("Test 14.4: GET /api/advertise/search - Case Insensitive", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=ALICE`);

      const body = await response.json();
      expect(body.results.length).toBeGreaterThan(0);
    });

    it("Test 14.5: GET /api/advertise/search - Missing Query", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search`);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("search query required");
    });

    it("Test 14.6: GET /api/advertise/search - Empty Query", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=`);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("search query required");
    });

    it("Test 14.7: GET /api/advertise/search - Limit Parameter", async () => {
      // Create 25 ads
      const token = await createTestToken("limituser", ctx.config.jwtSecret);
      for (let i = 0; i < 25; i++) {
        await fetch(`${ctx.config.apiUrl}/api/advertise`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ 
            channel: `agent.limituser.test${i}`, 
            description: `Test ${i}` 
          }),
        });
      }

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=limituser&limit=10`);

      const body = await response.json();
      expect(body.results.length).toBeLessThanOrEqual(10);
    });

    it("Test 14.8: GET /api/advertise/search - Default Limit (20)", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=test`);

      const body = await response.json();
      expect(body.results.length).toBeLessThanOrEqual(20);
    });

    it("Test 14.9: GET /api/advertise/search - Max Limit (100)", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=a&limit=200`);

      const body = await response.json();
      expect(body.results.length).toBeLessThanOrEqual(100);
    });

    it("Test 14.10: GET /api/advertise/search - No Results", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=nonexistentxyz123`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.count).toBe(0);
      expect(body.results).toEqual([]);
    });

    it("Test 14.11: GET /api/advertise/search - Sorted by updatedAt", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/search?q=updates`);

      const body = await response.json();
      // Check results are sorted newest first
      for (let i = 1; i < body.results.length; i++) {
        expect(body.results[i].updatedAt).toBeLessThanOrEqual(body.results[i - 1].updatedAt);
      }
    });
  });

  describe("GET /api/advertise/list", () => {
    beforeEach(async () => {
      const token = await createTestToken("listuser", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.listuser.channel1", 
          description: "Channel 1" 
        }),
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.listuser.channel2", 
          description: "Channel 2" 
        }),
      });
    });

    it("Test 15.1: GET /api/advertise/list - Happy Path", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/list`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.channels).toBeDefined();
      expect(Array.isArray(body.channels)).toBe(true);
      expect(body.count).toBeDefined();
    });

    it("Test 15.2: GET /api/advertise/list - Empty List", async () => {
      // Clear all ads
      const keys = await ctx.redis.keys("advertise:*");
      if (keys.length > 0) {
        await ctx.redis.del(keys);
      }

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/list`);

      const body = await response.json();
      expect(body.channels).toEqual([]);
      expect(body.count).toBe(0);
    });

    it("Test 15.3: GET /api/advertise/list - Sorted by updatedAt", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/list`);

      const body = await response.json();
      // Check sorted newest first
      for (let i = 1; i < body.channels.length; i++) {
        expect(body.channels[i].updatedAt).toBeLessThanOrEqual(body.channels[i - 1].updatedAt);
      }
    });
  });

  describe("GET /api/advertise/:agent", () => {
    beforeEach(async () => {
      const token = await createTestToken("specific", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.specific.test1", 
          description: "Test 1" 
        }),
      });

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.specific.test2", 
          description: "Test 2" 
        }),
      });
    });

    it("Test 16.1: GET /api/advertise/:agent - Happy Path", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/specific`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.agent).toBe("specific");
      expect(body.advertisements).toBeDefined();
      expect(body.advertisements.length).toBe(2);
    });

    it("Test 16.2: GET /api/advertise/:agent - Empty Result", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/nonexistent`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.advertisements).toEqual([]);
    });
  });

  describe("GET /api/advertise/:agent/:topic", () => {
    beforeEach(async () => {
      const token = await createTestToken("detail", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.detail.updates", 
          description: "My updates",
          schema: { type: "object" }
        }),
      });
    });

    it("Test 17.1: GET /api/advertise/:agent/:topic - Happy Path", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/detail/updates`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.channel).toBe("agent.detail.updates");
      expect(body.description).toBe("My updates");
      expect(body.schema).toEqual({ type: "object" });
      expect(body.updatedAt).toBeDefined();
    });

    it("Test 17.2: GET /api/advertise/:agent/:topic - Not Found", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/detail/nonexistent`);

      expect(response.status).toBe(404);
      const body = await response.json();
      expect(body.error).toContain("not found");
    });

    it("Test 17.3: GET /api/advertise/:agent/:topic - Multi-part Topic", async () => {
      const token = await createTestToken("detail", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.detail.data.sensor1", 
          description: "Sensor 1 data" 
        }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/api/advertise/detail/data.sensor1`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.channel).toBe("agent.detail.data.sensor1");
    });
  });
});
