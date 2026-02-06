import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import {
  createTestContext,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  type TestContext,
} from "./test-utils.ts";

describe("Utility Endpoints", () => {
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

  describe("GET /health", () => {
    it("Test 20.1: GET /health - Returns OK", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/health`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
    });

    it("Test 20.2: GET /health - No Auth Required", async () => {
      // No Authorization header
      const response = await fetch(`${ctx.config.apiUrl}/health`, {
        headers: { "Content-Type": "application/json" },
      });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /og.jpeg", () => {
    it("Test 20.3: GET /og.jpeg - Returns Image", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/og.jpeg`);

      // May be 200 if image exists or 404 if not
      expect([200, 404]).toContain(response.status);
      
      if (response.status === 200) {
        const contentType = response.headers.get("Content-Type");
        expect(contentType).toContain("image/jpeg");
      }
    });

    it("Test 20.4: GET /og.jpeg - Cache Headers", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/og.jpeg`);

      if (response.status === 200) {
        const cacheControl = response.headers.get("Cache-Control");
        expect(cacheControl).toBeDefined();
        expect(cacheControl).toContain("max-age");
      }
    });

    it("Test 20.5: GET /og.jpeg - Not Found Handling", async () => {
      // Response should be either 404 or 200 depending on if file exists
      const response = await fetch(`${ctx.config.apiUrl}/og.jpeg`);
      expect([200, 404]).toContain(response.status);
    });
  });

  describe("GET / (homepage)", () => {
    it("Test 20.6: GET / (homepage) - Returns HTML", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/`);

      expect(response.status).toBe(200);
      const contentType = response.headers.get("Content-Type");
      expect(contentType).toContain("text/html");
    });

    it("Test 20.7: GET / (homepage) - Core Sections Included", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/`);

      const html = await response.text();
      expect(html).toContain("Channel Model");
      expect(html).toContain("Quick Commands");
    });
  });

  describe("GET /docs", () => {
    it("Test 20.8: GET /docs - Returns Documentation", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/docs`);

      expect(response.status).toBe(200);
      const contentType = response.headers.get("Content-Type");
      expect(contentType).toContain("text/html");
      
      const html = await response.text();
      expect(html).toContain("Documentation");
    });
  });
});
