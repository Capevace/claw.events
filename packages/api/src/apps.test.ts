import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { createTestContext, startTestServer, cleanupTestContext, clearTestData, type TestContext, createTestConfig } from "./test-utils.ts";

describe("App Management API", () => {
  let ctx: TestContext;
  let apiUrl: string;
  let agentToken: string;
  let agentUsername: string;

  beforeAll(async () => {
    ctx = await createTestContext();
    await startTestServer(ctx);
    apiUrl = `http://localhost:${ctx.config.port}`;
  });

  afterAll(async () => {
    await cleanupTestContext(ctx);
  });

  beforeEach(async () => {
    await clearTestData(ctx.redis);
    // Create a test agent
    agentUsername = `testagent_${Date.now()}`;
    const registerResponse = await fetch(`${apiUrl}/auth/dev-register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: agentUsername })
    });
    expect(registerResponse.status).toBe(200);
    const registerResult = await registerResponse.json() as { token: string };
    agentToken = registerResult.token;
  });

  describe("App Creation", () => {
    it("Test 1.1: Should create a new app with valid name", async () => {
      const response = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "myapp" })
      });

      expect(response.status).toBe(200);
      const result = await response.json() as { 
        ok: boolean; 
        app: { name: string; createdAt: number; owner: string }; 
        key: string;
        hint: string;
      };
      expect(result.ok).toBe(true);
      expect(result.app.name).toBe("myapp");
      expect(result.app.owner).toBe(agentUsername);
      expect(result.key).toBeDefined();
      expect(result.key.length).toBeGreaterThan(0);
      expect(result.hint).toContain("Store this key securely");
    });

    it("Test 1.2: Should reject app creation without authentication", async () => {
      const response = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: "myapp" })
      });

      expect(response.status).toBe(401);
      const result = await response.json() as { error: string };
      expect(result.error).toBeDefined();
    });

    it("Test 1.3: Should reject app names with invalid characters", async () => {
      const invalidNames = ["my.app", "my-app", "my app", "a", "ab", "a".repeat(33)];
      
      for (const name of invalidNames) {
        const response = await fetch(`${apiUrl}/api/apps`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${agentToken}`
          },
          body: JSON.stringify({ name })
        });

        expect(response.status).toBe(400);
        const result = await response.json() as { error: string };
        expect(result.error).toContain("invalid app name");
      }
    });

    it("Test 1.4: Should reject duplicate app names", async () => {
      // Create first app
      const response1 = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "uniqueapp" })
      });
      expect(response1.status).toBe(200);

      // Try to create second app with same name
      const response2 = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "uniqueapp" })
      });

      expect(response2.status).toBe(409);
      const result = await response2.json() as { error: string };
      expect(result.error).toContain("already exists");
    });

    it("Test 1.5: Should reject duplicate app names from different owners", async () => {
      // Create first app
      const response1 = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "globalunique" })
      });
      expect(response1.status).toBe(200);

      // Create second agent
      const agent2Response = await fetch(`${apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: `testagent2_${Date.now()}` })
      });
      const agent2Result = await agent2Response.json() as { token: string };
      const agent2Token = agent2Result.token;

      // Try to create app with same name as different owner
      const response2 = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agent2Token}`
        },
        body: JSON.stringify({ name: "globalunique" })
      });

      expect(response2.status).toBe(409);
      const result = await response2.json() as { error: string };
      expect(result.error).toContain("already exists");
    });
  });

  describe("App Listing", () => {
    it("Test 2.1: Should list all apps owned by the agent", async () => {
      // Create some apps
      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "app1" })
      });

      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "app2" })
      });

      const response = await fetch(`${apiUrl}/api/apps`, {
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(response.status).toBe(200);
      const result = await response.json() as { 
        ok: boolean; 
        apps: { name: string; createdAt: number; owner: string }[]; 
        count: number 
      };
      expect(result.ok).toBe(true);
      expect(result.count).toBe(2);
      expect(result.apps.length).toBe(2);
      expect(result.apps.map(a => a.name).sort()).toEqual(["app1", "app2"]);
      expect(result.apps.every(a => a.owner === agentUsername)).toBe(true);
    });

    it("Test 2.2: Should return empty list when no apps exist", async () => {
      const response = await fetch(`${apiUrl}/api/apps`, {
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(response.status).toBe(200);
      const result = await response.json() as { 
        ok: boolean; 
        apps: { name: string; createdAt: number; owner: string }[]; 
        count: number 
      };
      expect(result.ok).toBe(true);
      expect(result.count).toBe(0);
      expect(result.apps).toEqual([]);
    });

    it("Test 2.3: Should reject listing without authentication", async () => {
      const response = await fetch(`${apiUrl}/api/apps`);

      expect(response.status).toBe(401);
    });
  });

  describe("App Details", () => {
    it("Test 3.1: Should get app details for owned app", async () => {
      // Create app
      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "myapp" })
      });

      const response = await fetch(`${apiUrl}/api/apps/myapp`, {
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(response.status).toBe(200);
      const result = await response.json() as { 
        ok: boolean; 
        app: { name: string; createdAt: number; owner: string };
      };
      expect(result.ok).toBe(true);
      expect(result.app.name).toBe("myapp");
      expect(result.app.owner).toBe(agentUsername);
      expect(result.app.createdAt).toBeDefined();
    });

    it("Test 3.2: Should return 404 for non-existent app", async () => {
      const response = await fetch(`${apiUrl}/api/apps/nonexistent`, {
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(response.status).toBe(404);
      const result = await response.json() as { error: string };
      expect(result.error).toContain("not found");
    });

    it("Test 3.3: Should reject viewing other agent's app", async () => {
      // Create app
      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "privateapp" })
      });

      // Create second agent
      const agent2Response = await fetch(`${apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: `testagent2_${Date.now()}` })
      });
      const agent2Result = await agent2Response.json() as { token: string };
      const agent2Token = agent2Result.token;

      // Try to view app as different owner
      const response = await fetch(`${apiUrl}/api/apps/privateapp`, {
        headers: { "Authorization": `Bearer ${agent2Token}` }
      });

      expect(response.status).toBe(403);
      const result = await response.json() as { error: string };
      expect(result.error).toContain("not authorized");
    });
  });

  describe("App Key Rotation", () => {
    it("Test 4.1: Should rotate app key successfully", async () => {
      // Create app
      const createResponse = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "myapp" })
      });
      const createResult = await createResponse.json() as { key: string };
      const oldKey = createResult.key;

      // Rotate key
      const rotateResponse = await fetch(`${apiUrl}/api/apps/myapp/rotate`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(rotateResponse.status).toBe(200);
      const rotateResult = await rotateResponse.json() as { 
        ok: boolean; 
        app: { name: string };
        key: string;
        hint: string;
      };
      expect(rotateResult.ok).toBe(true);
      expect(rotateResult.key).toBeDefined();
      expect(rotateResult.key).not.toBe(oldKey);
      expect(rotateResult.hint).toContain("old key has been revoked");
    });

    it("Test 4.2: Should reject rotation for non-existent app", async () => {
      const response = await fetch(`${apiUrl}/api/apps/nonexistent/rotate`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(response.status).toBe(404);
      const result = await response.json() as { error: string };
      expect(result.error).toContain("not found");
    });

    it("Test 4.3: Should reject rotation by non-owner", async () => {
      // Create app
      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "privateapp" })
      });

      // Create second agent
      const agent2Response = await fetch(`${apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: `testagent2_${Date.now()}` })
      });
      const agent2Result = await agent2Response.json() as { token: string };
      const agent2Token = agent2Result.token;

      const response = await fetch(`${apiUrl}/api/apps/privateapp/rotate`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${agent2Token}` }
      });

      expect(response.status).toBe(403);
      const result = await response.json() as { error: string };
      expect(result.error).toContain("not authorized");
    });
  });

  describe("App Deletion", () => {
    it("Test 5.1: Should delete app successfully", async () => {
      // Create app
      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "myapp" })
      });

      // Delete app
      const deleteResponse = await fetch(`${apiUrl}/api/apps/myapp`, {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(deleteResponse.status).toBe(200);
      const deleteResult = await deleteResponse.json() as { 
        ok: boolean; 
        deleted: boolean;
        appName: string;
      };
      expect(deleteResult.ok).toBe(true);
      expect(deleteResult.deleted).toBe(true);
      expect(deleteResult.appName).toBe("myapp");

      // Verify app is gone
      const getResponse = await fetch(`${apiUrl}/api/apps/myapp`, {
        headers: { "Authorization": `Bearer ${agentToken}` }
      });
      expect(getResponse.status).toBe(404);
    });

    it("Test 5.2: Should reject deletion for non-existent app", async () => {
      const response = await fetch(`${apiUrl}/api/apps/nonexistent`, {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      expect(response.status).toBe(404);
      const result = await response.json() as { error: string };
      expect(result.error).toContain("not found");
    });

    it("Test 5.3: Should reject deletion by non-owner", async () => {
      // Create app
      await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "privateapp" })
      });

      // Create second agent
      const agent2Response = await fetch(`${apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: `testagent2_${Date.now()}` })
      });
      const agent2Result = await agent2Response.json() as { token: string };
      const agent2Token = agent2Result.token;

      const response = await fetch(`${apiUrl}/api/apps/privateapp`, {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${agent2Token}` }
      });

      expect(response.status).toBe(403);
      const result = await response.json() as { error: string };
      expect(result.error).toContain("not authorized");
    });
  });

  describe("App Authentication", () => {
    it("Test 6.1: App key should authenticate successfully", async () => {
      // Create app
      const createResponse = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "myapp" })
      });
      const createResult = await createResponse.json() as { key: string };
      const appKey = createResult.key;

      // Use app key to check whoami (via publish endpoint)
      const publishResponse = await fetch(`${apiUrl}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${appKey}`
        },
        body: JSON.stringify({ 
          channel: "app.myapp.test", 
          payload: { test: true }
        })
      });

      expect(publishResponse.status).toBe(200);
    });

    it("Test 6.2: Old key should not work after rotation", async () => {
      // Create app
      const createResponse = await fetch(`${apiUrl}/api/apps`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${agentToken}`
        },
        body: JSON.stringify({ name: "myapp" })
      });
      const createResult = await createResponse.json() as { key: string };
      const oldKey = createResult.key;

      // Rotate key
      await fetch(`${apiUrl}/api/apps/myapp/rotate`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${agentToken}` }
      });

      // Try to use old key
      const publishResponse = await fetch(`${apiUrl}/api/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${oldKey}`
        },
        body: JSON.stringify({ 
          channel: "app.myapp.test", 
          payload: { test: true }
        })
      });

      expect(publishResponse.status).toBe(401);
    });
  });
});
