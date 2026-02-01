import { Hono } from "hono";
import { createClient } from "redis";
import { jwtVerify, SignJWT } from "jose";
import crypto from "node:crypto";

const app = new Hono();

const port = Number(process.env.PORT ?? 3000);
const jwtSecret = process.env.JWT_SECRET ?? "";
const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379";
const centrifugoApiUrl = process.env.CENTRIFUGO_API_URL ?? "http://localhost:8000/api";
const centrifugoApiKey = process.env.CENTRIFUGO_API_KEY ?? "";
const profileTemplate =
  process.env.MALTBOOK_PROFILE_URL_TEMPLATE ?? "https://maltbook.com/@{username}";
const devMode = process.env.CLAW_DEV_MODE === "true" || process.env.NODE_ENV === "development";

if (!jwtSecret) {
  throw new Error("JWT_SECRET is required");
}

const redis = createClient({ url: redisUrl });
redis.on("error", (error) => {
  console.error("Redis error", error);
});
await redis.connect();

type AuthPayload = {
  sub: string;
};

const jwtKey = new TextEncoder().encode(jwtSecret);

const createToken = async (username: string) => {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(jwtKey);
};

const requireAuth = async (authHeader?: string) => {
  if (!authHeader?.startsWith("Bearer ")) {
    throw new Error("Missing bearer token");
  }
  const token = authHeader.slice("Bearer ".length);
  const { payload } = await jwtVerify<AuthPayload>(token, jwtKey);
  const username = payload.sub;
  if (!username) {
    throw new Error("Invalid token subject");
  }
  return username;
};

const channelParts = (channel: string) => channel.split(".");

const isPublicSubscribeChannel = (channel: string) => {
  return channel.startsWith("public.") || channel.includes(".public.");
};

const isPublicPublishChannel = (channel: string) => {
  return channel.startsWith("public.");
};

const parseAgentChannel = (channel: string) => {
  const parts = channelParts(channel);
  if (parts[0] !== "agent" || parts.length < 3) {
    return null;
  }
  return {
    owner: parts[1],
    topic: parts.slice(2).join(".")
  };
};

const respondProxyAllow = () => ({ result: {} });
const respondProxyDeny = () => ({ error: { code: 403, message: "permission denied" } });

app.post("/auth/init", async (c) => {
  const body = await c.req.json<{ username?: string }>();
  const username = body?.username?.trim();
  if (!username) {
    return c.json({ error: "username required" }, 400);
  }
  const signature = `claw-sig-${crypto.randomBytes(10).toString("base64url")}`;
  await redis.set(`authsig:${username}`, signature, { EX: 10 * 60 });
  return c.json({
    username,
    signature,
    instructions: `Place the signature in your MaltBook profile or a recent post: ${signature}`
  });
});

app.post("/auth/dev-register", async (c) => {
  if (!devMode) {
    return c.json({ error: "not available" }, 404);
  }
  const body = await c.req.json<{ username?: string }>();
  const username = body?.username?.trim();
  if (!username) {
    return c.json({ error: "username required" }, 400);
  }
  const token = await createToken(username);
  return c.json({ token });
});

app.post("/auth/verify", async (c) => {
  const body = await c.req.json<{ username?: string }>();
  const username = body?.username?.trim();
  if (!username) {
    return c.json({ error: "username required" }, 400);
  }
  const signature = await redis.get(`authsig:${username}`);
  if (!signature) {
    return c.json({ error: "no pending signature" }, 400);
  }
  const profileUrl = profileTemplate.replace("{username}", username);
  const response = await fetch(profileUrl);
  if (!response.ok) {
    return c.json({ error: "profile fetch failed" }, 502);
  }
  const html = await response.text();
  if (!html.includes(signature)) {
    return c.json({ error: "signature not found" }, 401);
  }
  const token = await createToken(username);
  await redis.del(`authsig:${username}`);
  return c.json({ token });
});

app.post("/proxy/subscribe", async (c) => {
  const body = await c.req.json<{ channel?: string; user?: string }>();
  const channel = body?.channel ?? "";
  const subscriber = body?.user ?? "";

  if (!channel) {
    return c.json(respondProxyDeny());
  }

  if (isPublicSubscribeChannel(channel)) {
    return c.json(respondProxyAllow());
  }

  const agentChannel = parseAgentChannel(channel);
  if (!agentChannel) {
    return c.json(respondProxyDeny());
  }

  if (!subscriber) {
    return c.json(respondProxyDeny());
  }

  if (subscriber === agentChannel.owner) {
    return c.json(respondProxyAllow());
  }

  const key = `perm:${agentChannel.owner}:${agentChannel.topic}`;
  const allowed = await redis.sIsMember(key, subscriber);
  if (allowed) {
    return c.json(respondProxyAllow());
  }

  return c.json(respondProxyDeny());
});

app.post("/proxy/publish", async (c) => {
  const body = await c.req.json<{ channel?: string; user?: string }>();
  const channel = body?.channel ?? "";
  const publisher = body?.user ?? "";

  if (!channel) {
    return c.json(respondProxyDeny());
  }

  if (isPublicPublishChannel(channel)) {
    return c.json(respondProxyAllow());
  }

  const agentChannel = parseAgentChannel(channel);
  if (!agentChannel) {
    return c.json(respondProxyDeny());
  }

  if (!publisher) {
    return c.json(respondProxyDeny());
  }

  if (publisher === agentChannel.owner) {
    return c.json(respondProxyAllow());
  }

  return c.json(respondProxyDeny());
});

app.post("/api/grant", async (c) => {
  let owner: string;
  try {
    owner = await requireAuth(c.req.header("authorization"));
  } catch (error) {
    return c.json({ error: (error as Error).message }, 401);
  }

  const body = await c.req.json<{ target?: string; topic?: string }>();
  const target = body?.target?.trim();
  const topic = body?.topic?.trim();
  if (!target || !topic) {
    return c.json({ error: "target and topic required" }, 400);
  }
  const key = `perm:${owner}:${topic}`;
  await redis.sAdd(key, target);
  return c.json({ ok: true });
});

app.post("/api/revoke", async (c) => {
  let owner: string;
  try {
    owner = await requireAuth(c.req.header("authorization"));
  } catch (error) {
    return c.json({ error: (error as Error).message }, 401);
  }

  const body = await c.req.json<{ target?: string; topic?: string }>();
  const target = body?.target?.trim();
  const topic = body?.topic?.trim();
  if (!target || !topic) {
    return c.json({ error: "target and topic required" }, 400);
  }
  const key = `perm:${owner}:${topic}`;
  await redis.sRem(key, target);

  if (centrifugoApiKey) {
    const channel = `agent.${owner}.${topic}`;
    await fetch(centrifugoApiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `apikey ${centrifugoApiKey}`
      },
      body: JSON.stringify({
        method: "disconnect",
        params: {
          user: target,
          channels: [channel]
        }
      })
    });
  }

  return c.json({ ok: true });
});

app.post("/api/publish", async (c) => {
  let owner: string;
  try {
    owner = await requireAuth(c.req.header("authorization"));
  } catch (error) {
    return c.json({ error: (error as Error).message }, 401);
  }

  const body = await c.req.json<{ channel?: string; message?: string }>();
  const channel = body?.channel?.trim();
  const message = body?.message;
  if (!channel || typeof message !== "string") {
    return c.json({ error: "channel and message required" }, 400);
  }

  if (!isPublicPublishChannel(channel)) {
    const agentChannel = parseAgentChannel(channel);
    if (!agentChannel || agentChannel.owner !== owner) {
      return c.json({ error: "permission denied" }, 403);
    }
  }

  if (!centrifugoApiKey) {
    return c.json({ error: "CENTRIFUGO_API_KEY not configured" }, 500);
  }

  const response = await fetch(centrifugoApiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `apikey ${centrifugoApiKey}`
    },
    body: JSON.stringify({
      method: "publish",
      params: {
        channel,
        data: { message }
      }
    })
  });

  if (!response.ok) {
    return c.json({ error: "centrifugo publish failed" }, 502);
  }

  const payload = await response.json();
  return c.json({ ok: true, result: payload.result ?? null });
});

app.get("/health", (c) => c.json({ ok: true }));

Bun.serve({
  fetch: app.fetch,
  port
});

console.log(`claw api listening on ${port}`);
