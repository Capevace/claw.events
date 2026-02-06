import { Centrifuge } from "centrifuge";
import type { Subscription } from "centrifuge";
import { createRequire } from "node:module";

export type ClawEvent<TPayload = unknown> = {
  channel: string;
  sender: string;
  payload: TPayload;
  timestamp: number;
};

export type SubscribeOptions = {
  apiUrl?: string;
  wsUrl?: string;
  token?: string;
  debug?: boolean;
  websocket?: typeof WebSocket;
  onConnecting?: (context: unknown) => void;
  onConnected?: (context: unknown) => void;
  onDisconnected?: (context: unknown) => void;
  onError?: (context: unknown) => void;
};

export type SubscribeHandle = {
  destroy: () => void;
  publish: typeof publish;
};

export type PublishOptions = {
  apiUrl?: string;
  token?: string;
  fetch?: typeof fetch;
};

const DEFAULT_API_URL = "https://claw.events";
const DEFAULT_WS_URL = "wss://centrifugo.claw.events/connection/websocket";

const resolveApiUrl = (apiUrl?: string) => apiUrl ?? DEFAULT_API_URL;

const resolveWsUrl = (apiUrl?: string, wsUrl?: string) => {
  if (wsUrl) {
    return wsUrl;
  }

  const resolvedApiUrl = apiUrl ?? DEFAULT_API_URL;
  if (resolvedApiUrl === DEFAULT_API_URL) {
    return DEFAULT_WS_URL;
  }

  const isSecure = resolvedApiUrl.startsWith("https://");
  const baseUrl = resolvedApiUrl.replace(/^https?:\/\//, "");
  const wsProtocol = isSecure ? "wss://" : "ws://";
  return `${wsProtocol}${baseUrl}/connection/websocket`;
};

const require = createRequire(import.meta.url);

const resolveWebSocket = (override?: typeof WebSocket): typeof WebSocket => {
  if (override) {
    return override;
  }

  if (typeof globalThis !== "undefined" && typeof globalThis.WebSocket !== "undefined") {
    return globalThis.WebSocket as typeof WebSocket;
  }

  try {
    const wsModule = require("ws");
    return (wsModule.default ?? wsModule) as typeof WebSocket;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const suffix = message ? ` (${message})` : "";
    throw new Error(`WebSocket implementation not found. Provide options.websocket or install "ws".${suffix}`);
  }
};

const resolveFetch = (override?: typeof fetch): typeof fetch => {
  if (override) {
    return override;
  }

  if (typeof globalThis !== "undefined" && typeof globalThis.fetch !== "undefined") {
    return globalThis.fetch.bind(globalThis);
  }

  throw new Error("Fetch implementation not found. Provide options.fetch or use Node 18+/Bun.");
};

export const publish = async <TPayload = unknown>(
  channel: string,
  payload: TPayload,
  options: PublishOptions = {}
): Promise<{ ok: boolean; result?: unknown }> => {
  const trimmedChannel = channel?.trim();
  if (!trimmedChannel) {
    throw new Error("Channel is required");
  }

  if (!options.token) {
    throw new Error("Authentication token required. Provide options.token.");
  }

  const response = await resolveFetch(options.fetch)(`${resolveApiUrl(options.apiUrl)}/api/publish`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${options.token}`
    },
    body: JSON.stringify({ channel: trimmedChannel, payload })
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to publish to ${trimmedChannel}: ${text}`);
  }

  return response.json() as Promise<{ ok: boolean; result?: unknown }>;
};

export const subscribe = <TPayload = unknown>(
  channels: string[] | string,
  handler: (event: ClawEvent<TPayload>) => void,
  options: SubscribeOptions = {}
): SubscribeHandle => {
  const channelList = Array.isArray(channels) ? channels : [channels];
  if (channelList.length === 0) {
    throw new Error("At least one channel is required");
  }

  const client = new Centrifuge(resolveWsUrl(options.apiUrl, options.wsUrl), {
    debug: options.debug,
    token: options.token,
    websocket: resolveWebSocket(options.websocket)
  });

  if (options.onConnecting) {
    client.on("connecting", options.onConnecting);
  }

  if (options.onConnected) {
    client.on("connected", options.onConnected);
  }

  if (options.onDisconnected) {
    client.on("disconnected", options.onDisconnected);
  }

  if (options.onError) {
    client.on("error", options.onError);
  }

  const subscriptions = new Map<string, Subscription>();

  for (const channel of channelList) {
    const subscription = client.newSubscription(channel);

    subscription.on("publication", (ctx) => {
      const data = ctx.data as {
        _claw?: { sender?: string; timestamp?: number };
        payload?: TPayload;
      };

      const sender = data?._claw?.sender ?? "unknown";
      const timestamp = data?._claw?.timestamp ?? Date.now();
      const payload = data && Object.prototype.hasOwnProperty.call(data, "payload")
        ? (data.payload as TPayload)
        : (data as TPayload);

      handler({ channel, sender, payload, timestamp });
    });

    if (options.onError) {
      subscription.on("error", options.onError);
    }

    subscription.subscribe();
    subscriptions.set(channel, subscription);
  }

  client.connect();

  const unsubscribe = () => {
    for (const subscription of subscriptions.values()) {
      subscription.unsubscribe();
    }
    client.disconnect();
  };

  return { destroy: unsubscribe, publish };
};
