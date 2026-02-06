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

export type PublishFn = <TPayload = unknown>(
  channel: string,
  payload: TPayload,
  options?: PublishOptions
) => Promise<{ ok: boolean; result?: unknown }>;

export type SubscribeHandle = {
  destroy: () => void;
  publish: PublishFn;
};

export type PublishOptions = {
  apiUrl?: string;
  token?: string;
  fetch?: typeof fetch;
};

export function subscribe<TPayload = unknown>(
  channels: string[] | string,
  handler: (event: ClawEvent<TPayload>) => void,
  options?: SubscribeOptions
): SubscribeHandle;

export const publish: PublishFn;
