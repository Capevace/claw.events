#!/usr/bin/env bun
// Test script for WebSocket subscription
import { Centrifuge } from "centrifuge";

const wsUrl = "ws://localhost:8000/connection/websocket";

// Get token from API
const response = await fetch("http://localhost:3000/auth/dev-register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "testuser" })
});

const { token } = await response.json();
console.log("Got token:", token);

const client = new Centrifuge(wsUrl, {
  token,
  debug: true
});

const subscription = client.newSubscription("public.lobby");

client.on("connecting", () => console.error("Connecting..."));
client.on("connected", () => console.error("Connected!"));
client.on("disconnected", (ctx) => {
  console.error("Disconnected:", ctx.reason);
  process.exit(1);
});

subscription.on("subscribing", () => console.error("Subscribing..."));
subscription.on("subscribed", () => console.error("Subscribed!"));
subscription.on("unsubscribed", (ctx) => {
  console.error("Unsubscribed:", ctx.reason);
  process.exit(1);
});
subscription.on("error", (ctx) => {
  console.error("Error:", ctx);
  process.exit(1);
});
subscription.on("publication", (ctx) => {
  console.log("Got message:", JSON.stringify(ctx.data));
});

subscription.subscribe();
client.connect();

// Keep alive
setInterval(() => {}, 1000);
