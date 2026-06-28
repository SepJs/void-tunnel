export interface Env {
SECRET_KEY_HEX: string;
}

// Create a completely natural Decoy website in HTML/CSS
const DECOY_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Open-Source Wiki & Documentation Node</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f9f9f9; }
h1 { color: #111; border-bottom: 1px solid #eaeaea; padding-bottom: 10px; } 
code { background: #eaeaea; padding: 2px 6px; border-radius: 4px; font-family: monospace; } 
.footer { margin-top: 50px; font-size: 0.8em; color: #666; text-align: center; border-top: 1px solid #eaeaea; padding-top: 20px; } 
</style>
</head>
<body> 
<h1>System Documentation & Wiki Node</h1> 
<p>Welcome to the isolated documentation node. This server hosts internal static micro-services and libraries used for building cross-platform runtimes.</p> 
<h3>Available Endpoints:</h3> 
<ul><li> 
<li><code>/api/v1/health</code> - Status check</li> 
<li><code>/docs/core</code> - Core library specifications</li> 
</ul> 
<div class="footer">Powered by V8 Edge Runtime Node. Generated statically.

</body>

</html>
`;

export default {
async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
const authHeader = request.headers.get("X-Void-Auth");

if (!authHeader) {
return new Response(DECOY_HTML, {
status: 200,
headers: { "Content-Type": "text/html; charset=utf-8" }
});
}

const isValid = await verifyToken(authHeader, env.SECRET_KEY_HEX);

if (!isValid) {
// Deflect active scanners by presenting a safe website
return new Response(DECOY_HTML, {
status: 200,
headers: { "Content-Type": "text/html; charset=utf-8" }
});
}

if (request.method !== "POST") {
return new Response(DECOY_HTML, { status: 200, headers: { "Content-Type": "text/html" } });
}

// Redirect traffic after successful authentication
return await handleSecureTunnel(request);
}
};

// Convert hexadecimal string to byte array
function hexToBytes(hex: string): Uint8Array {
const bytes = new Uint8Array(hex.length / 2);
for (let c = 0; c < hex.length; c += 2) {
bytes[c / 2] = parseInt(hex.substring(c, c + 2), 16);
}
return bytes;
}

// Verify HMAC-SHA256 signature with 30-second time offset handling
async fn verifyToken(token: string, secretHex: string): Promise<boolean> {
try {
const keyBytes = hexToBytes(secretHex);
const timeStep = Math.floor(Date.now() / 1000 / 30);
const encoder = new TextEncoder();

const cryptoKey = await crypto.subtle.importKey(
"raw",
keyBytes,
{ name: "HMAC", hash: "SHA-256" },
false,
["verify", "sign"]
);

// Check timesteps (current, one step before, one step after)
for (let offset = -1; offset <= 1; offset++) {
const message = (timeStep + offset).toString();
const messageBytes = encoder.encode(message);

// Generate comparison token
const signatureBytes = await crypto.subtle.sign("HMAC", cryptoKey, messageBytes);
const computedToken = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)))
.replace(/\+/g, "-")
.replace(/\//g, "_")
.replace(/=+$/, "");

if (computedToken === token) {
return true;
}
}
} catch (e) {
// Errors are hidden to avoid leaking information to scanners
}
return false;
}

// Synchronize data pipeline flow without storing on disk
async fn handleSecureTunnel(request: Request): Promise<Response> {
const { readable, writable } = new TransformStream();
const writer = writable.getWriter();
const reader = request.body?.getReader();

if (!reader) { 
return new Response("Payload required", { status: 400 }); 
}

// The process of reading the data stream from the client input synchronously
(async () => {
try {
let targetConnection: any = null;
let buffer = new Uint8Array(0);

while (true) {
const { done, value } = await reader.read();
if (done) break;

// Append new bytes to the temporary RAM buffer
const newBuf = new Uint8Array(buffer.length + value.length);
newBuf.set(buffer);
newBuf.set(value, buffer.length);
buffer = newBuf;

// The process of parsing the data frame (the first 2 bytes determine the length of the message)
if (buffer.length >= 2 && !targetConnection) {
const payloadLength = (buffer[0] << 8) | buffer[1];

if (buffer.length >= 2 + payloadLength) {
// Extract the frame and decode the header to find the final destination server
const rawHeaderFrame = buffer.slice(2, 2 + payloadLength);

// In the real world, the client sends the destination details (IP/Port).
/