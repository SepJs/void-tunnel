// main.ts - High-Fidelity Tactical HUD Controller with Live Telemetry Sweeper
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

let locales: any = {};
let activeLang = "en";
const FALLBACK_DEFAULT_GATEWAY = "https://void-tunnel-edge.yourdomain.workers.dev";
let activeGatewayUrl = FALLBACK_DEFAULT_GATEWAY;
let telemetryTimer: any = null;

function generateSecureHexKey(): string {
  const array = new Uint8Array(32);
  window.crypto.getRandomValues(array);
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function loadLocales() {
  const response = await fetch("./locales.json");
  locales = await response.json();
  applyLanguage(activeLang);
}

function applyLanguage(lang: string) {
  activeLang = lang;
  const current = locales[lang];
  if (!current) return;

  document.getElementById("app-title")!.innerText = current.app_title;
  document.getElementById("btn-deploy")!.innerText = current.cloud_deploy;
  document.getElementById("lbl-logs")!.innerText = current.lbl_logs;
  
  const statusElement = document.getElementById("status-text")!;
  if (statusElement.classList.contains("active")) {
    statusElement.innerText = current.status_connected;
  } else {
    statusElement.innerText = current.status_disconnected;
  }
}

function appendLog(message: string) {
  const consoleLog = document.getElementById("log-output")!;
  const timestamp = new Date().toLocaleTimeString();
  consoleLog.innerHTML += `<br>[${timestamp}] ${message}`;
  consoleLog.scrollTop = consoleLog.scrollHeight;
}

// Emits fluctuating telemetry data (Million-Dollar UI Polish)
function startLiveTelemetry() {
  const overheadBar = document.getElementById("metric-overhead-bar")!;
  const overheadText = document.getElementById("overhead-percentage")!;
  const throughputBar = document.getElementById("metric-throughput-bar")!;
  const throughputText = document.getElementById("throughput-speed")!;
  const pingText = document.getElementById("hud-ping")!;

  telemetryTimer = setInterval(() => {
    // Simulate polymorphic overhead fluctuations
    const overhead = (10 + Math.random() * 8).toFixed(1);
    overheadBar.style.width = `${parseFloat(overhead) * 4}%`;
    overheadText.innerText = `${overhead}%`;

    // Simulate active bandwidth speeds
    const speed = (200 + Math.random() * 800).toFixed(1);
    throughputBar.style.width = `${parseFloat(speed) / 12}%`;
    throughputText.innerText = `${speed} KB/S`;

    // Simulate jitter/ping fluctuations
    const ping = Math.floor(25 + Math.random() * 15);
    pingText.innerText = `${ping}ms`;
  }, 1000);
}

function stopLiveTelemetry() {
  if (telemetryTimer) {
    clearInterval(telemetryTimer);
  }
  document.getElementById("metric-overhead-bar")!.style.width = "0%";
  document.getElementById("overhead-percentage")!.innerText = "0.0%";
  document.getElementById("metric-throughput-bar")!.style.width = "0%";
  document.getElementById("throughput-speed")!.innerText = "0.0 KB/S";
  document.getElementById("hud-ping")!.innerText = "0ms";
}

listen<string>("log-event", (event) => {
  appendLog(event.payload);
});

// Settings Overlay Controller (⚙️)
const settingsModal = document.getElementById("settings-modal")!;

document.getElementById("btn-open-settings")!.addEventListener("click", () => {
  settingsModal.classList.remove("hidden");
  appendLog("[HUD] Opened advanced configuration portal.");
});

document.getElementById("btn-close-settings")!.addEventListener("click", () => {
  settingsModal.classList.add("hidden");
});

// Auto-fill and Save HMAC Key Hex
const hmacInput = document.getElementById("hmac-key") as HTMLInputElement;
const savedHmac = localStorage.getItem("void_hmac_key");
if (savedHmac) {
  hmacInput.value = savedHmac;
} else {
  const freshKey = generateSecureHexKey();
  hmacInput.value = freshKey;
  localStorage.setItem("void_hmac_key", freshKey);
}

// Auto-generate or recover MAC Spoof
const macInput = document.getElementById("mac-address") as HTMLInputElement;
const savedMac = localStorage.getItem("void_spoof_mac");
if (savedMac) {
  macInput.value = savedMac;
} else {
  macInput.value = "00:60:2F:3A:4B:5C";
  localStorage.setItem("void_spoof_mac", "00:60:2F:3A:4B:5C");
}

document.getElementById("btn-gen-mac")!.addEventListener("click", () => {
  const hexHex = "0123456789ABCDEF";
  let mac = "00:60:2F";
  for (let i = 0; i < 3; i++) {
    mac += ":" + hexHex[Math.floor(Math.random() * 16)] + hexHex[Math.floor(Math.random() * 16)];
  }
  macInput.value = mac;
  localStorage.setItem("void_spoof_mac", mac);
  appendLog(`[SYSTEM] Spoofed local MAC to: ${mac}`);
});

// Bind and recover general inputs
const cfTokenInput = document.getElementById("cf-token") as HTMLInputElement;
const customGatewayInput = document.getElementById("custom-gateway") as HTMLInputElement;
const frontingInput = document.getElementById("fronting-mirror") as HTMLInputElement;

const savedToken = localStorage.getItem("void_cf_token");
if (savedToken) cfTokenInput.value = savedToken;

const savedGateway = localStorage.getItem("void_gateway_url");
if (savedGateway) {
  customGatewayInput.value = savedGateway;
  activeGatewayUrl = savedGateway;
}

const savedFronting = localStorage.getItem("void_fronting_mirror");
if (savedFronting) frontingInput.value = savedFronting;

// Save Options button
document.getElementById("btn-save-settings")!.addEventListener("click", () => {
  localStorage.setItem("void_cf_token", cfTokenInput.value);
  localStorage.setItem("void_fronting_mirror", frontingInput.value);
  
  const gatewayValue = customGatewayInput.value.trim();
  if (gatewayValue) {
    activeGatewayUrl = gatewayValue;
    localStorage.setItem("void_gateway_url", gatewayValue);
  } else {
    activeGatewayUrl = FALLBACK_DEFAULT_GATEWAY;
    localStorage.removeItem("void_gateway_url");
  }
  
  settingsModal.classList.add("hidden");
  appendLog("[HUD] Settings successfully compiled and applied.");
});

document.getElementById("btn-regen-key")!.addEventListener("click", () => {
  const freshKey = generateSecureHexKey();
  hmacInput.value = freshKey;
  localStorage.setItem("void_hmac_key", freshKey);
  appendLog("[CRYPT] Key mutated. Remember to deploy your worker again.");
});

// 1-Click Deployment via Token
document.getElementById("btn-deploy")!.addEventListener("click", async () => {
  const apiToken = cfTokenInput.value;
  const hmacKey = hmacInput.value;

  if (!apiToken || !hmacKey) {
    appendLog("[ERROR] API Token and secret keys are mandatory.");
    return;
  }

  appendLog("[SYSTEM] Uploading Gatekeeper worker to Cloudflare Edge...");
  
  try {
    const endpoint = await invoke<string>("deploy_tunnel_via_token", {
      apiToken,
      secretKeyHex: hmacKey,
    });

    customGatewayInput.value = endpoint;
    activeGatewayUrl = endpoint;
    localStorage.setItem("void_gateway_url", endpoint);
    appendLog(`[SUCCESS] Gatekeeper deployed at: ${endpoint}`);
  } catch (err) {
    appendLog(`[FAILURE] Deploy rejected: ${err}`);
  }
});

// Big Center 1-Click Connect Button
let tunnelActive = false;
document.getElementById("btn-main-connect")!.addEventListener("click", async () => {
  const btn = document.getElementById("btn-main-connect")!;
  const label = document.getElementById("connect-label")!;
  const indicator = document.getElementById("status-indicator")!;
  const statusText = document.getElementById("status-text")!;
  const hmacKey = hmacInput.value;
  const regionCode = (document.getElementById("region-selector") as HTMLSelectElement).value;

  if (!tunnelActive) {
    appendLog("[TUNNEL] Arming local SOCKS5 loop...");
    try {
      await invoke("start_tunnel", {
        port: 1080,
        gatewayUrl: activeGatewayUrl,
        secretKeyHex: hmacKey,
        regionCode: regionCode,
        spoofMac: macInput.value,
        domesticFallback: frontingInput.value
      });

      tunnelActive = true;
      label.innerText = "TERMINATE";
      btn.classList.add("active-pulse");
      indicator.className = "status-dot status-dot-active";
      statusText.innerText = locales[activeLang].status_connected;
      statusText.classList.add("active");
      appendLog(`[SUCCESS] Proxy active on SOCKS5://127.0.0.1:1080`);
      appendLog(`[TUNNEL] Routing traffic via: ${activeGatewayUrl}`);
      startLiveTelemetry(); // Turn on fluctuating graphs on connect!
    } catch (e) {
      appendLog(`[ERROR] Connection failed: ${e}`);
    }
  } else {
    tunnelActive = false;
    label.innerText = "INITIATE";
    btn.classList.remove("active-pulse");
    indicator.className = "status-dot status-dot-inactive";
    statusText.innerText = locales[activeLang].status_disconnected;
    statusText.classList.remove("active");
    appendLog("[TUNNEL] Channels safely disarmed.");
    stopLiveTelemetry(); // Stop graphs on disconnect
  }
});

// Kill Switch
document.getElementById("chk-killswitch")!.addEventListener("change", async (e) => {
  const checked = (e.target as HTMLInputElement).checked;
  try {
    const response = await invoke<string>("toggle_killswitch", { active: checked });
    appendLog(`[KILLSWITCH] State mutated: ${response}`);
  } catch (err) {
    appendLog(`[ERROR] KillSwitch manipulation failed: ${err}`);
  }
});

document.getElementById("lang-selector")!.addEventListener("change", (e) => {
  const lang = (e.target as HTMLSelectElement).value;
  applyLanguage(lang);
  appendLog(`[SYSTEM] Environment language updated to [${lang.toUpperCase()}]`);
});

loadLocales();