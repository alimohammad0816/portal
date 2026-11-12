/**
 * In-browser stand-in for the Tauri backend, used when the UI is opened with
 * plain `pnpm dev` in a browser (no Tauri, no daemon). Lets you work on the
 * interface without root or a VPN server.
 */
import type { ConnectInput, DaemonInfo, ImportResult, Profile, ProfileEdit, Status } from "./types";
import { defaultPrefs, defaultSettings, emptyStatus, type Prefs, type Settings as SettingsT } from "./types";

type Handler = (payload: unknown) => void;
const handlers = new Map<string, Set<Handler>>();

function emit(event: string, payload: unknown) {
  for (const h of handlers.get(event) ?? []) h(payload);
}

const now = () => Math.floor(Date.now() / 1000);

const profiles: Profile[] = [
  ["DE", "Frankfurt", "de-fra-02.provider-a.net", "udp", 1194, "Provider A", "user_pass"],
  ["NL", "Amsterdam", "nl-ams-01.provider-a.net", "udp", 1194, "Provider A", "user_pass"],
  ["FI", "Helsinki", "fi-hel-03.provider-a.net", "tcp", 443, "Provider A", "user_pass"],
  ["TR", "Istanbul office", "vpn.office.example", "udp", 1194, "Work", "user_pass_challenge"],
  ["SE", "Stockholm (key)", "se-sto-01.example.org", "udp", 1194, "Personal", "certificate"],
  ["CA", "Toronto", "ca-tor-02.example.org", "udp", 1194, "Personal", "certificate"],
  ["US", "New York", "us-nyc-07.example.org", "tcp", 443, "Personal", "certificate"],
].map(([country, name, host, proto, port, group, auth], i) => ({
  id: `mock${i}`,
  name: name as string,
  group: group as string,
  country: country as string,
  remote_host: host as string,
  remote_port: port as number,
  proto: proto as string,
  auth: auth as Profile["auth"],
  challenge: auth === "user_pass_challenge" ? "Enter OTP" : null,
  source_file: `${(host as string).split(".")[0]}.ovpn`,
  imported_at: now() - 86400 * 3,
  last_connected_at: i === 0 ? now() - 3600 : i === 3 ? now() - 7200 : null,
  key_encrypted: (name as string).includes("(key)"),
  disable_dco: false,
  extra_directives: "",
}));

let settings: SettingsT = { ...defaultSettings };
let status: Status = { ...emptyStatus };
let blockedAfterDrop = false;
/** Keyring slots: profile id, `id:key`, `connection-proxy`. */
const saved = new Set<string>();
/** A dynamic challenge is waiting (username `challenge` acts it out). */
let pendingChallenge: string | null = null;
let prefs: Prefs = { ...defaultPrefs };

function firewallFields(s: Status): Partial<Status> {
  const active = s.state !== "disconnected";
  const block = settings.firewall === "always" || (settings.firewall === "auto" && (active || blockedAfterDrop));
  return { firewall_active: block, internet_blocked: block && s.state !== "connected" };
}
const log: string[] = [];
let timers: number[] = [];

function setStatus(s: Partial<Status>) {
  status = { ...status, ...s };
  status = { ...status, ...firewallFields(status) };
  emit("portal://status", status);
}

function addLog(line: string) {
  log.push(line);
  emit("portal://log", line);
}

function clearTimers() {
  timers.forEach((t) => clearTimeout(t));
  timers = [];
}

function startSession(id: string) {
  clearTimers();
  setStatus({ ...emptyStatus, state: "connecting", profile_id: id, detail: "RESOLVE" });
  ["WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP"].forEach((d, i) =>
    timers.push(window.setTimeout(() => {
      setStatus({ detail: d });
      addLog(`MOCK: ${d}`);
    }, 250 * (i + 1))),
  );
  timers.push(
    window.setTimeout(() => {
      setStatus({
        state: "connected",
        detail: "CONNECTED",
        connected_since: now(),
        tunnel_ip: "10.8.0.6",
        server_ip: "203.0.113.24",
        dns_servers: settings.dns.mode === "custom" ? settings.dns.servers : ["10.8.0.1"],
        split_active: settings.split.enabled,
        proxy_address: settings.proxy_gateway.enabled ? `192.168.1.50:${settings.proxy_gateway.port}` : null,
      });
      addLog("MOCK: Initialization Sequence Completed");
      let rx = 0;
      let tx = 0;
      const tick = () => {
        const rin = 5_000_000 + Math.random() * 5_000_000;
        const rout = 700_000 + Math.random() * 800_000;
        rx += rin;
        tx += rout;
        setStatus({ bytes_in: rx, bytes_out: tx, rate_in: rin, rate_out: rout });
        timers.push(window.setTimeout(tick, 1000));
      };
      tick();
    }, 1400),
  );
}

export const mockInvoke = async (cmd: string, args: Record<string, unknown> = {}): Promise<unknown> => {
  switch (cmd) {
    case "daemon_info":
      return { bus: "session", reachable: true, error: null } satisfies DaemonInfo;
    case "list_profiles":
      return profiles.map((p) => ({ ...p }));
    case "get_status":
      return status;
    case "get_log":
      return [...log];
    case "import_profiles":
      return { imported: [], errors: [{ file: "browser", message: "Importing needs the desktop app." }] } satisfies ImportResult;
    case "update_profile": {
      const p = profiles.find((x) => x.id === args.id);
      if (!p) throw "No such profile";
      const e = args.edit as ProfileEdit;
      if (e.name) p.name = e.name;
      if (e.group) p.group = e.group;
      if (e.country !== undefined) p.country = e.country === "-" ? null : e.country || p.country;
      if (e.disable_dco !== undefined) p.disable_dco = e.disable_dco;
      if (e.extra_directives !== undefined) {
        if (/^\s*(up|down|script-security|plugin)\b/m.test(e.extra_directives))
          throw "Extra options: line 1: `up` is not allowed in imported profiles";
        p.extra_directives = e.extra_directives.trim() ? e.extra_directives.trim() + "\n" : "";
      }
      return { ...p };
    }
    case "remove_profile": {
      const i = profiles.findIndex((x) => x.id === args.id);
      if (i >= 0) profiles.splice(i, 1);
      return null;
    }
    case "connect": {
      const p = profiles.find((x) => x.id === args.id);
      if (!p) throw "No such profile";
      const input = (args.input ?? {}) as ConnectInput;
      const keep = (slot: string, given: boolean) => {
        if (given && args.remember) saved.add(slot);
        if (given && args.remember === false) saved.delete(slot);
      };
      keep(p.id, !!input.username);
      keep(`${p.id}:key`, !!input.key_passphrase);
      keep("connection-proxy", !!input.proxy_username);
      if (p.auth !== "certificate" && !input.username && !saved.has(p.id))
        throw "This profile needs a username and password.";
      clearTimers();
      if (p.key_encrypted && !input.key_passphrase && !saved.has(`${p.id}:key`)) {
        setStatus({ ...emptyStatus, state: "needs_credentials", profile_id: p.id, request: { kind: "key_passphrase", message: null, echo: false } });
        return null;
      }
      if (input.username === "challenge") {
        pendingChallenge = p.id;
        setStatus({
          ...emptyStatus,
          state: "needs_credentials",
          profile_id: p.id,
          request: { kind: "challenge", message: "Enter the code from your authenticator app", echo: true },
        });
        return null;
      }
      p.last_connected_at = now();
      startSession(p.id);
      return null;
    }
    case "answer_challenge": {
      if (!pendingChallenge) throw "Nothing is waiting for an answer.";
      const id = pendingChallenge;
      pendingChallenge = null;
      if (args.response !== "123456") {
        setStatus({ ...emptyStatus, profile_id: id, error: "Authentication failed. Check your username and password." });
        return null;
      }
      startSession(id);
      return null;
    }
    case "get_settings":
      return settings;
    case "get_prefs":
      return prefs;
    case "set_prefs":
      prefs = args.prefs as Prefs;
      return prefs;
    case "current_network":
      return { name: "Home Wi-Fi", wireless: true };
    case "exit_info":
      await new Promise((r) => setTimeout(r, 400));
      return { ip: "185.107.56.12", country_code: "DE", city: "Frankfurt am Main", latitude: 50.11, longitude: 8.68 };
    case "saved_credentials": {
      const id = args.id as string;
      return { login: saved.has(id), key: saved.has(`${id}:key`), proxy: saved.has("connection-proxy") };
    }
    case "forget_credentials": {
      const id = args.id as string;
      const kind = args.kind as string | undefined;
      if (!kind || kind === "login") saved.delete(id);
      if (!kind || kind === "key") saved.delete(`${id}:key`);
      if (kind === "proxy") saved.delete("connection-proxy");
      return null;
    }
    case "list_apps":
      return [
        ["Firefox", "/usr/bin/firefox"],
        ["qBittorrent", "/usr/bin/qbittorrent"],
        ["Steam", "/usr/games/steam"],
        ["Telegram Desktop", "/usr/bin/telegram-desktop"],
        ["Thunderbird", "/usr/bin/thunderbird"],
        ["Visual Studio Code", "/usr/share/code/code"],
      ].map(([name, path]) => ({ name, path, icon: null }));
    case "set_settings":
      {
        const prev = settings;
        settings = args.settings as SettingsT;
        if (status.state === "connected") {
          const include = (x: SettingsT) => x.split.enabled && x.split.mode === "include";
          const reconnect = include(prev) !== include(settings) || status.split_needs_reconnect;
          setStatus({ split_needs_reconnect: reconnect, split_active: settings.split.enabled && !reconnect });
        }
      }
      if (settings.firewall !== "auto") blockedAfterDrop = false;
      emit("portal://settings", settings);
      setStatus({});
      return settings;
    case "simulate_drop":
      clearTimers();
      blockedAfterDrop = settings.firewall === "auto";
      setStatus({ ...emptyStatus, profile_id: status.profile_id, error: "The connection ended unexpectedly." });
      return null;
    case "disconnect":
      pendingChallenge = null;
      blockedAfterDrop = false;
      clearTimers();
      setStatus({ state: "disconnecting" });
      timers.push(window.setTimeout(() => setStatus({ ...emptyStatus, profile_id: status.profile_id }), 300));
      return null;
    case "probe_latency": {
      const host = args.host as string;
      await new Promise((r) => setTimeout(r, 200 + Math.random() * 400));
      if (host.startsWith("us-")) return null;
      return 40 + ((host.length * 37) % 140);
    }
    case "versions":
      return { app: "0.1.0", daemon: "0.1.0" };
    case "check_update":
      return {
        current: "0.1.0",
        enabled: true,
        available: {
          version: "0.2.0",
          notes: "- Kill switch\n- DNS leak protection",
          url: "https://github.com/",
          published_at: new Date().toISOString(),
        },
      };
    case "install_update":
      await new Promise((r) => setTimeout(r, 1500));
      return "0.2.0";
    case "restart_app":
      location.reload();
      return null;
    default:
      throw `unknown command ${cmd}`;
  }
};

export function mockListen(event: string, cb: Handler): () => void {
  const set = handlers.get(event) ?? new Set();
  set.add(cb);
  handlers.set(event, set);
  return () => set.delete(cb);
}
