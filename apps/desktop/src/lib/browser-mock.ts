/**
 * In-browser stand-in for the Tauri backend, used when the UI is opened with
 * plain `pnpm dev` in a browser (no Tauri, no daemon). Lets you work on the
 * interface without root or a VPN server.
 */
import type { DaemonInfo, ImportResult, Profile, Status } from "./types";
import { emptyStatus } from "./types";

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
}));

let status: Status = { ...emptyStatus };
const log: string[] = [];
let timers: number[] = [];

function setStatus(s: Partial<Status>) {
  status = { ...status, ...s };
  emit("tunnel://status", status);
}

function addLog(line: string) {
  log.push(line);
  emit("tunnel://log", line);
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
      setStatus({ state: "connected", detail: "CONNECTED", connected_since: now(), tunnel_ip: "10.8.0.6", server_ip: "203.0.113.24" });
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
      if (args.name) p.name = args.name as string;
      if (args.group) p.group = args.group as string;
      p.country = args.country === "-" ? null : ((args.country as string) || p.country);
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
      if (p.auth !== "certificate" && !args.username) throw "This profile needs a username and password.";
      p.last_connected_at = now();
      startSession(p.id);
      return null;
    }
    case "disconnect":
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
