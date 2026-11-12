import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";

import { mockInvoke, mockListen } from "./browser-mock";
import type { DaemonInfo, ImportResult, Profile, Settings, Status, UpdateInfo, Versions } from "./types";

export * from "./types";

type UnlistenFn = () => void;

/** True inside the Tauri webview; false in a plain browser during UI work. */
export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return (inTauri ? tauriInvoke<T>(cmd, args) : mockInvoke(cmd, args)) as Promise<T>;
}

async function listen<T>(event: string, cb: (e: { payload: T }) => void): Promise<UnlistenFn> {
  if (inTauri) return tauriListen<T>(event, cb);
  return mockListen(event, (payload) => cb({ payload: payload as T }));
}


export const api = {
  daemonInfo: () => invoke<DaemonInfo>("daemon_info"),
  listProfiles: () => invoke<Profile[]>("list_profiles"),
  importProfiles: (paths: string[]) => invoke<ImportResult>("import_profiles", { paths }),
  updateProfile: (id: string, name: string, group: string, country: string) =>
    invoke<Profile>("update_profile", { id, name, group, country }),
  removeProfile: (id: string) => invoke<void>("remove_profile", { id }),
  connect: (id: string, username = "", password = "", response = "") =>
    invoke<void>("connect", { id, username, password, response }),
  disconnect: () => invoke<void>("disconnect"),
  getStatus: () => invoke<Status>("get_status"),
  getLog: () => invoke<string[]>("get_log"),
  probeLatency: (host: string, port: number, proto: string) =>
    invoke<number | null>("probe_latency", { host, port, proto }),
  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) => invoke<Settings>("set_settings", { settings }),
  versions: () => invoke<Versions>("versions"),
  checkUpdate: () => invoke<UpdateInfo>("check_update"),
  installUpdate: () => invoke<string>("install_update"),
  restartApp: () => invoke<void>("restart_app"),
};

export function onStatus(cb: (s: Status) => void): Promise<UnlistenFn> {
  return listen<Status>("tunnel://status", (e) => cb(e.payload));
}

export function onLog(cb: (line: string) => void): Promise<UnlistenFn> {
  return listen<string>("tunnel://log", (e) => cb(e.payload));
}

export function onSettings(cb: (s: Settings) => void): Promise<UnlistenFn> {
  return listen<Settings>("tunnel://settings", (e) => cb(e.payload));
}

export function onDaemon(cb: (info: DaemonInfo) => void): Promise<UnlistenFn> {
  return listen<DaemonInfo>("tunnel://daemon", (e) => cb(e.payload));
}

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}
