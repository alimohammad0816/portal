import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";

import { mockInvoke, mockListen } from "./browser-mock";
import type {
  ConnectInput,
  DaemonInfo,
  ExitInfo,
  ImportResult,
  InstalledApp,
  Network,
  Prefs,
  Profile,
  ProfileEdit,
  SavedCredentials,
  Settings,
  Status,
  UpdateInfo,
  Versions,
} from "./types";

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
  updateProfile: (id: string, edit: ProfileEdit) => invoke<Profile>("update_profile", { id, edit }),
  removeProfile: (id: string) => invoke<void>("remove_profile", { id }),
  connect: (id: string, input?: ConnectInput, remember?: boolean, name?: string) =>
    invoke<void>("connect", { id, input: input ?? {}, remember, name }),
  answerChallenge: (response: string) => invoke<void>("answer_challenge", { response }),
  savedCredentials: (id: string) => invoke<SavedCredentials>("saved_credentials", { id }),
  forgetCredentials: (id: string, kind?: "login" | "key" | "proxy") =>
    invoke<void>("forget_credentials", { id, kind }),
  disconnect: () => invoke<void>("disconnect"),
  getStatus: () => invoke<Status>("get_status"),
  getLog: () => invoke<string[]>("get_log"),
  probeLatency: (host: string, port: number, proto: string) =>
    invoke<number | null>("probe_latency", { host, port, proto }),
  getSettings: () => invoke<Settings>("get_settings"),
  listApps: () => invoke<InstalledApp[]>("list_apps"),
  getPrefs: () => invoke<Prefs>("get_prefs"),
  setPrefs: (prefs: Prefs) => invoke<Prefs>("set_prefs", { prefs }),
  currentNetwork: () => invoke<Network | null>("current_network"),
  exitInfo: () => invoke<ExitInfo>("exit_info"),
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

export function onNetwork(cb: (n: Network | null) => void): Promise<UnlistenFn> {
  return listen<Network | null>("tunnel://network", (e) => cb(e.payload));
}

export function onNeedsCredentials(cb: (profileId: string) => void): Promise<UnlistenFn> {
  return listen<{ profile_id: string }>("tunnel://needs-credentials", (e) => cb(e.payload.profile_id));
}

export function onDaemon(cb: (info: DaemonInfo) => void): Promise<UnlistenFn> {
  return listen<DaemonInfo>("tunnel://daemon", (e) => cb(e.payload));
}

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}
