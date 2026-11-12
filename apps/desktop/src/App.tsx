import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  ArrowUpCircle,
  Download,
  FileUp,
  Loader2,
  Power,
  RotateCw,
  Search,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { type Credentials, CredentialsDialog } from "@/components/CredentialsDialog";
import { type Latency, LocationList } from "@/components/LocationList";
import { SettingsDialog } from "@/components/SettingsDialog";
import { Sparkline } from "@/components/Sparkline";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { UpdateDialog } from "@/components/UpdateDialog";
import { WorldMap } from "@/components/WorldMap";
import {
  api,
  type DaemonInfo,
  defaultSettings,
  emptyStatus,
  errorText,
  inTauri,
  onDaemon,
  onLog,
  onSettings,
  onStatus,
  type Profile,
  type Settings,
  type Status,
  type UpdateInfo,
  type Versions,
} from "@/lib/api";
import { isNewer } from "@/lib/version";
import { formatDuration, formatRate } from "@/lib/format";
import { countryLocation, homeLocation } from "@/lib/geo";
import { cn } from "@/lib/utils";

type ListTab = "all" | "favorites" | "recent";
const FAV_KEY = "tunnel.favorites";
const AUTO_UPDATE_KEY = "tunnel.autoUpdate";
const HISTORY = 30;

function readPref(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : v === "1";
  } catch {
    return fallback;
  }
}

function writePref(key: string, value: boolean) {
  try {
    localStorage.setItem(key, value ? "1" : "0");
  } catch {
    /* not persisted; fine */
  }
}

function loadFavorites(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(FAV_KEY) ?? "[]"));
  } catch {
    return new Set();
  }
}

const STATE_TEXT: Record<Status["state"], string> = {
  disconnected: "Not connected",
  connecting: "Connecting…",
  needs_credentials: "Waiting for credentials…",
  connected: "Connected",
  disconnecting: "Disconnecting…",
};

export function App() {
  const [daemon, setDaemon] = useState<DaemonInfo | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [status, setStatus] = useState<Status>(emptyStatus);
  const [log, setLog] = useState<string[]>([]);
  const [tab, setTab] = useState<ListTab>("all");
  const [query, setQuery] = useState("");
  const [favorites, setFavorites] = useState<Set<string>>(loadFavorites);
  const [pickedId, setPickedId] = useState<string | null>(null);
  const [latency, setLatency] = useState<Record<string, Latency>>({});
  const [credsFor, setCredsFor] = useState<Profile | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState("split");
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [dragging, setDragging] = useState(false);
  const [rates, setRates] = useState<{ rx: number[]; tx: number[] }>({ rx: [], tx: [] });
  const [now, setNow] = useState(() => Date.now());
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [autoCheck, setAutoCheck] = useState(() => readPref(AUTO_UPDATE_KEY, true));
  const [checking, setChecking] = useState(false);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [updateOpen, setUpdateOpen] = useState(false);
  const [installing, setInstalling] = useState<string | null>(null);
  const [versions, setVersions] = useState<Versions | null>(null);

  const home = useMemo(homeLocation, []);

  const checkUpdates = useCallback(async () => {
    setChecking(true);
    try {
      setUpdateInfo(await api.checkUpdate());
      setUpdateError(null);
    } catch (e) {
      setUpdateError(errorText(e));
    } finally {
      setChecking(false);
    }
  }, []);

  const refreshVersions = useCallback(async () => {
    try {
      setVersions(await api.versions());
    } catch {
      /* daemon unreachable; shown elsewhere */
    }
  }, []);

  useEffect(() => {
    refreshVersions();
    if (!autoCheck) return;
    checkUpdates();
    const t = setInterval(checkUpdates, 6 * 3600 * 1000);
    return () => clearInterval(t);
  }, [autoCheck, checkUpdates, refreshVersions]);

  // After an update the service restarts first; this window is still the old build.
  const needsRestart = !!versions?.daemon && isNewer(versions.daemon, versions.app);

  const refreshProfiles = useCallback(async () => {
    try {
      setProfiles(await api.listProfiles());
    } catch (e) {
      setNotice(errorText(e));
    }
  }, []);

  const refreshAll = useCallback(async () => {
    const info = await api.daemonInfo();
    setDaemon(info);
    if (!info.reachable) return;
    const [p, s, l, st] = await Promise.all([api.listProfiles(), api.getStatus(), api.getLog(), api.getSettings()]);
    setProfiles(p);
    setStatus(s);
    setLog(l);
    setSettings(st);
  }, []);

  // Initial load and live updates from the daemon.
  useEffect(() => {
    refreshAll().catch((e) => setNotice(errorText(e)));
    const subs = [
      onStatus((s) => {
        setStatus(s);
        if (s.state === "connected") {
          setRates((r) => ({ rx: [...r.rx, s.rate_in].slice(-HISTORY), tx: [...r.tx, s.rate_out].slice(-HISTORY) }));
        } else if (s.state === "disconnected") {
          setRates({ rx: [], tx: [] });
        }
      }),
      onLog((line) => setLog((l) => [...l.slice(-999), line])),
      onSettings(setSettings),
      onDaemon((info) => {
        setDaemon(info);
        if (info.reachable) {
          refreshAll().catch(() => {});
          api.versions().then(setVersions).catch(() => {});
        }
      }),
    ];
    return () => {
      subs.forEach((p) => p.then((un) => un()));
    };
  }, [refreshAll]);

  // Session clock.
  useEffect(() => {
    if (status.state !== "connected") return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [status.state]);

  // Latency: measure while disconnected (through the tunnel the numbers lie).
  useEffect(() => {
    if (status.state !== "disconnected" || profiles.length === 0) return;
    let cancelled = false;
    const probe = () =>
      profiles.forEach((p) =>
        api
          .probeLatency(p.remote_host, p.remote_port, p.proto)
          .then((ms) => !cancelled && setLatency((l) => ({ ...l, [p.id]: ms })))
          .catch(() => !cancelled && setLatency((l) => ({ ...l, [p.id]: null }))),
      );
    probe();
    const t = setInterval(probe, 60_000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [profiles, status.state]);

  const importPaths = useCallback(
    async (paths: string[]) => {
      if (paths.length === 0) return;
      try {
        const res = await api.importProfiles(paths);
        await refreshProfiles();
        if (res.errors.length > 0) {
          setNotice(res.errors.map((e) => `${e.file}: ${e.message}`).join("\n"));
        } else {
          setNotice(null);
        }
        if (res.imported[0]) setPickedId(res.imported[0].id);
      } catch (e) {
        setNotice(errorText(e));
      }
    },
    [refreshProfiles],
  );

  // Drag and drop .ovpn files onto the window.
  useEffect(() => {
    if (!inTauri) return;
    const un = getCurrentWebview().onDragDropEvent((e) => {
      if (e.payload.type === "enter" || e.payload.type === "over") setDragging(true);
      else if (e.payload.type === "leave") setDragging(false);
      else if (e.payload.type === "drop") {
        setDragging(false);
        importPaths(e.payload.paths);
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, [importPaths]);

  async function pickFiles() {
    if (!inTauri) {
      setNotice("Importing needs the desktop app.");
      return;
    }
    const picked = await openDialog({
      multiple: true,
      directory: false,
      filters: [{ name: "OpenVPN profiles", extensions: ["ovpn", "conf"] }],
    });
    if (picked) importPaths(Array.isArray(picked) ? picked : [picked]);
  }

  const active = status.state !== "disconnected";
  const recentProfile = useMemo(
    () => [...profiles].sort((a, b) => (b.last_connected_at ?? 0) - (a.last_connected_at ?? 0))[0],
    [profiles],
  );
  const selectedId =
    (active ? status.profile_id : null) ?? pickedId ?? status.profile_id ?? recentProfile?.id ?? null;
  const selected = profiles.find((p) => p.id === selectedId) ?? null;

  async function doConnect(p: Profile, c?: Credentials) {
    setNotice(null);
    try {
      await api.connect(p.id, c?.username ?? "", c?.password ?? "", c?.response ?? "");
    } catch (e) {
      setNotice(errorText(e));
    }
  }

  function connectTo(p: Profile) {
    setPickedId(p.id);
    if (p.auth === "certificate") doConnect(p);
    else setCredsFor(p);
  }

  async function changeSettings(next: Settings) {
    const prev = settings;
    setSettings(next);
    try {
      setSettings(await api.setSettings(next));
    } catch (e) {
      setSettings(prev);
      setNotice(errorText(e));
    }
  }

  function openSettings(tab: string) {
    setSettingsTab(tab);
    setSettingsOpen(true);
  }

  async function disconnect() {
    try {
      await api.disconnect();
    } catch (e) {
      setNotice(errorText(e));
    }
  }

  function onPower() {
    if (status.state === "disconnected") {
      if (selected) connectTo(selected);
      else pickFiles();
    } else {
      disconnect();
    }
  }

  function onPick(p: Profile) {
    if (p.id === status.profile_id && active) return;
    connectTo(p);
  }

  function toggleFavorite(p: Profile) {
    setFavorites((f) => {
      const next = new Set(f);
      if (next.has(p.id)) next.delete(p.id);
      else next.add(p.id);
      try {
        localStorage.setItem(FAV_KEY, JSON.stringify([...next]));
      } catch {
        /* not persisted; fine */
      }
      return next;
    });
  }

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = profiles;
    if (tab === "favorites") list = list.filter((p) => favorites.has(p.id));
    if (tab === "recent")
      list = list
        .filter((p) => p.last_connected_at)
        .sort((a, b) => (b.last_connected_at ?? 0) - (a.last_connected_at ?? 0))
        .slice(0, 6);
    if (q)
      list = list.filter((p) =>
        [p.name, p.group, p.remote_host, p.country ?? ""].some((s) => s.toLowerCase().includes(q)),
      );
    return list;
  }, [profiles, tab, query, favorites]);

  const live = status.state === "connected";
  const busy = status.state === "connecting" || status.state === "disconnecting" || status.state === "needs_credentials";
  const statusColor = live ? "text-success" : busy ? "text-warning" : "text-muted-foreground";
  const mapLabel = live && selected ? `${selected.name}${selected.country ? `, ${selected.country}` : ""}` : busy ? "Connecting" : "Unprotected";
  const error = notice ?? status.error;

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden rounded-[14px] border bg-background">
      {/* Title bar */}
      <header data-tauri-drag-region className="flex h-[52px] shrink-0 items-center justify-between pr-2.5 pl-4">
        <div data-tauri-drag-region className="flex items-center gap-2.5">
          <div className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Shield className="size-3.5" strokeWidth={2.4} />
          </div>
          <span data-tauri-drag-region className="text-sm font-semibold tracking-tight">
            Tunnel
          </span>
        </div>
        <div className="flex items-center gap-0.5">
          {needsRestart ? (
            <Button size="sm" className="mr-1 h-7 rounded-full px-3 text-xs" onClick={() => api.restartApp()}>
              <RotateCw />
              Restart to update
            </Button>
          ) : installing ? (
            <span className="mr-1 flex h-7 items-center gap-1.5 rounded-full border px-3 text-xs text-muted-foreground">
              <Loader2 className="size-3 animate-spin" />
              Installing {installing}
            </span>
          ) : updateInfo?.available ? (
            <Button
              variant="outline"
              size="sm"
              className="mr-1 h-7 rounded-full px-3 text-xs"
              onClick={() => setUpdateOpen(true)}
            >
              <ArrowUpCircle />
              Update
            </Button>
          ) : null}
          <Button variant="ghost" size="icon" aria-label="Import profiles" onClick={pickFiles} className="text-muted-foreground">
            <Download />
          </Button>
          <Button variant="ghost" size="icon" aria-label="Settings" onClick={() => openSettings("firewall")} className="text-muted-foreground">
            <SlidersHorizontal />
          </Button>
          <button
            type="button"
            aria-label="Hide window"
            onClick={() => inTauri && getCurrentWindow().hide()}
            className="ml-1.5 flex size-6 cursor-pointer items-center justify-center rounded-full bg-accent text-muted-foreground hover:text-foreground"
          >
            <X className="size-3" strokeWidth={2.8} />
          </button>
        </div>
      </header>

      {/* Map */}
      <div className="px-4">
        <WorldMap
          home={home}
          server={countryLocation(selected?.country)}
          state={status.state}
          label={mapLabel}
          exitIp={live ? status.server_ip : null}
        />
      </div>

      {/* Status */}
      <div className="flex items-end justify-between gap-3 px-4 pt-4">
        <div className="min-w-0">
          <div className={cn("text-xs font-medium", statusColor)}>
            {STATE_TEXT[status.state]}
            {busy && status.detail ? <span className="text-dim"> · {status.detail.toLowerCase().replace("_", " ")}</span> : null}
          </div>
          <div className="mt-0.5 truncate text-2xl font-semibold tracking-[-0.03em]">{selected?.name ?? "No profile"}</div>
          <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
            {selected ? `${selected.remote_host} · ${selected.proto.toUpperCase()} ${selected.remote_port}` : "Import an .ovpn file to start"}
          </div>
        </div>
        <div className="shrink-0 pb-0.5 text-right text-xs text-muted-foreground">
          <div className="font-mono text-[13px] text-foreground">
            {live && status.connected_since ? formatDuration(now / 1000 - status.connected_since) : "--:--:--"}
          </div>
          <div>Session</div>
        </div>
      </div>

      <div className="px-4 pt-3">
        <Button
          size="lg"
          variant={status.state === "disconnected" ? "default" : busy ? "secondary" : "outline"}
          className="w-full"
          onClick={onPower}
          disabled={daemon?.reachable === false}
        >
          {busy ? <Loader2 className="animate-spin" /> : <Power />}
          {status.state === "disconnected" ? (selected ? "Connect" : "Import a profile") : busy ? "Cancel" : "Disconnect"}
        </Button>
        {error && (
          <div className="mt-2 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <span className="selectable flex-1 whitespace-pre-line">{error}</span>
            <button type="button" aria-label="Dismiss" className="cursor-pointer" onClick={() => setNotice(null)}>
              <X className="size-3.5" />
            </button>
          </div>
        )}
      </div>

      {status.internet_blocked && status.state === "disconnected" && (
        <div className="mx-4 mt-2 flex items-center gap-3 rounded-lg border px-3 py-2.5">
          <ShieldAlert className="size-4 shrink-0 text-warning" />
          <span className="flex-1 text-xs leading-5 text-muted-foreground">
            {settings.firewall === "always"
              ? "The firewall is always on: only the VPN can reach the internet."
              : "The VPN dropped, so the firewall is blocking the internet."}
          </span>
          {settings.firewall === "always" ? (
            <Button size="sm" variant="outline" onClick={() => openSettings("firewall")}>
              Change
            </Button>
          ) : (
            <Button size="sm" variant="outline" onClick={disconnect}>
              Unblock
            </Button>
          )}
        </div>
      )}

      {status.split_needs_reconnect && live && (
        <div className="mx-4 mt-2 flex items-center gap-3 rounded-lg border px-3 py-2.5">
          <span className="flex-1 text-xs leading-5 text-muted-foreground">
            Reconnect to switch split tunneling to {settings.split.enabled && settings.split.mode === "include" ? "Only listed" : "Exclude"} mode.
          </span>
          <Button size="sm" variant="outline" onClick={() => selected && connectTo(selected)}>
            Reconnect
          </Button>
        </div>
      )}

      {/* Stats */}
      <div className="mx-4 mt-3 grid grid-cols-3 rounded-xl border">
        <div className="flex flex-col gap-[3px] border-r px-3 py-2.5">
          <span className="text-xs text-muted-foreground">Download</span>
          <span className="text-sm font-medium tabular-nums">{live ? formatRate(status.rate_in) : "—"}</span>
          <Sparkline values={rates.rx} stroke="var(--foreground)" />
        </div>
        <div className="flex flex-col gap-[3px] border-r px-3 py-2.5">
          <span className="text-xs text-muted-foreground">Upload</span>
          <span className="text-sm font-medium tabular-nums">{live ? formatRate(status.rate_out) : "—"}</span>
          <Sparkline values={rates.tx} stroke="var(--dim)" />
        </div>
        <div className="flex min-w-0 flex-col gap-[3px] px-3 py-2.5">
          <span className="text-xs text-muted-foreground">Tunnel IP</span>
          <span className="truncate font-mono text-sm font-medium">{live ? (status.tunnel_ip ?? "—") : "—"}</span>
          <span className="truncate text-[11px] text-dim">{selected ? `${selected.proto.toUpperCase()} · ${authLabel(selected)}` : ""}</span>
        </div>
      </div>

      {/* Quick toggles */}
      <div className="mx-4 mt-2 grid grid-cols-3 rounded-xl border">
        <QuickToggle
          label="Firewall"
          sub={settings.firewall === "always" ? "Always on" : settings.firewall === "auto" ? (status.firewall_active ? "Blocking leaks" : "Automatic") : "Off"}
          checked={settings.firewall !== "off"}
          onChange={(on) => changeSettings({ ...settings, firewall: on ? "auto" : "off" })}
          onMore={() => openSettings("firewall")}
        />
        <QuickToggle
          label="Split"
          sub={splitSummary(settings)}
          checked={settings.split.enabled}
          onChange={(on) => changeSettings({ ...settings, split: { ...settings.split, enabled: on } })}
          onMore={() => openSettings("split")}
          divider
        />
        <QuickToggle
          label="LAN"
          sub={settings.allow_lan ? "Allowed" : "Blocked"}
          checked={settings.allow_lan}
          onChange={(on) => changeSettings({ ...settings, allow_lan: on })}
          onMore={() => openSettings("firewall")}
          divider
        />
      </div>

      {/* Locations */}
      <div className="mt-3.5 flex min-h-0 flex-1 flex-col border-t">
        <div className="flex items-center gap-2 px-4 pt-3 pb-2">
          <Tabs value={tab} onValueChange={(v) => setTab(v as ListTab)}>
            <TabsList>
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="favorites">Favorites</TabsTrigger>
              <TabsTrigger value="recent">Recent</TabsTrigger>
            </TabsList>
          </Tabs>
          <label className="flex h-8 min-w-0 flex-1 items-center gap-2 rounded-md border px-2.5 text-dim focus-within:border-ring">
            <Search className="size-3.5 shrink-0" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search"
              aria-label="Search locations"
              className="min-w-0 flex-1 bg-transparent text-[13px] text-foreground outline-none placeholder:text-dim"
            />
          </label>
        </div>
        <div className="scroll-subtle fade-bottom min-h-0 flex-1 overflow-y-auto px-2 pb-5">
          {daemon && !daemon.reachable ? (
            <DaemonDown info={daemon} onRetry={() => refreshAll().catch(() => {})} />
          ) : profiles.length === 0 ? (
            <EmptyState onImport={pickFiles} />
          ) : visible.length === 0 ? (
            <p className="px-3 py-8 text-center text-[13px] text-muted-foreground">
              {tab === "favorites" ? "Star a location to keep it here." : tab === "recent" ? "Locations you connect to show up here." : "No locations match your search."}
            </p>
          ) : (
            <LocationList
              profiles={visible}
              selectedId={selectedId}
              latency={latency}
              favorites={favorites}
              onPick={onPick}
              onToggleFavorite={toggleFavorite}
            />
          )}
        </div>
      </div>

      {dragging && (
        <div className="pointer-events-none absolute inset-2 flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-ring bg-background/90">
          <FileUp className="size-6 text-muted-foreground" />
          <span className="text-sm font-medium">Drop to import</span>
          <span className="text-xs text-muted-foreground">.ovpn and .conf files</span>
        </div>
      )}

      <CredentialsDialog
        profile={credsFor}
        onCancel={() => setCredsFor(null)}
        onSubmit={(c) => {
          const p = credsFor;
          setCredsFor(null);
          if (p) doConnect(p, c);
        }}
      />
      <SettingsDialog
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        profiles={profiles}
        log={log}
        onProfilesChanged={refreshProfiles}
        settings={settings}
        status={status}
        onSettingsChange={changeSettings}
        tab={settingsTab}
        onTabChange={setSettingsTab}
        updates={{
          autoCheck,
          onAutoCheckChange: (on) => {
            setAutoCheck(on);
            writePref(AUTO_UPDATE_KEY, on);
          },
          info: updateInfo,
          daemonVersion: versions?.daemon ?? null,
          checking,
          error: updateError,
          onCheckNow: checkUpdates,
          onShowUpdate: () => {
            setSettingsTab("about");
            setSettingsOpen(false);
            setUpdateOpen(true);
          },
        }}
      />
      <UpdateDialog
        release={updateInfo?.available ?? null}
        current={updateInfo?.current ?? versions?.app ?? ""}
        open={updateOpen}
        onOpenChange={setUpdateOpen}
        onInstalling={(v) => setInstalling(v)}
      />
    </div>
  );
}

function splitSummary(settings: Settings): string {
  const s = settings.split;
  if (!s.enabled) return "Off";
  const n = s.apps.length + s.hosts.length + s.countries.length;
  const rules = n === 1 ? "1 rule" : `${n} rules`;
  return s.mode === "exclude" ? `Excluding ${rules}` : `Only ${rules}`;
}

function QuickToggle({
  label,
  sub,
  checked,
  onChange,
  onMore,
  divider,
}: {
  label: string;
  sub: string;
  checked: boolean;
  onChange: (on: boolean) => void;
  onMore: () => void;
  divider?: boolean;
}) {
  return (
    <div className={cn("flex min-w-0 items-center justify-between gap-2 px-3 py-2.5", divider && "border-l")}>
      <button type="button" onClick={onMore} className="min-w-0 cursor-pointer text-left">
        <div className="text-[13px] font-medium">{label}</div>
        <div className="truncate text-[11px] text-muted-foreground">{sub}</div>
      </button>
      <Switch checked={checked} onCheckedChange={onChange} aria-label={label} />
    </div>
  );
}

function authLabel(p: Profile): string {
  return p.auth === "certificate" ? "Certificate" : p.auth === "user_pass" ? "Password" : "Password + OTP";
}

function EmptyState({ onImport }: { onImport: () => void }) {
  return (
    <div className="mx-2 mt-3 flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-8 text-center">
      <div className="flex size-10 items-center justify-center rounded-lg border bg-subtle text-muted-foreground">
        <FileUp className="size-[18px]" />
      </div>
      <div className="grid gap-1">
        <span className="text-sm font-medium">Import your first profile</span>
        <span className="text-xs text-muted-foreground">Drop .ovpn files here, or pick them from disk.</span>
      </div>
      <Button size="sm" onClick={onImport}>
        Import
      </Button>
    </div>
  );
}

function DaemonDown({ info, onRetry }: { info: DaemonInfo; onRetry: () => void }) {
  return (
    <div className="mx-2 mt-3 grid gap-3 rounded-xl border px-4 py-4">
      <div className="grid gap-1">
        <span className="text-sm font-medium">Can't reach the Tunnel service</span>
        <span className="text-xs text-muted-foreground">
          The app talks to <span className="font-mono">tunneld</span> on the {info.bus} bus. Start it, then retry.
        </span>
      </div>
      <code className="selectable rounded-md bg-subtle px-3 py-2 font-mono text-[11px] text-zinc-300">
        {info.bus === "system" ? "sudo systemctl start tunneld" : "cargo run -p tunneld -- --session --mock"}
      </code>
      {info.error && <span className="selectable font-mono text-[11px] text-dim">{info.error}</span>}
      <Button variant="outline" size="sm" className="justify-self-start" onClick={onRetry}>
        Retry
      </Button>
    </div>
  );
}
