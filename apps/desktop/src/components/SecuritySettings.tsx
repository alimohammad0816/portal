import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api, type FirewallMode, type ProxyKind, type Settings, type Status } from "@/lib/api";
import { cn } from "@/lib/utils";

export function Choice({
  selected,
  title,
  description,
  onSelect,
}: {
  selected: boolean;
  title: string;
  description: string;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={onSelect}
      className={cn(
        "flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors",
        selected ? "border-foreground bg-subtle" : "hover:bg-subtle/60",
      )}
    >
      <span
        className={cn(
          "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border",
          selected ? "border-foreground" : "border-zinc-600",
        )}
      >
        {selected && <span className="size-2 rounded-full bg-foreground" />}
      </span>
      <span className="grid gap-0.5">
        <span className="text-[13.5px] font-medium">{title}</span>
        <span className="text-xs leading-5 text-muted-foreground">{description}</span>
      </span>
    </button>
  );
}

function Toggle({
  id,
  title,
  description,
  checked,
  onChange,
}: {
  id: string;
  title: string;
  description: string;
  checked: boolean;
  onChange: (on: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <Label htmlFor={id} className="grid gap-1 font-normal">
        <span className="text-[13.5px] font-medium">{title}</span>
        <span className="text-xs leading-5 text-muted-foreground">{description}</span>
      </Label>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

const MODES: { value: FirewallMode; title: string; description: string }[] = [
  {
    value: "auto",
    title: "Automatic",
    description: "Blocks traffic outside the VPN while connecting and connected. If the tunnel drops, it stays blocked until you reconnect or disconnect.",
  },
  {
    value: "always",
    title: "Always on",
    description: "Nothing leaves this computer except through the VPN, even when you're disconnected.",
  },
  { value: "off", title: "Off", description: "Apps can use your normal connection if the VPN isn't up." },
];

export function FirewallSettings({ settings, onChange }: { settings: Settings; onChange: (s: Settings) => void }) {
  return (
    <div className="grid gap-4 pt-1">
      <div role="radiogroup" aria-label="Firewall" className="grid gap-2">
        {MODES.map((m) => (
          <Choice
            key={m.value}
            selected={settings.firewall === m.value}
            title={m.title}
            description={m.description}
            onSelect={() => onChange({ ...settings, firewall: m.value })}
          />
        ))}
      </div>
      <Toggle
        id="allow-lan"
        title="Allow local network"
        description="Printers, file shares and other devices on your LAN stay reachable."
        checked={settings.allow_lan}
        onChange={(v) => onChange({ ...settings, allow_lan: v })}
      />
      <Toggle
        id="block-ipv6"
        title="Block IPv6 outside the VPN"
        description="Stops IPv6 traffic from going around a tunnel that only carries IPv4."
        checked={settings.block_ipv6}
        onChange={(v) => onChange({ ...settings, block_ipv6: v })}
      />
    </div>
  );
}

const PROXY_KINDS: { value: ProxyKind; label: string }[] = [
  { value: "profile", label: "Off" },
  { value: "http", label: "HTTP" },
  { value: "socks", label: "SOCKS5" },
];

/** Reach VPN servers through a proxy, e.g. on networks that only allow web traffic. */
export function ConnectionProxySettings({ settings, onChange }: { settings: Settings; onChange: (s: Settings) => void }) {
  const cp = settings.connection_proxy;
  const [host, setHost] = useState(cp.host);
  const [port, setPort] = useState(String(cp.port));
  const [error, setError] = useState<string | null>(null);
  const [savedLogin, setSavedLogin] = useState(false);
  useEffect(() => setHost(cp.host), [cp.host]);
  useEffect(() => setPort(String(cp.port)), [cp.port]);
  useEffect(() => {
    if (cp.auth) api.savedCredentials("").then((s) => setSavedLogin(s.proxy)).catch(() => {});
  }, [cp.auth]);

  // A type chosen while the address is still empty; saved once it's typed.
  const [pendingKind, setPendingKind] = useState<ProxyKind | null>(null);

  function save(next: Partial<Settings["connection_proxy"]>) {
    const merged = { ...cp, host: host.trim(), port: Number(port), ...next };
    if (merged.kind !== "profile") {
      if (!merged.host) {
        setError("Enter the proxy's address.");
        return;
      }
      if (!Number.isInteger(merged.port) || merged.port < 1 || merged.port > 65535) {
        setError("Use a port between 1 and 65535.");
        return;
      }
    }
    setError(null);
    setPendingKind(null);
    onChange({ ...settings, connection_proxy: merged });
  }

  const shownKind = pendingKind ?? cp.kind;
  const on = shownKind !== "profile";

  return (
    <div className="grid gap-3 rounded-xl border p-3">
      <div className="grid gap-1">
        <span className="text-[13.5px] font-medium">Connect through a proxy</span>
        <span className="text-xs leading-5 text-muted-foreground">
          For networks that only let web traffic out. Off uses the profile's own proxy, if it has one.
        </span>
      </div>
      <div role="radiogroup" aria-label="Proxy type" className="grid grid-cols-3 gap-1 rounded-lg bg-subtle p-1">
        {PROXY_KINDS.map((k) => (
          <button
            key={k.value}
            type="button"
            role="radio"
            aria-checked={shownKind === k.value}
            onClick={() => {
              if (k.value === "profile" || host.trim()) save({ kind: k.value });
              else setPendingKind(k.value);
            }}
            className={cn(
              "h-7 cursor-pointer rounded-md text-xs font-medium transition-colors",
              shownKind === k.value ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {k.label}
          </button>
        ))}
      </div>
      {on && (
        <>
          <div className="grid grid-cols-[minmax(0,1fr)_84px] gap-2">
            <Input
              aria-label="Proxy host"
              placeholder="proxy.example.com"
              value={host}
              onChange={(e) => {
                setHost(e.target.value);
                setError(null);
              }}
              onKeyDown={(e) => e.key === "Enter" && save({ kind: shownKind })}
              onBlur={() => host.trim() && save({ kind: shownKind })}
              className="h-8 font-mono text-[13.5px]"
            />
            <Input
              aria-label="Proxy port"
              inputMode="numeric"
              value={port}
              onChange={(e) => {
                setPort(e.target.value);
                setError(null);
              }}
              onKeyDown={(e) => e.key === "Enter" && save({ kind: shownKind })}
              onBlur={() => host.trim() && save({ kind: shownKind })}
              className="h-8 font-mono text-[13.5px]"
            />
          </div>
          <Toggle
            id="proxy-auth"
            title="Proxy needs a password"
            description={
              cp.auth && savedLogin
                ? "Your proxy sign-in is saved in your keyring."
                : "You'll be asked for it when connecting; it's kept in your keyring, not by the service."
            }
            checked={cp.auth}
            onChange={(v) => save({ kind: shownKind, auth: v })}
          />
          {cp.auth && savedLogin && (
            <div className="flex justify-end">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-muted-foreground"
                onClick={() => api.forgetCredentials("", "proxy").then(() => setSavedLogin(false)).catch(() => {})}
              >
                Forget proxy sign-in
              </Button>
            </div>
          )}
          {pendingKind && !host.trim() && !error && <span className="text-xs text-muted-foreground">Enter the proxy's address to turn it on.</span>}
          {cp.kind !== "profile" && <span className="text-xs text-muted-foreground">Applies the next time you connect.</span>}
        </>
      )}
      {error && <span className="text-xs text-destructive">{error}</span>}
    </div>
  );
}

export function GatewaySettings({
  settings,
  status,
  onChange,
}: {
  settings: Settings;
  status: Status;
  onChange: (s: Settings) => void;
}) {
  const gw = settings.proxy_gateway;
  const [port, setPort] = useState(String(gw.port));
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setPort(String(gw.port)), [gw.port]);

  function savePort() {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1024 || n > 65535) {
      setError("Use a port between 1024 and 65535.");
      return;
    }
    setError(null);
    onChange({ ...settings, proxy_gateway: { ...gw, port: n } });
  }

  return (
    <div className="grid gap-3 rounded-xl border p-3">
      <Toggle
        id="gateway"
        title="Proxy gateway"
        description="Let phones and other devices on your network use the VPN through this computer (SOCKS5 or HTTP proxy)."
        checked={gw.enabled}
        onChange={(v) => onChange({ ...settings, proxy_gateway: { ...gw, enabled: v } })}
      />
      <div className="flex items-center gap-2">
        <Label htmlFor="gateway-port" className="text-xs font-normal text-muted-foreground">
          Port
        </Label>
        <Input
          id="gateway-port"
          inputMode="numeric"
          value={port}
          onChange={(e) => {
            setPort(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && savePort()}
          onBlur={savePort}
          className="h-8 w-24 font-mono text-[13.5px]"
        />
        {error && <span className="text-xs text-destructive">{error}</span>}
      </div>
      {gw.enabled && (
        <p className="text-xs leading-5 text-muted-foreground">
          {status.proxy_address ? (
            <>
              Set the proxy on your devices to{" "}
              <span className="selectable font-mono text-foreground">{status.proxy_address}</span>.
            </>
          ) : (
            "Starts when the VPN connects."
          )}
        </p>
      )}
    </div>
  );
}

export function DnsSettings({
  settings,
  status,
  onChange,
}: {
  settings: Settings;
  status: Status;
  onChange: (s: Settings) => void;
}) {
  const custom = settings.dns.mode === "custom";
  const [draft, setDraft] = useState(settings.dns.mode === "custom" ? settings.dns.servers.join(", ") : "");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (settings.dns.mode === "custom") setDraft(settings.dns.servers.join(", "));
  }, [settings.dns]);

  function saveCustom() {
    const servers = draft
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (servers.length === 0) {
      setError("Enter at least one server, like 1.1.1.1.");
      return;
    }
    const bad = servers.find((s) => !/^[0-9a-fA-F:.]+$/.test(s));
    if (bad) {
      setError(`${bad} isn't an IP address.`);
      return;
    }
    setError(null);
    onChange({ ...settings, dns: { mode: "custom", servers } });
  }

  const savedCustom = settings.dns.mode === "custom" ? settings.dns.servers.join(", ") : "";

  return (
    <div className="grid gap-4 pt-1">
      <div role="radiogroup" aria-label="DNS servers" className="grid gap-2">
        <Choice
          selected={!custom}
          title="Use the VPN's DNS"
          description="The servers your VPN provider pushes when you connect."
          onSelect={() => onChange({ ...settings, dns: { mode: "vpn" } })}
        />
        <Choice
          selected={custom}
          title="Custom servers"
          description="Your own resolvers, reached through the tunnel."
          onSelect={() => !custom && setError("Enter servers and press Save.")}
        />
      </div>
      <div className="grid gap-2">
        <div className="flex gap-2">
          <Input
            aria-label="Custom DNS servers"
            placeholder="1.1.1.1, 9.9.9.9"
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
              setError(null);
            }}
            onKeyDown={(e) => e.key === "Enter" && saveCustom()}
            className="h-8 font-mono text-[13.5px]"
          />
          <Button size="sm" onClick={saveCustom} disabled={custom && draft === savedCustom}>
            Save
          </Button>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
      </div>
      <Toggle
        id="dns-guard"
        title="DNS leak protection"
        description="While connected, every lookup goes through the tunnel and DNS to anywhere else is blocked."
        checked={settings.dns_leak_protection}
        onChange={(v) => onChange({ ...settings, dns_leak_protection: v })}
      />
      <div className="rounded-lg border px-3 py-2.5 text-xs text-muted-foreground">
        {status.state === "connected" ? (
          status.dns_servers.length > 0 ? (
            <>
              In use: <span className="font-mono text-foreground">{status.dns_servers.join(", ")}</span>
            </>
          ) : (
            "The server didn't push DNS servers, so your system's DNS is in use. Add custom servers to keep lookups inside the tunnel."
          )
        ) : (
          "DNS settings apply when you connect."
        )}
      </div>
    </div>
  );
}
