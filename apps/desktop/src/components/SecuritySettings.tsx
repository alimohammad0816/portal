import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { FirewallMode, Settings, Status } from "@/lib/api";
import { cn } from "@/lib/utils";

function Choice({
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
        <span className="text-[13px] font-medium">{title}</span>
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
        <span className="text-[13px] font-medium">{title}</span>
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
            className="h-8 font-mono text-[13px]"
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
