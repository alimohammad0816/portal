import { AlertCircle, Bug, Dices, Eye, EyeOff, Fish, Loader2, Pickaxe, Share2, ShieldOff } from "lucide-react";
import { useState } from "react";

import { HostList, hostKey, hostKind, Section, validHost } from "@/components/SplitSettings";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import type { BlockingSettings as Blocking, BlocklistStatus, Settings, Status } from "@/lib/api";
import { formatAgo } from "@/lib/format";
import { cn } from "@/lib/utils";

/** The daemon's categories (`portal_core::blocking::BLOCKLISTS`), in its order. */
const CATEGORIES = [
  { id: "malware", name: "Malware & phishing", hint: "Known malware, phishing and cryptojacking hosts.", icon: Bug },
  { id: "ads", name: "Ads & trackers", hint: "Ads, analytics and telemetry.", icon: Eye },
  { id: "social", name: "Social networks", hint: "Facebook, Instagram, TikTok, X and others.", icon: Share2 },
  { id: "adult", name: "Adult content", hint: "Porn and other adult sites.", icon: EyeOff },
  { id: "gambling", name: "Gambling", hint: "Betting, casinos and lotteries.", icon: Dices },
  { id: "scams", name: "Scams & fakes", hint: "Fake shops, scams and traps.", icon: Fish },
  { id: "vpn", name: "Other VPNs & proxies", hint: "VPN, proxy, Tor and encrypted DNS services.", icon: ShieldOff },
  { id: "crypto", name: "Crypto miners", hint: "Mining scripts on web pages.", icon: Pickaxe },
] as const;

const count = new Intl.NumberFormat("en-US");

function listLine(on: boolean, hint: string, st: BlocklistStatus | undefined) {
  if (!on) return <span>{hint}</span>;
  if (!st || (st.loading && st.domains === 0))
    return (
      <span className="flex items-center gap-1">
        <Loader2 className="size-3 animate-spin" />
        Downloading the list…
      </span>
    );
  if (st.domains === 0)
    return (
      <span className="flex min-w-0 items-center gap-1 text-destructive" title={st.error ?? undefined}>
        <AlertCircle className="size-3 shrink-0" />
        <span className="truncate">Couldn't download the list. It retries when you reconnect.</span>
      </span>
    );
  return (
    <span className="flex min-w-0 items-center gap-1" title={st.error ? `Last update failed: ${st.error}` : undefined}>
      {st.error && <AlertCircle className="size-3 shrink-0 text-warning" />}
      <span className="truncate">
        {count.format(st.domains)} domains · updated {formatAgo(st.updated_at).toLowerCase()}
      </span>
    </span>
  );
}

/** Domains typed by the user; blocking rules can't be IP addresses. */
function RuleSection({
  title,
  hint,
  placeholder,
  rules,
  onChange,
}: {
  title: string;
  hint: string;
  placeholder: string;
  rules: string[];
  onChange: (rules: string[]) => void;
}) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  function add() {
    const items = text
      .split(/[\s,]+/)
      .map((h) => h.trim())
      .filter(Boolean);
    if (items.length === 0) return;
    const bad = items.find((h) => !validHost(h) || !["Domain", "Wildcard"].includes(hostKind(h)));
    if (bad) {
      setError(`${bad} isn't a domain.`);
      return;
    }
    const next = [...rules];
    for (const h of items) if (!next.some((x) => hostKey(x) === hostKey(h))) next.push(h);
    onChange(next);
    setText("");
    setError(null);
  }

  return (
    <Section title={title} count={rules.length} hint={hint}>
      <div className="flex gap-2">
        <Input
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && add()}
          placeholder={placeholder}
          aria-label={`${title}: domain`}
          className="h-8 font-mono text-xs"
        />
        <Button size="sm" onClick={add}>
          Add
        </Button>
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {rules.length > 0 && (
        <HostList hosts={rules} label={`Filter ${title.toLowerCase()}`} onRemove={(h) => onChange(rules.filter((x) => x !== h))} />
      )}
    </Section>
  );
}

export function BlockingSettings({
  settings,
  status,
  onChange,
}: {
  settings: Settings;
  status: Status;
  onChange: (s: Settings) => void;
}) {
  const b = settings.blocking;
  const set = (patch: Partial<Blocking>) => onChange({ ...settings, blocking: { ...b, ...patch } });
  const active = b.lists.length > 0 || b.block.length > 0;
  const connected = status.state === "connected";

  function toggle(id: string, on: boolean) {
    // Keep the daemon's order so the settings file stays tidy.
    const ids = CATEGORIES.map((c) => c.id as string).filter((c) => (c === id ? on : b.lists.includes(c)));
    set({ lists: ids });
  }

  return (
    <div className="grid gap-3 pt-1">
      <div className="grid gap-1">
        <span className="text-[13.5px] font-medium">Blocking</span>
        <span className="text-xs leading-5 text-muted-foreground">
          {active && connected
            ? `On · ${count.format(status.blocked_queries)} lookup${status.blocked_queries === 1 ? "" : "s"} blocked this session.`
            : active
              ? "Starts when you connect, for every app on this computer."
              : "Block categories of sites for every app, through DNS, while you're connected."}
        </span>
      </div>

      <div className="grid rounded-xl border">
        {CATEGORIES.map((c) => {
          const on = b.lists.includes(c.id);
          const st = status.blocklists.find((l) => l.id === c.id);
          const Icon = c.icon;
          return (
            <label
              key={c.id}
              htmlFor={`block-${c.id}`}
              className="flex cursor-pointer items-center gap-3 border-b px-3 py-2.5 last:border-0"
            >
              <span
                className={cn(
                  "flex size-8 shrink-0 items-center justify-center rounded-lg border bg-subtle text-muted-foreground transition-colors",
                  on && "border-zinc-600 text-foreground",
                )}
              >
                <Icon className="size-4" />
              </span>
              <span className="grid min-w-0 flex-1 gap-0.5">
                <span className="text-[13.5px] font-medium">{c.name}</span>
                <span className="min-w-0 text-xs text-muted-foreground">{listLine(on, c.hint, st)}</span>
              </span>
              <Switch id={`block-${c.id}`} checked={on} onCheckedChange={(v) => toggle(c.id, v)} />
            </label>
          );
        })}
      </div>

      <RuleSection
        title="Always allow"
        hint="Never blocked, even when a list has them. *.example.com covers subdomains."
        placeholder="e.g. example.com, *.example.com"
        rules={b.allow}
        onChange={(allow) => set({ allow })}
      />
      <RuleSection
        title="Also block"
        hint="Blocked on top of the lists. example.com is just that name."
        placeholder="e.g. ads.example.com, *.example.net"
        rules={b.block}
        onChange={(block) => set({ block })}
      />

      <p className="text-[12px] leading-4 text-dim">
        Lists come from HaGeZi's DNS blocklists and NoCoin and refresh daily. Blocked names get an empty answer, so
        pages load without them. Browsers set to their own secure DNS skip blocking; keep DNS leak protection on.
      </p>
    </div>
  );
}
