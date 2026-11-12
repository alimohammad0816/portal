import { Asterisk, Globe, ListFilter, MapPin, Network, Plus, RefreshCw, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Choice } from "@/components/SecuritySettings";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollFade } from "@/components/ui/scroll-fade";
import { Switch } from "@/components/ui/switch";
import { api, errorText, type InstalledApp, type Settings, type SplitSettings as Split, type Status } from "@/lib/api";
import { cn } from "@/lib/utils";

const COUNTRIES: Record<string, string> = {
  IR: "Iran", TR: "Türkiye", AE: "United Arab Emirates", IQ: "Iraq", AF: "Afghanistan", AM: "Armenia",
  AZ: "Azerbaijan", RU: "Russia", CN: "China", DE: "Germany", NL: "Netherlands", GB: "United Kingdom",
  US: "United States", CA: "Canada", FR: "France",
};

export function hostKind(h: string): "CIDR" | "IP" | "Wildcard" | "Domain" {
  if (h.includes("/")) return "CIDR";
  if (/^[0-9.]+$/.test(h) || (h.includes(":") && /^[0-9a-fA-F:.]+$/.test(h))) return "IP";
  if (h.startsWith("*.")) return "Wildcard";
  return "Domain";
}

const KIND_ICON = { Domain: Globe, Wildcard: Asterisk, IP: MapPin, CIDR: Network } as const;

/** `*.example.com` and `example.com` are the same rule. */
function hostKey(h: string): string {
  return h.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
}

function validHost(h: string): boolean {
  const kind = hostKind(h);
  if (kind === "CIDR") {
    const [addr, len] = h.split("/");
    const n = Number(len);
    return /^[0-9a-fA-F:.]+$/.test(addr) && Number.isInteger(n) && n >= 0 && n <= (addr.includes(":") ? 128 : 32);
  }
  if (kind === "IP") return true;
  return /^(\*\.)?[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*\.?$/.test(h);
}

function AppPicker({
  open,
  onOpenChange,
  taken,
  onPick,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  taken: Set<string>;
  onPick: (a: InstalledApp) => void;
}) {
  const [apps, setApps] = useState<InstalledApp[] | null>(null);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || apps) return;
    api.listApps().then(setApps).catch((e) => setError(errorText(e)));
  }, [open, apps]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (apps ?? []).filter((a) => !q || a.name.toLowerCase().includes(q) || a.path.toLowerCase().includes(q));
  }, [apps, query]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-none content-start gap-3">
        <DialogHeader>
          <DialogTitle>Add an app</DialogTitle>
          <DialogDescription>Its traffic, and its child processes', follows the split rules.</DialogDescription>
        </DialogHeader>
        <label className="flex h-8 items-center gap-2 rounded-md border px-2.5 text-dim focus-within:border-ring">
          <Search className="size-3.5" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search apps"
            aria-label="Search apps"
            className="min-w-0 flex-1 bg-transparent text-[13.5px] text-foreground outline-none placeholder:text-dim"
          />
        </label>
        <ScrollFade className="-mx-1 h-80 overflow-y-auto px-1">
          {error && <p className="py-6 text-center text-xs text-destructive">{error}</p>}
          {!apps && !error && <p className="py-6 text-center text-xs text-muted-foreground">Looking for apps…</p>}
          {apps && shown.length === 0 && <p className="py-6 text-center text-xs text-muted-foreground">No apps match.</p>}
          {shown.map((a) => {
            const added = taken.has(a.path);
            return (
              <button
                key={a.path}
                type="button"
                disabled={added}
                onClick={() => onPick(a)}
                className="flex w-full cursor-pointer items-center gap-3 rounded-lg px-2 py-1.5 text-left hover:bg-subtle disabled:cursor-default disabled:opacity-50"
              >
                <AppGlyph name={a.name} />
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="truncate text-[13.5px] font-medium">{a.name}</span>
                  <span className="truncate font-mono text-[12px] text-dim">{a.path}</span>
                </span>
                {added ? <span className="text-[12px] text-muted-foreground">Added</span> : <Plus className="size-3.5 text-muted-foreground" />}
              </button>
            );
          })}
        </ScrollFade>
      </DialogContent>
    </Dialog>
  );
}

function AppGlyph({ name }: { name: string }) {
  return (
    <span className="flex size-7 shrink-0 items-center justify-center rounded-md border bg-subtle text-[12.5px] font-semibold">
      {name.charAt(0).toUpperCase()}
    </span>
  );
}

function Section({
  title,
  hint,
  count,
  action,
  children,
}: {
  title: string;
  hint: string;
  count?: number;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="grid gap-2 rounded-xl border p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="grid gap-0.5">
          <span className="flex items-center gap-1.5 text-[13.5px] font-semibold">
            {title}
            {!!count && (
              <span className="rounded bg-accent px-1.5 text-[11px] leading-[18px] font-medium text-muted-foreground tabular-nums">
                {count}
              </span>
            )}
          </span>
          <span className="text-xs text-muted-foreground">{hint}</span>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function RemoveButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      className="flex size-7 shrink-0 cursor-pointer items-center justify-center rounded-md text-dim hover:bg-accent hover:text-foreground"
    >
      <X className="size-3.5" />
    </button>
  );
}

function Chip({ icon, label, title, onRemove }: { icon?: React.ReactNode; label: React.ReactNode; title: string; onRemove: () => void }) {
  return (
    <li title={title} className="flex h-7 max-w-full items-center gap-1.5 rounded-md border bg-subtle/60 pr-0.5 pl-2">
      {icon}
      <span className="selectable min-w-0 truncate font-mono text-xs">{label}</span>
      <button
        type="button"
        aria-label={`Remove ${title}`}
        onClick={onRemove}
        className="flex size-6 shrink-0 cursor-pointer items-center justify-center rounded text-dim hover:bg-accent hover:text-foreground"
      >
        <X className="size-3" />
      </button>
    </li>
  );
}

/** Rules as wrapping chips in a box that scrolls on its own once it fills,
 * with a filter when there are many. */
function HostList({ hosts, onRemove }: { hosts: string[]; onRemove: (h: string) => void }) {
  const [filter, setFilter] = useState("");
  const q = filter.trim().toLowerCase();
  const shown = q ? hosts.filter((h) => h.toLowerCase().includes(q)) : hosts;
  return (
    <div className="grid gap-2">
      {hosts.length > 8 && (
        <label className="flex h-7 items-center gap-2 rounded-md border px-2 text-dim focus-within:border-ring">
          <ListFilter className="size-3.5" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={`Filter ${hosts.length} entries`}
            aria-label="Filter sites and IP ranges"
            className="min-w-0 flex-1 bg-transparent font-mono text-xs text-foreground outline-none placeholder:font-sans placeholder:text-dim"
          />
        </label>
      )}
      <ScrollFade className="-mx-1 max-h-[142px] overflow-y-auto px-1">
        <ul className="flex flex-wrap gap-1.5">
          {shown.map((h) => {
            const kind = hostKind(h);
            const Icon = KIND_ICON[kind];
            return (
              <Chip
                key={h}
                title={`${h} (${kind})`}
                icon={<Icon className="size-3 shrink-0 text-dim" />}
                label={h}
                onRemove={() => onRemove(h)}
              />
            );
          })}
        </ul>
        {q && shown.length === 0 && <p className="py-1 text-xs text-dim">Nothing matches.</p>}
      </ScrollFade>
    </div>
  );
}

/** Rule changes reach new connections at once; this moves open ones too. */
function ApplyBar({ pending }: { pending: boolean }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!message) return;
    const t = setTimeout(() => setMessage(null), 5000);
    return () => clearTimeout(t);
  }, [message]);

  async function apply() {
    setBusy(true);
    try {
      const n = await api.applySplit();
      setMessage(
        n === 0
          ? "Every open connection already follows the rules."
          : `Closed ${n} connection${n === 1 ? "" : "s"}. Apps reconnect with the current rules.`,
      );
    } catch (e) {
      setMessage(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={cn("flex items-center gap-3 rounded-xl border px-3 py-2.5", pending && "border-zinc-600 bg-subtle")}>
      <span className="grid min-w-0 flex-1 gap-0.5" aria-live="polite">
        <span className="text-[13px] font-medium">{pending ? "Open connections use older rules" : "Open connections"}</span>
        <span className="text-xs leading-4 text-muted-foreground">
          {message ??
            (pending
              ? "Removed rules and app changes reach them when you apply."
              : "Added rules move them right away. Apply restarts the rest.")}
        </span>
      </span>
      <Button size="sm" variant={pending ? "default" : "outline"} disabled={busy} onClick={apply}>
        <RefreshCw className={cn(busy && "animate-spin")} />
        Apply
      </Button>
    </div>
  );
}

export function SplitSettings({
  settings,
  status,
  onChange,
}: {
  settings: Settings;
  status: Status;
  onChange: (s: Settings) => void;
}) {
  const split = settings.split;
  const set = (patch: Partial<Split>) => onChange({ ...settings, split: { ...split, ...patch } });
  const [pickerOpen, setPickerOpen] = useState(false);
  const [host, setHost] = useState("");
  const [hostError, setHostError] = useState<string | null>(null);
  const [country, setCountry] = useState("");

  function addHost() {
    const items = host
      .split(/[\s,]+/)
      .map((h) => h.trim())
      .filter(Boolean);
    if (items.length === 0) return;
    const bad = items.find((h) => !validHost(h));
    if (bad) {
      setHostError(`${bad} isn't a domain, IP address or network.`);
      return;
    }
    const next = [...split.hosts];
    for (const h of items) if (!next.some((x) => hostKey(x) === hostKey(h))) next.push(h);
    set({ hosts: next });
    setHost("");
    setHostError(null);
  }

  function addCountry(code: string) {
    const c = code.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(c) || split.countries.includes(c)) return;
    set({ countries: [...split.countries, c] });
    setCountry("");
  }

  const exclude = split.mode === "exclude";

  return (
    <div className="grid gap-3 pt-1">
      <div className="flex items-center justify-between gap-4">
        <Label htmlFor="split-on" className="grid gap-1 font-normal">
          <span className="text-[13.5px] font-medium">Split tunneling</span>
          <span className="text-xs leading-5 text-muted-foreground">
            {status.split_active
              ? `On${status.split_processes ? ` · ${status.split_processes} processes split` : ""}. Changes apply live.`
              : "Choose apps and sites that skip the VPN, or the only ones that use it."}
          </span>
        </Label>
        <Switch id="split-on" checked={split.enabled} onCheckedChange={(v) => set({ enabled: v })} />
      </div>

      {status.split_active && <ApplyBar pending={status.split_pending} />}

      <div className={cn("grid gap-3", !split.enabled && "pointer-events-none opacity-45")}>
        <div role="radiogroup" aria-label="Split mode" className="grid grid-cols-2 gap-2">
          <Choice
            selected={exclude}
            title="Exclude"
            description="Everything uses the VPN except what's listed."
            onSelect={() => set({ mode: "exclude" })}
          />
          <Choice
            selected={!exclude}
            title="Only listed"
            description="Only what's listed uses the VPN."
            onSelect={() => set({ mode: "include" })}
          />
        </div>

        <Section
          title="Apps"
          count={split.apps.length}
          hint={exclude ? "These apps skip the VPN." : "Only these apps use the VPN."}
          action={
            <Button size="sm" variant="outline" onClick={() => setPickerOpen(true)}>
              <Plus />
              Add app
            </Button>
          }
        >
          {split.apps.length === 0 ? (
            <p className="text-xs text-dim">No apps yet.</p>
          ) : (
            <ScrollFade className="-mx-1 grid max-h-[176px] overflow-y-auto px-1">
              {split.apps.map((a) => (
                <div key={a.path} className="flex items-center gap-3 rounded-lg py-1">
                  <AppGlyph name={a.name} />
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate text-[13.5px] font-medium">{a.name}</span>
                    <span className="truncate font-mono text-[12px] text-dim">{a.path}</span>
                  </span>
                  <RemoveButton label={`Remove ${a.name}`} onClick={() => set({ apps: split.apps.filter((x) => x.path !== a.path) })} />
                </div>
              ))}
            </ScrollFade>
          )}
          <p className="text-[12px] leading-4 text-dim">
            Or start any program this way: <span className="selectable font-mono text-muted-foreground">portal bypass -- firefox</span>
          </p>
        </Section>

        <Section
          title="Sites and IP ranges"
          count={split.hosts.length}
          hint="Domains include their subdomains; *.ir covers a whole TLD."
        >
          <div className="flex gap-2">
            <Input
              value={host}
              onChange={(e) => {
                setHost(e.target.value);
                setHostError(null);
              }}
              onKeyDown={(e) => e.key === "Enter" && addHost()}
              placeholder="e.g. *.ir, example.com, 10.0.0.0/8"
              aria-label="Domain, IP address or network"
              className="h-8 font-mono text-xs"
            />
            <Button size="sm" onClick={addHost}>
              Add
            </Button>
          </div>
          {hostError && <p className="text-xs text-destructive">{hostError}</p>}
          {split.hosts.length > 0 && (
            <HostList hosts={split.hosts} onRemove={(h) => set({ hosts: split.hosts.filter((x) => x !== h) })} />
          )}
        </Section>

        <Section
          title="Countries"
          count={split.countries.length}
          hint="Every IP range registered to a country, updated weekly."
        >
          <ul className="flex flex-wrap gap-1.5">
            {split.countries.map((c) => (
              <Chip
                key={c}
                title={COUNTRIES[c] ?? c}
                label={
                  <>
                    <span className="text-muted-foreground">{c}</span>
                    {COUNTRIES[c] && <span className="ml-1.5 font-sans">{COUNTRIES[c]}</span>}
                  </>
                }
                onRemove={() => set({ countries: split.countries.filter((x) => x !== c) })}
              />
            ))}
            {!split.countries.includes("IR") && (
              <li className="contents">
                <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => addCountry("IR")}>
                  <Plus />
                  Iran
                </Button>
              </li>
            )}
            <li className="contents">
              <Input
                value={country}
                maxLength={2}
                onChange={(e) => setCountry(e.target.value.toUpperCase())}
                onKeyDown={(e) => e.key === "Enter" && addCountry(country)}
                placeholder="Code"
                aria-label="Country code"
                className="h-7 w-16 text-center font-mono text-xs"
              />
            </li>
          </ul>
        </Section>

        <p className="text-[12px] leading-4 text-dim">
          Switching between Exclude and Only listed reconnects the VPN. Local network traffic never uses the VPN in
          Only listed mode.
        </p>
      </div>

      <AppPicker
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        taken={new Set(split.apps.map((a) => a.path))}
        onPick={(a) => {
          set({ apps: [...split.apps, { name: a.name, path: a.path }] });
          setPickerOpen(false);
        }}
      />
    </div>
  );
}

