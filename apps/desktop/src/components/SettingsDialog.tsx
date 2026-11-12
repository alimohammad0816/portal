import { Copy, Download, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DnsSettings, FirewallSettings } from "@/components/SecuritySettings";
import { SplitSettings } from "@/components/SplitSettings";
import { api, errorText, type Profile, type Settings, type Status, type UpdateInfo } from "@/lib/api";
import { formatAgo } from "@/lib/format";

function ProfileRow({ profile, onChanged }: { profile: Profile; onChanged: () => void }) {
  const [name, setName] = useState(profile.name);
  const [group, setGroup] = useState(profile.group);
  const [country, setCountry] = useState(profile.country ?? "");
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = name !== profile.name || group !== profile.group || country !== (profile.country ?? "");

  async function save() {
    if (country && !/^[a-zA-Z]{2}$/.test(country)) {
      setError("Country must be a two-letter code, like DE.");
      return;
    }
    try {
      await api.updateProfile(profile.id, name, group, country || "-");
      setError(null);
      onChanged();
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function remove() {
    if (!confirming) {
      setConfirming(true);
      return;
    }
    try {
      await api.removeProfile(profile.id);
      onChanged();
    } catch (e) {
      setError(errorText(e));
      setConfirming(false);
    }
  }

  return (
    <div className="grid gap-2 border-b py-3 last:border-0">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[11px] text-dim">
          {profile.source_file} · {profile.remote_host} · last used {formatAgo(profile.last_connected_at).toLowerCase()}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className={confirming ? "text-destructive" : "text-muted-foreground"}
          onClick={remove}
          onBlur={() => setConfirming(false)}
        >
          <Trash2 />
          {confirming ? "Confirm" : "Remove"}
        </Button>
      </div>
      <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_56px] gap-2">
        <Input aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} className="h-8 text-[13px]" />
        <Input aria-label="Group" value={group} onChange={(e) => setGroup(e.target.value)} className="h-8 text-[13px]" />
        <Input
          aria-label="Country code"
          value={country}
          maxLength={2}
          placeholder="--"
          onChange={(e) => {
            setCountry(e.target.value.toUpperCase());
            setError(null);
          }}
          className="h-8 text-center font-mono text-[13px]"
        />
      </div>
      {(dirty || error) && (
        <div className="flex items-center justify-between gap-2">
          <span className="text-[12px] text-destructive">{error}</span>
          {dirty && (
            <Button size="sm" onClick={save}>
              Save
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function LogView({ lines }: { lines: string[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);
  return (
    <div className="grid gap-2">
      <div
        ref={ref}
        className="selectable scroll-subtle h-80 overflow-auto rounded-lg border bg-subtle/50 p-3 font-mono text-[11px] leading-5 text-zinc-300"
      >
        {lines.length === 0 ? <span className="text-dim">No log lines yet.</span> : lines.map((l, i) => <div key={i}>{l}</div>)}
      </div>
      <div className="flex justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={async () => {
            await navigator.clipboard.writeText(lines.join("\n"));
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          <Copy />
          {copied ? "Copied" : "Copy log"}
        </Button>
      </div>
    </div>
  );
}

export interface UpdateSettings {
  autoCheck: boolean;
  onAutoCheckChange: (on: boolean) => void;
  info: UpdateInfo | null;
  daemonVersion: string | null;
  checking: boolean;
  error: string | null;
  onCheckNow: () => void;
  onShowUpdate: () => void;
}

function AboutView({ u }: { u: UpdateSettings }) {
  const enabled = u.info?.enabled !== false;
  return (
    <div className="grid gap-4 pt-1">
      <div className="grid grid-cols-2 gap-3 rounded-lg border p-3 text-[13px]">
        <div className="grid gap-0.5">
          <span className="text-xs text-muted-foreground">App</span>
          <span className="font-mono">{u.info?.current ?? "—"}</span>
        </div>
        <div className="grid gap-0.5">
          <span className="text-xs text-muted-foreground">Service</span>
          <span className="font-mono">{u.daemonVersion ?? "not running"}</span>
        </div>
      </div>
      <div className="flex items-center justify-between gap-4">
        <Label htmlFor="auto-update" className="grid gap-1 font-normal">
          <span className="text-[13px] font-medium">Check for updates automatically</span>
          <span className="text-xs text-muted-foreground">Asks GitHub for new releases at start and every few hours.</span>
        </Label>
        <Switch id="auto-update" checked={u.autoCheck} onCheckedChange={u.onAutoCheckChange} disabled={!enabled} />
      </div>
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-muted-foreground">
          {!enabled
            ? "This is a local build, so it doesn't check for updates."
            : u.error
              ? <span className="text-destructive">{u.error}</span>
              : u.info?.available
                ? `Version ${u.info.available.version} is available.`
                : u.info
                  ? "You're up to date."
                  : ""}
        </span>
        {u.info?.available ? (
          <Button size="sm" onClick={u.onShowUpdate}>
            <Download />
            Update
          </Button>
        ) : (
          <Button size="sm" variant="outline" onClick={u.onCheckNow} disabled={u.checking || !enabled}>
            {u.checking ? <Loader2 className="animate-spin" /> : <RefreshCw />}
            Check now
          </Button>
        )}
      </div>
    </div>
  );
}

export function SettingsDialog({
  open,
  onOpenChange,
  profiles,
  log,
  onProfilesChanged,
  updates,
  settings,
  status,
  onSettingsChange,
  tab,
  onTabChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  profiles: Profile[];
  log: string[];
  onProfilesChanged: () => void;
  updates: UpdateSettings;
  settings: Settings;
  status: Status;
  onSettingsChange: (s: Settings) => void;
  tab: string;
  onTabChange: (tab: string) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[calc(100%-2rem)] gap-3">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>Changes apply right away, without reconnecting.</DialogDescription>
        </DialogHeader>
        <Tabs value={tab} onValueChange={onTabChange}>
          <TabsList className="w-full">
            <TabsTrigger value="split">Split</TabsTrigger>
            <TabsTrigger value="firewall">Firewall</TabsTrigger>
            <TabsTrigger value="dns">DNS</TabsTrigger>
            <TabsTrigger value="profiles">Profiles</TabsTrigger>
            <TabsTrigger value="log">Log</TabsTrigger>
            <TabsTrigger value="about">About</TabsTrigger>
          </TabsList>
          <TabsContent value="split">
            <div className="scroll-subtle max-h-[28rem] overflow-y-auto pr-1">
              <SplitSettings settings={settings} status={status} onChange={onSettingsChange} />
            </div>
          </TabsContent>
          <TabsContent value="firewall">
            <FirewallSettings settings={settings} onChange={onSettingsChange} />
          </TabsContent>
          <TabsContent value="dns">
            <DnsSettings settings={settings} status={status} onChange={onSettingsChange} />
          </TabsContent>
          <TabsContent value="profiles">
            <div className="scroll-subtle max-h-[26rem] overflow-y-auto pr-1">
              {profiles.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">No profiles yet.</p>
              ) : (
                profiles.map((p) => <ProfileRow key={`${p.id}:${p.name}:${p.group}:${p.country}`} profile={p} onChanged={onProfilesChanged} />)
              )}
            </div>
          </TabsContent>
          <TabsContent value="log">
            <LogView lines={log} />
          </TabsContent>
          <TabsContent value="about">
            <AboutView u={updates} />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
