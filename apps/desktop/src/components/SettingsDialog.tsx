import { ChevronRight, Copy, Download, FileUp, FolderOpen, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { ScrollFade } from "@/components/ui/scroll-fade";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ConnectionProxySettings, DnsSettings, FirewallSettings, GatewaySettings } from "@/components/SecuritySettings";
import { GeneralSettings } from "@/components/GeneralSettings";
import { SplitSettings } from "@/components/SplitSettings";
import {
  api,
  errorText,
  type Network,
  type Prefs,
  type Profile,
  type ProfileEdit,
  type SavedCredentials,
  type Settings,
  type Status,
  type UpdateInfo,
} from "@/lib/api";
import { formatAgo } from "@/lib/format";
import { cn } from "@/lib/utils";

function ProfileRow({ profile, onChanged }: { profile: Profile; onChanged: () => void }) {
  const [name, setName] = useState(profile.name);
  const [group, setGroup] = useState(profile.group);
  const [country, setCountry] = useState(profile.country ?? "");
  const [dco, setDco] = useState(!profile.disable_dco);
  const [extra, setExtra] = useState(profile.extra_directives);
  const [advanced, setAdvanced] = useState(profile.disable_dco || profile.extra_directives !== "");
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedCredentials>({ login: false, key: false, proxy: false });

  useEffect(() => {
    if (profile.auth !== "certificate" || profile.key_encrypted) api.savedCredentials(profile.id).then(setSaved).catch(() => {});
  }, [profile.id, profile.auth, profile.key_encrypted]);
  const dirty =
    name !== profile.name ||
    group !== profile.group ||
    country !== (profile.country ?? "") ||
    dco === profile.disable_dco ||
    extra.trim() !== profile.extra_directives.trim();

  async function save() {
    if (country && !/^[a-zA-Z]{2}$/.test(country)) {
      setError("Country must be a two-letter code, like DE.");
      return;
    }
    const edit: ProfileEdit = { name, group, country: country || "-", disable_dco: !dco, extra_directives: extra };
    try {
      const p = await api.updateProfile(profile.id, edit);
      setExtra(p.extra_directives);
      setError(null);
      onChanged();
    } catch (e) {
      setError(errorText(e));
    }
  }

  function forget(kind: "login" | "key") {
    api
      .forgetCredentials(profile.id, kind)
      .then(() => setSaved((s) => ({ ...s, [kind]: false })))
      .catch((e) => setError(errorText(e)));
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
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2 border-b py-3 last:border-0">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[12px] text-dim">
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
        <Input aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} className="h-8 text-[13.5px]" />
        <Input aria-label="Group" value={group} onChange={(e) => setGroup(e.target.value)} className="h-8 text-[13.5px]" />
        <Input
          aria-label="Country code"
          value={country}
          maxLength={2}
          placeholder="--"
          onChange={(e) => {
            setCountry(e.target.value.toUpperCase());
            setError(null);
          }}
          className="h-8 text-center font-mono text-[13.5px]"
        />
      </div>
      {saved.login && (
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>Password saved in your keyring</span>
          <Button variant="ghost" size="sm" className="h-7 text-muted-foreground" onClick={() => forget("login")}>
            Forget
          </Button>
        </div>
      )}
      {saved.key && (
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>Key passphrase saved in your keyring</span>
          <Button variant="ghost" size="sm" className="h-7 text-muted-foreground" onClick={() => forget("key")}>
            Forget
          </Button>
        </div>
      )}
      <button
        type="button"
        onClick={() => setAdvanced((a) => !a)}
        aria-expanded={advanced}
        className="flex cursor-pointer items-center gap-1 justify-self-start text-xs text-muted-foreground hover:text-foreground"
      >
        <ChevronRight className={cn("size-3.5 transition-transform", advanced && "rotate-90")} />
        Advanced
      </button>
      {advanced && (
        <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3 rounded-lg border p-3">
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor={`dco-${profile.id}`} className="grid gap-1 font-normal">
              <span className="text-[13.5px] font-medium">Data channel offload (DCO)</span>
              <span className="text-xs leading-5 text-muted-foreground">Faster encryption in the kernel. Turn off if the connection misbehaves.</span>
            </Label>
            <Switch id={`dco-${profile.id}`} checked={dco} onCheckedChange={setDco} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor={`extra-${profile.id}`} className="text-[13.5px] font-medium">
              Extra options
            </Label>
            <textarea
              id={`extra-${profile.id}`}
              value={extra}
              onChange={(e) => {
                setExtra(e.target.value);
                setError(null);
              }}
              rows={3}
              spellCheck={false}
              placeholder={"mssfix 1400\ntun-mtu 1500"}
              className="selectable scroll-subtle min-h-16 w-full min-w-0 resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-[12.5px] leading-5 outline-none placeholder:text-dim focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
            />
            <span className="text-xs leading-5 text-muted-foreground">OpenVPN directives, one per line, added after the profile's own.</span>
          </div>
        </div>
      )}
      {(dirty || error) && (
        <div className="flex items-center justify-between gap-2">
          <span className="min-w-0 text-[12.5px] break-words text-destructive">{error}</span>
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
      <div className="overflow-hidden rounded-lg border bg-subtle/50">
        <ScrollFade ref={ref} className="selectable h-80 overflow-auto p-3 font-mono text-[12px] leading-5 text-zinc-300">
          {lines.length === 0 ? <span className="text-dim">No log lines yet.</span> : lines.map((l, i) => <div key={i}>{l}</div>)}
        </ScrollFade>
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
      <div className="grid grid-cols-2 gap-3 rounded-lg border p-3 text-[13.5px]">
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
          <span className="text-[13.5px] font-medium">Check for updates automatically</span>
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
  onImportFiles,
  onImportFolder,
  updates,
  settings,
  status,
  onSettingsChange,
  tab,
  onTabChange,
  prefs,
  onPrefsChange,
  network,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  profiles: Profile[];
  log: string[];
  onProfilesChanged: () => void;
  onImportFiles: () => void;
  onImportFolder: () => void;
  updates: UpdateSettings;
  settings: Settings;
  status: Status;
  onSettingsChange: (s: Settings) => void;
  tab: string;
  onTabChange: (tab: string) => void;
  prefs: Prefs;
  onPrefsChange: (p: Prefs) => void;
  network: Network | null;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-none content-start gap-3">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>Changes apply right away, without reconnecting.</DialogDescription>
        </DialogHeader>
        <Tabs value={tab} onValueChange={onTabChange}>
          <TabsList className="w-full">
            <TabsTrigger value="split">Split</TabsTrigger>
            <TabsTrigger value="firewall">Network</TabsTrigger>
            <TabsTrigger value="dns">DNS</TabsTrigger>
            <TabsTrigger value="profiles">Profiles</TabsTrigger>
            <TabsTrigger value="log">Log</TabsTrigger>
            <TabsTrigger value="about">General</TabsTrigger>
          </TabsList>
          <TabsContent value="split">
            <ScrollFade className="scroll-gutter max-h-[calc(100vh-15rem)] overflow-y-auto">
              <SplitSettings settings={settings} status={status} onChange={onSettingsChange} />
            </ScrollFade>
          </TabsContent>
          <TabsContent value="firewall">
            <ScrollFade className="scroll-gutter grid max-h-[calc(100vh-15rem)] gap-4 overflow-y-auto">
              <FirewallSettings settings={settings} onChange={onSettingsChange} />
              <ConnectionProxySettings settings={settings} onChange={onSettingsChange} />
              <GatewaySettings settings={settings} status={status} onChange={onSettingsChange} />
            </ScrollFade>
          </TabsContent>
          <TabsContent value="dns">
            <DnsSettings settings={settings} status={status} onChange={onSettingsChange} />
          </TabsContent>
          <TabsContent value="profiles">
            <div className="flex gap-2 pb-1">
              <Button size="sm" variant="outline" onClick={onImportFiles}>
                <FileUp />
                Import files
              </Button>
              <Button size="sm" variant="outline" onClick={onImportFolder}>
                <FolderOpen />
                Import folder
              </Button>
            </div>
            <ScrollFade className="scroll-gutter max-h-[calc(100vh-18rem)] overflow-y-auto">
              {profiles.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">No profiles yet.</p>
              ) : (
                profiles.map((p) => (
                  <ProfileRow
                    key={`${p.id}:${p.name}:${p.group}:${p.country}:${p.disable_dco}:${p.extra_directives}:${p.key_encrypted}`}
                    profile={p}
                    onChanged={onProfilesChanged}
                  />
                ))
              )}
            </ScrollFade>
          </TabsContent>
          <TabsContent value="log">
            <LogView lines={log} />
          </TabsContent>
          <TabsContent value="about">
            <ScrollFade className="scroll-gutter grid max-h-[calc(100vh-15rem)] gap-5 overflow-y-auto">
              <GeneralSettings prefs={prefs} onChange={onPrefsChange} profiles={profiles} network={network} />
              <div className="border-t pt-1">
                <AboutView u={updates} />
              </div>
            </ScrollFade>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
