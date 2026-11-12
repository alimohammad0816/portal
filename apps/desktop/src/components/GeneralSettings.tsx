import { ChevronDown, Wifi, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { Network, Prefs, Profile } from "@/lib/api";

function Row({
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
  onChange: (v: boolean) => void;
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

export function GeneralSettings({
  prefs,
  onChange,
  profiles,
  network,
}: {
  prefs: Prefs;
  onChange: (p: Prefs) => void;
  profiles: Profile[];
  network: Network | null;
}) {
  const set = (patch: Partial<Prefs>) => onChange({ ...prefs, ...patch });
  const trusted = network && prefs.trusted_networks.includes(network.name);

  return (
    <div className="grid gap-4">
      <Row
        id="pref-login"
        title="Start at login"
        description="Portal waits in the tray, ready to connect."
        checked={prefs.launch_at_login}
        onChange={(v) => set({ launch_at_login: v })}
      />
      <Row
        id="pref-launch"
        title="Connect when Portal starts"
        description="Uses saved passwords; profiles with one-time codes still ask."
        checked={prefs.connect_on_launch}
        onChange={(v) => set({ connect_on_launch: v })}
      />
      <Row
        id="pref-untrusted"
        title="Connect on untrusted networks"
        description="Joining any network that isn't in your trusted list connects the VPN."
        checked={prefs.auto_connect_untrusted}
        onChange={(v) => set({ auto_connect_untrusted: v })}
      />

      <div className="grid gap-2">
        <Label htmlFor="pref-profile" className="text-[13.5px]">
          Location for automatic connections
        </Label>
        <div className="relative">
          <select
            id="pref-profile"
            value={prefs.auto_profile ?? ""}
            onChange={(e) => set({ auto_profile: e.target.value || null })}
            className="h-8 w-full cursor-pointer appearance-none rounded-md border bg-background pr-8 pl-2.5 text-[13.5px] text-foreground outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
          >
            <option value="" className="bg-popover text-popover-foreground">
              Last used
            </option>
            {profiles.map((p) => (
              <option key={p.id} value={p.id} className="bg-popover text-popover-foreground">
                {p.name}
              </option>
            ))}
          </select>
          <ChevronDown className="pointer-events-none absolute top-1/2 right-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        </div>
      </div>

      <div className="grid gap-2 rounded-xl border p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="grid gap-0.5">
            <span className="text-[13.5px] font-semibold">Trusted networks</span>
            <span className="text-xs text-muted-foreground">No automatic connection on these.</span>
          </div>
          {network && !trusted && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => set({ trusted_networks: [...prefs.trusted_networks, network.name] })}
            >
              Trust {network.name.length > 14 ? "this network" : network.name}
            </Button>
          )}
        </div>
        {prefs.trusted_networks.length === 0 ? (
          <p className="text-xs text-dim">None yet.</p>
        ) : (
          prefs.trusted_networks.map((n) => (
            <div key={n} className="flex items-center gap-2">
              <Wifi className="size-3.5 text-muted-foreground" />
              <span className="min-w-0 flex-1 truncate text-[13.5px]">
                {n}
                {network?.name === n && <span className="text-xs text-dim"> · current</span>}
              </span>
              <button
                type="button"
                aria-label={`Stop trusting ${n}`}
                onClick={() => set({ trusted_networks: prefs.trusted_networks.filter((x) => x !== n) })}
                className="flex size-7 cursor-pointer items-center justify-center rounded-md text-dim hover:bg-accent hover:text-foreground"
              >
                <X className="size-3.5" />
              </button>
            </div>
          ))
        )}
      </div>

      <Row
        id="pref-exit"
        title="Show where the VPN exits"
        description="Looks up the exit IP's location (ipwho.is) through the tunnel, for the map."
        checked={prefs.show_exit_location}
        onChange={(v) => set({ show_exit_location: v })}
      />
    </div>
  );
}
