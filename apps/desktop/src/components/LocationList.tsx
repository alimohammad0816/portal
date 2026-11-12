import { Check, Star } from "lucide-react";

import type { Profile } from "@/lib/api";
import { cn } from "@/lib/utils";

export type Latency = number | null | undefined; // undefined: not measured yet, null: timeout

function bars(ms: Latency): number {
  if (ms === null) return 0;
  if (ms === undefined) return -1;
  if (ms < 90) return 3;
  if (ms < 150) return 2;
  return 1;
}

function LatencyBars({ ms }: { ms: Latency }) {
  const n = bars(ms);
  return (
    <span className="flex h-[11px] items-end gap-0.5" aria-hidden="true">
      {[4, 7, 11].map((h, i) => (
        <span
          key={h}
          className={cn("w-[3px] rounded-[1px]", i < n ? "bg-zinc-300" : "bg-zinc-700")}
          style={{ height: h }}
        />
      ))}
    </span>
  );
}

export function LocationList({
  profiles,
  selectedId,
  latency,
  favorites,
  onPick,
  onToggleFavorite,
}: {
  profiles: Profile[];
  selectedId: string | null;
  latency: Record<string, Latency>;
  favorites: Set<string>;
  onPick: (p: Profile) => void;
  onToggleFavorite: (p: Profile) => void;
}) {
  const groups = new Map<string, Profile[]>();
  for (const p of profiles) {
    const list = groups.get(p.group) ?? [];
    list.push(p);
    groups.set(p.group, list);
  }

  return (
    <div className="flex flex-col">
      {[...groups.entries()].map(([group, items]) => (
        <section key={group} aria-label={group}>
          <div className="flex justify-between px-2.5 pt-2.5 pb-1 text-xs font-medium text-dim">
            <span>{group}</span>
            <span>{items.length}</span>
          </div>
          {items.map((p) => {
            const ms = latency[p.id];
            const on = p.id === selectedId;
            const fav = favorites.has(p.id);
            return (
              <div
                key={p.id}
                className={cn(
                  "group flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left transition-colors",
                  on ? "bg-accent" : "hover:bg-subtle",
                )}
              >
                <button
                  type="button"
                  onClick={() => onPick(p)}
                  className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 text-left outline-none"
                >
                  <span className="flex h-5 w-[30px] shrink-0 items-center justify-center rounded-[5px] border font-mono text-[10px] font-medium text-zinc-300">
                    {p.country ?? "--"}
                  </span>
                  <span className="flex min-w-0 flex-1 flex-col gap-px">
                    <span className="truncate text-[13px] font-medium">{p.name}</span>
                    <span className="truncate font-mono text-[11px] text-dim">
                      {p.proto.toUpperCase()} {p.remote_port} · {p.remote_host}
                    </span>
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => onToggleFavorite(p)}
                  aria-label={fav ? `Remove ${p.name} from favorites` : `Add ${p.name} to favorites`}
                  aria-pressed={fav}
                  className={cn(
                    "cursor-pointer rounded p-0.5 text-muted-foreground transition-opacity hover:text-foreground",
                    fav ? "opacity-100" : "opacity-0 group-hover:opacity-100 focus-visible:opacity-100",
                  )}
                >
                  <Star className="size-3" fill={fav ? "currentColor" : "none"} />
                </button>
                <LatencyBars ms={ms} />
                <span
                  className={cn(
                    "w-[52px] text-right text-xs tabular-nums",
                    ms === null ? "text-destructive" : "text-muted-foreground",
                  )}
                >
                  {ms === undefined ? "…" : ms === null ? "Timeout" : `${ms} ms`}
                </span>
                <span className="flex w-3.5 justify-end">{on && <Check className="size-3.5" />}</span>
              </div>
            );
          })}
        </section>
      ))}
    </div>
  );
}
