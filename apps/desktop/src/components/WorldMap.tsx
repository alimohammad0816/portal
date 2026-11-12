import type { ConnState } from "@/lib/api";
import { type LonLat, project, WORLD_DOTS } from "@/lib/geo";

const round = (n: number) => Math.round(n * 10) / 10;

function arcPath(from: [number, number], to: [number, number]): string {
  const [x1, y1] = from;
  const [x2, y2] = to;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const dist = Math.hypot(dx, dy) || 1;
  let nx = -dy / dist;
  let ny = dx / dist;
  if (ny > 0) {
    nx = -nx;
    ny = -ny;
  }
  const k = Math.min(dist * 0.32, 40);
  const cx = (x1 + x2) / 2 + nx * k;
  const cy = (y1 + y2) / 2 + ny * k;
  return `M${round(x1)} ${round(y1)} Q${round(cx)} ${round(cy)} ${round(x2)} ${round(y2)}`;
}

const STATE_COLOR: Record<ConnState, string> = {
  connected: "var(--success)",
  connecting: "var(--warning)",
  needs_credentials: "var(--warning)",
  disconnecting: "var(--warning)",
  disconnected: "var(--muted-foreground)",
};

export function WorldMap({
  home,
  server,
  state,
  label,
  exitIp,
}: {
  home: LonLat | null;
  server: LonLat | null;
  state: ConnState;
  label: string;
  exitIp: string | null;
}) {
  const color = STATE_COLOR[state];
  const h = home ? project(home) : null;
  const s = server ? project(server) : null;
  const showArc = h && s && state !== "disconnected";

  return (
    <div className="relative h-44 overflow-hidden rounded-xl border bg-background">
      <svg
        className="block size-full"
        viewBox="0 -8 360 156"
        preserveAspectRatio="xMidYMid slice"
        role="img"
        aria-label={label}
      >
        <path
          d={WORLD_DOTS}
          fill="none"
          stroke="oklch(0.37 0.013 285.805)"
          strokeWidth={1.15}
          strokeLinecap="round"
          strokeDasharray="0 2.5"
        />
        {showArc && (
          <path
            className="map-flow transition-all duration-500"
            d={arcPath(h, s)}
            fill="none"
            stroke={color}
            strokeWidth={0.9}
            strokeLinecap="round"
          />
        )}
        {h && (
          <>
            <circle cx={h[0]} cy={h[1]} r={1.9} fill="var(--background)" stroke="var(--muted-foreground)" strokeWidth={0.9} />
            <text x={h[0] + 4} y={h[1] + 8} fill="var(--muted-foreground)" fontSize={6.5} fontFamily="var(--font-sans)">
              You
            </text>
          </>
        )}
        {s && (
          <>
            {state === "connected" && <circle className="map-pulse" cx={s[0]} cy={s[1]} r={2.4} fill={color} />}
            <circle cx={s[0]} cy={s[1]} r={2.4} fill={color} stroke="var(--background)" strokeWidth={0.8} />
          </>
        )}
      </svg>
      <div className="absolute top-2.5 left-2.5 flex h-6 items-center gap-1.5 rounded-full border bg-background px-2.5 text-xs font-medium">
        <span className="size-1.5 rounded-full" style={{ background: color }} />
        {label}
      </div>
      {exitIp && (
        <div className="absolute top-2.5 right-2.5 flex h-6 items-center rounded-full border bg-background px-2.5 font-mono text-xs text-muted-foreground">
          {exitIp}
        </div>
      )}
    </div>
  );
}
