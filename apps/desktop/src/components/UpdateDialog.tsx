import { Download, ExternalLink, Loader2 } from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollFade } from "@/components/ui/scroll-fade";
import { api, errorText, inTauri, onUpdateProgress, type Release, type UpdateProgress } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";

function progressLabel(p: UpdateProgress | null): string {
  if (!p) return "Downloading…";
  if (p.phase === "install") return "Installing…";
  if (p.total) return `Downloading ${Math.floor((p.downloaded / p.total) * 100)}%`;
  return `Downloading ${formatBytes(p.downloaded)}`;
}

export function UpdateDialog({
  release,
  current,
  open,
  onOpenChange,
  onInstalling,
}: {
  release: Release | null;
  current: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onInstalling: (version: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);

  useEffect(() => {
    if (!busy) return;
    const sub = onUpdateProgress(setProgress);
    return () => {
      sub.then((off) => off());
    };
  }, [busy]);

  const percent =
    progress?.phase === "install" ? 100 : progress?.total ? (progress.downloaded / progress.total) * 100 : null;

  async function install() {
    setProgress(null);
    setBusy(true);
    setError(null);
    try {
      const v = await api.installUpdate();
      onInstalling(v);
      onOpenChange(false);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open && release !== null} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Portal {release?.version} is available</DialogTitle>
          <DialogDescription>
            You have {current}. The update is checked against the release signature before it's installed. An active VPN
            connection drops briefly while the service restarts.
          </DialogDescription>
        </DialogHeader>
        {release?.notes && (
          <div className="overflow-hidden rounded-lg border bg-subtle/50">
            <ScrollFade className="selectable max-h-56 overflow-y-auto px-3 py-2.5 text-[13.5px] leading-6 whitespace-pre-line text-zinc-300">
              {release.notes}
            </ScrollFade>
          </div>
        )}
        {busy && (
          <div className="grid gap-1.5" aria-live="polite">
            <div
              role="progressbar"
              aria-label="Update progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={percent === null ? undefined : Math.floor(percent)}
              className="h-1.5 overflow-hidden rounded-full bg-accent"
            >
              <div
                className={cn(
                  "h-full rounded-full bg-foreground transition-[width] duration-200",
                  percent === null && "w-1/3 animate-pulse",
                )}
                style={percent === null ? undefined : { width: `${percent}%` }}
              />
            </div>
            <span className="text-xs text-muted-foreground tabular-nums">
              {progress?.phase === "install"
                ? "Checking the signature and installing. This takes a few seconds."
                : progress?.total
                  ? `${formatBytes(progress.downloaded)} of ${formatBytes(progress.total)}`
                  : progress
                    ? formatBytes(progress.downloaded)
                    : "Starting the download…"}
            </span>
          </div>
        )}
        {error && <p className="text-[13.5px] text-destructive">{error}</p>}
        <DialogFooter className="justify-between">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => release && (inTauri ? openUrl(release.url) : window.open(release.url, "_blank"))}
          >
            <ExternalLink />
            Release page
          </Button>
          <Button onClick={install} disabled={busy} className="tabular-nums">
            {busy ? <Loader2 className="animate-spin" /> : <Download />}
            {busy ? progressLabel(progress) : "Install update"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
