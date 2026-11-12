import { Download, ExternalLink, Loader2 } from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api, errorText, inTauri, type Release } from "@/lib/api";

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

  async function install() {
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
          <DialogTitle>Tunnel {release?.version} is available</DialogTitle>
          <DialogDescription>
            You have {current}. The update is checked against the release signature before it's installed. An active VPN
            connection drops briefly while the service restarts.
          </DialogDescription>
        </DialogHeader>
        {release?.notes && (
          <div className="selectable scroll-subtle max-h-56 overflow-y-auto rounded-lg border bg-subtle/50 px-3 py-2.5 text-[13px] leading-6 whitespace-pre-line text-zinc-300">
            {release.notes}
          </div>
        )}
        {error && <p className="text-[13px] text-destructive">{error}</p>}
        <DialogFooter className="justify-between">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => release && (inTauri ? openUrl(release.url) : window.open(release.url, "_blank"))}
          >
            <ExternalLink />
            Release page
          </Button>
          <Button onClick={install} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : <Download />}
            {busy ? "Downloading…" : "Install update"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
