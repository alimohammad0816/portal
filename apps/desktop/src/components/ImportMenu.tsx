import { Download, FileUp, FolderOpen } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";

/** The title bar's import button: files or a whole folder. */
export function ImportMenu({ onFiles, onFolder }: { onFiles: () => void; onFolder: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  const item = (label: string, Icon: typeof FileUp, run: () => void) => (
    <button
      type="button"
      role="menuitem"
      onClick={() => {
        setOpen(false);
        run();
      }}
      className="flex w-full cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[13.5px] hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
    >
      <Icon className="size-4 text-muted-foreground" />
      {label}
    </button>
  );

  return (
    <div ref={ref} className="relative">
      <Button
        variant="ghost"
        size="icon"
        aria-label="Import profiles"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="text-muted-foreground"
      >
        <Download />
      </Button>
      {open && (
        <div role="menu" className="absolute top-full right-0 z-40 mt-1 grid w-44 gap-0.5 rounded-lg border bg-popover p-1 shadow-lg">
          {item("Import files…", FileUp, onFiles)}
          {item("Import folder…", FolderOpen, onFolder)}
        </div>
      )}
    </div>
  );
}
