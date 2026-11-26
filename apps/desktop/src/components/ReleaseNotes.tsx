import { openUrl } from "@tauri-apps/plugin-opener";
import type * as React from "react";

import { inTauri } from "@/lib/api";

/** Release notes are Markdown from GitHub. This covers what they use —
 * headings, bullets, **bold**, `code`, [links](url) and bare URLs — and
 * builds elements, never HTML, so a release body can't inject markup. */

function openLink(url: string) {
  if (!/^https?:\/\//.test(url)) return;
  if (inTauri) openUrl(url).catch(() => {});
  else window.open(url, "_blank", "noopener");
}

function Link({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      onClick={(e) => {
        e.preventDefault();
        openLink(href);
      }}
      className="break-all text-foreground underline decoration-zinc-600 underline-offset-2 hover:decoration-foreground"
    >
      {children}
    </a>
  );
}

const INLINE = /\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)|(https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g;

function inline(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(INLINE)) {
    const i = m.index ?? 0;
    if (i > last) out.push(text.slice(last, i));
    const key = `${i}`;
    if (m[1] !== undefined) out.push(<strong key={key} className="font-semibold text-foreground">{inline(m[1])}</strong>);
    else if (m[2] !== undefined)
      out.push(
        <code key={key} className="rounded bg-accent px-1 font-mono text-[12.5px]">
          {m[2]}
        </code>,
      );
    else if (m[3] !== undefined) out.push(<Link key={key} href={m[4]}>{m[3]}</Link>);
    else if (m[5] !== undefined) out.push(<Link key={key} href={m[5]}>{m[5]}</Link>);
    last = i + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

type Block = { kind: "heading" | "para"; text: string } | { kind: "list"; items: string[] };

function blocks(md: string): Block[] {
  const out: Block[] = [];
  for (const raw of md.replace(/\r/g, "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const item = /^[-*+]\s+(.*)$/.exec(line);
    const heading = /^#{1,6}\s+(.*)$/.exec(line);
    const prev = out[out.length - 1];
    if (item) {
      if (prev?.kind === "list") prev.items.push(item[1]);
      else out.push({ kind: "list", items: [item[1]] });
    } else if (heading) {
      out.push({ kind: "heading", text: heading[1] });
    } else {
      out.push({ kind: "para", text: line });
    }
  }
  return out;
}

export function ReleaseNotes({ markdown }: { markdown: string }) {
  return (
    <div className="grid gap-2">
      {blocks(markdown).map((b, i) => {
        if (b.kind === "heading")
          return (
            <p key={i} className="text-[13.5px] font-semibold text-foreground">
              {inline(b.text)}
            </p>
          );
        if (b.kind === "list")
          return (
            <ul key={i} className="grid list-disc gap-1 pl-4 marker:text-dim">
              {b.items.map((it, j) => (
                <li key={j}>{inline(it)}</li>
              ))}
            </ul>
          );
        return <p key={i}>{inline(b.text)}</p>;
      })}
    </div>
  );
}
