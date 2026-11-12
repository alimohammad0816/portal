/** The Portal mark (the small-size drawing: two arches and the light). */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 1024 1024" className={className} aria-hidden="true">
      <rect x="32" y="32" width="960" height="960" rx="216" fill="#09090b" />
      <rect x="38" y="38" width="948" height="948" rx="210" fill="none" stroke="#3f3f46" strokeWidth="14" />
      <g fill="none" strokeLinecap="round" transform="translate(0 30)">
        <path d="M240 770V480a272 272 0 0 1 544 0v290" stroke="#fafafa" strokeWidth="88" />
        <path d="M392 770V560a120 120 0 0 1 240 0v210" stroke="#a1a1aa" strokeWidth="76" />
      </g>
      <circle cx="512" cy="720" r="46" fill="#fafafa" />
    </svg>
  );
}
