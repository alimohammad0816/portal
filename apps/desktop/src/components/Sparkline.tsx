export function Sparkline({ values, stroke }: { values: number[]; stroke: string }) {
  if (values.length < 2) return <div className="h-3.5" aria-hidden="true" />;
  const max = Math.max(1, ...values);
  const n = values.length - 1;
  const d = values
    .map((v, i) => `${i === 0 ? "M" : "L"}${((i / n) * 100).toFixed(1)} ${(14 - (v / max) * 12).toFixed(1)}`)
    .join(" ");
  return (
    <svg width="100%" height="14" viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true">
      <path d={d} fill="none" stroke={stroke} strokeWidth={1.25} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
