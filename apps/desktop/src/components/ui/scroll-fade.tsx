import { type Ref, useCallback, useEffect, useRef } from "react";
import type * as React from "react";

import { cn } from "@/lib/utils";

/**
 * A scrolling box whose edges fade out where more content is hidden, so
 * rows don't end in a hard cut. The fade follows the scroll position:
 * none at the very top or bottom.
 */
export function ScrollFade({ className, ref, onScroll, children, ...props }: React.ComponentProps<"div">) {
  const own = useRef<HTMLDivElement | null>(null);

  const update = useCallback(() => {
    const el = own.current;
    if (!el) return;
    const top = el.scrollTop > 1;
    const bottom = el.scrollTop + el.clientHeight < el.scrollHeight - 1;
    el.toggleAttribute("data-fade-top", top);
    el.toggleAttribute("data-fade-bottom", bottom);
  }, []);

  const setRef = useCallback(
    (el: HTMLDivElement | null) => {
      own.current = el;
      assign(ref, el);
    },
    [ref],
  );

  useEffect(() => {
    const el = own.current;
    if (!el) return;
    update();
    // Content and size change without a scroll event (tabs, filters, new log lines).
    const resize = new ResizeObserver(update);
    resize.observe(el);
    const mutate = new MutationObserver(update);
    mutate.observe(el, { childList: true, subtree: true, characterData: true });
    return () => {
      resize.disconnect();
      mutate.disconnect();
    };
  }, [update]);

  return (
    <div
      ref={setRef}
      className={cn("scroll-subtle scroll-fade", className)}
      onScroll={(e) => {
        update();
        onScroll?.(e);
      }}
      {...props}
    >
      {children}
    </div>
  );
}

function assign<T>(ref: Ref<T> | undefined, value: T | null) {
  if (typeof ref === "function") ref(value);
  else if (ref) (ref as React.RefObject<T | null>).current = value;
}
