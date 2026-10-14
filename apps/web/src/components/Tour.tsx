import { useCallback, useEffect, useLayoutEffect, useState, type CSSProperties } from "react";

// Lightweight guided tour: highlights elements marked with data-tour="<target>" and explains them one at a time.
// Shown once per browser (best effort); restart with startTour().

export interface TourStep { target: string; title: string; text: string }

const EVENT = "threatready:tour";

export function startTour() {
  window.dispatchEvent(new Event(EVENT));
}

function seen(id: string) {
  try {
    return localStorage.getItem(`threatready.tour.${id}`) === "done";
  } catch {
    return true;
  }
}

function markSeen(id: string) {
  try {
    localStorage.setItem(`threatready.tour.${id}`, "done");
  } catch {
    /* ignore */
  }
}

export function Tour({ id, steps }: { id: string; steps: TourStep[] }) {
  const [i, setI] = useState<number | null>(null);
  const [rect, setRect] = useState<DOMRect | null>(null);

  useEffect(() => {
    if (!seen(id)) setI(0);
    const restart = () => setI(0);
    window.addEventListener(EVENT, restart);
    return () => window.removeEventListener(EVENT, restart);
  }, [id]);

  const close = useCallback(() => {
    markSeen(id);
    setI(null);
  }, [id]);

  useLayoutEffect(() => {
    document.querySelectorAll(".tour-highlight").forEach((el) => el.classList.remove("tour-highlight"));
    if (i === null) return;
    const el = document.querySelector(`[data-tour="${steps[i].target}"]`);
    if (!el) {
      setRect(null);
      return;
    }
    el.classList.add("tour-highlight");
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    const update = () => setRect(el.getBoundingClientRect());
    update();
    const t = setTimeout(update, 350);
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      clearTimeout(t);
      el.classList.remove("tour-highlight");
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [i, steps]);

  useEffect(() => {
    if (i === null) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [i, close]);

  if (i === null) return null;
  const s = steps[i];
  const width = Math.min(340, window.innerWidth - 32);
  let style: CSSProperties = { right: 16, bottom: 16, width };
  if (rect) {
    const below = rect.bottom + 12 + 180 < window.innerHeight;
    const left = Math.max(16, Math.min(rect.left, window.innerWidth - width - 16));
    style = below ? { top: rect.bottom + 12, left, width } : { top: Math.max(16, rect.top - 192), left, width };
  }
  return (
    <div className="tour-pop" role="dialog" aria-modal="false" aria-labelledby="tour-title" style={style}>
      <p className="eyebrow">Guided tour · step {i + 1} of {steps.length}</p>
      <h3 id="tour-title">{s.title}</h3>
      <p className="small">{s.text}</p>
      <div className="row between">
        <button className="small ghost" onClick={close}>Skip tour</button>
        <span className="row">
          {i > 0 && <button className="small" onClick={() => setI(i - 1)}>Back</button>}
          {i < steps.length - 1 ? <button className="small primary" onClick={() => setI(i + 1)}>Next</button>
            : <button className="small primary" onClick={close}>Got it</button>}
        </span>
      </div>
    </div>
  );
}
