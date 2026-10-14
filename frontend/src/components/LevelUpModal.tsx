import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useCareer } from "../state";
import type { CareerProfile, Promotion } from "../types";
import { ActionButton } from "./ui";

const CONFETTI = Array.from({ length: 28 }, (_, i) => i);

// Congratulations popup shown whenever a level has just been completed and the next one unlocked.
export function LevelUpModal() {
  const { profile, setProfile } = useCareer();
  const navigate = useNavigate();
  const [promo, setPromo] = useState<Promotion | null>(null);
  const primary = useRef<HTMLButtonElement | null>(null);
  const pending = profile?.pending_promotion ?? null;

  useEffect(() => {
    if (pending === null) {
      setPromo(null);
      return;
    }
    api.get<{ pending: Promotion | null }>("/api/career/promotion").then((r) => setPromo(r.pending)).catch(() => setPromo(null));
  }, [pending]);

  useEffect(() => {
    if (promo) primary.current?.focus();
  }, [promo]);

  if (!promo) return null;
  const acknowledge = async (to: string) => {
    setProfile(await api.post<CareerProfile>("/api/career/promotion/acknowledge"));
    navigate(to);
  };
  return (
    <div className="modal-backdrop" role="presentation">
      <div className="modal levelup" role="dialog" aria-modal="true" aria-labelledby="levelup-title">
        <div className="confetti" aria-hidden>{CONFETTI.map((i) => <span key={i} style={{ left: `${(i * 37) % 100}%`, animationDelay: `${(i % 7) * 0.15}s` }} />)}</div>
        <div className="levelup-badge" aria-hidden>{promo.journey_complete ? "🏆" : "🎉"}</div>
        <p className="eyebrow">{promo.journey_complete ? "All six levels complete" : `Level ${promo.completed_level} complete`}</p>
        <h2 id="levelup-title">{promo.journey_complete ? "Congratulations — you reached Mastery!" : `Congratulations! Level ${promo.level} — ${promo.title} is unlocked`}</h2>
        {promo.new_title && <p>Your new title: <strong>{promo.new_title}</strong></p>}
        <p className="small muted">{promo.summary}</p>
        {!promo.journey_complete && (
          <div className="levelup-grid">
            <div><h3>New responsibilities</h3><ul className="small">{promo.responsibilities.map((r) => <li key={r}>{r}</li>)}</ul></div>
            <div><h3>Harder challenges</h3><p className="small">{promo.challenge}</p>
              <ul className="small">{promo.missions.map((m) => <li key={m.id}>{m.title}</li>)}</ul></div>
          </div>
        )}
        <div className="row end" style={{ marginTop: 12 }}>
          <ActionButton onClick={() => acknowledge("/")}>Back to My Journey</ActionButton>
          {!promo.journey_complete && (
            <button ref={primary} className="primary cta" onClick={() => void acknowledge(`/levels/${promo.level}`)}>Start Level {promo.level} →</button>
          )}
        </div>
      </div>
    </div>
  );
}
