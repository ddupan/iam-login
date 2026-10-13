import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

export function Brand({ host = true }: { host?: boolean }) {
  const { t } = useTranslation();
  return (
    <a href="/signin" className="brand">
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="2"
        style={{ color: "var(--accent)" }} aria-hidden="true">
        <rect x="4" y="12" width="20" height="13" rx="3" /><path d="M9 12V8a5 5 0 0 1 10 0v4" />
      </svg>
      <strong>ddupan</strong>
      {host && <span>{t("brand.host", { host: window.location.host })}</span>}
    </a>
  );
}

/** One focused task in a centered column: sign-in, two-step verification, consent. */
export function Single({ wide, top, children, below }: { wide?: boolean; top?: ReactNode; children: ReactNode; below?: ReactNode }) {
  return (
    <main className={wide ? "single wide" : "single"}>
      <div className="column">
        {top ?? <Brand />}
        <section className="card">{children}</section>
        {below && <div className="below">{below}</div>}
      </div>
    </main>
  );
}

export function Alert({ kind = "error", children }: { kind?: "error" | "warn"; children: ReactNode }) {
  return (
    <div className={`alert ${kind}`} role="alert">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
        <circle cx="12" cy="12" r="9" /><path d="M12 7v6M12 16.5v.5" />
      </svg>
      <span>{children}</span>
    </div>
  );
}

export function Steps({ current }: { current: 1 | 2 }) {
  const { t } = useTranslation();
  return (
    <ol className="steps" aria-label={t("steps.label")}>
      <li className={current === 1 ? "current" : "done"}><span className="dot">{current === 1 ? "1" : "✓"}</span>{t("steps.password")}</li>
      <li aria-hidden="true">—</li>
      <li className={current === 2 ? "current" : ""} aria-current={current === 2 ? "step" : undefined}><span className="dot">2</span>{t("steps.secondFactor")}</li>
    </ol>
  );
}
