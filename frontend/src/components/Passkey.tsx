import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { CsrfToken } from "../page-context";
import { Alert } from "./Chrome";

export type Problem = "expired" | "unsupported" | "cancelled" | "timeout" | "failed";

/** A failure whose message is a catalogue key, so the text follows the page language. */
export class Failure extends Error {
  constructor(readonly problem: Problem) { super(problem); }
}

/** What went wrong, as a catalogue key: a DOMException is the browser's own cancel or timeout. */
export function problem(cause: unknown): Problem {
  return cause instanceof DOMException ? "timeout" : cause instanceof Failure ? cause.problem : "failed";
}

function supported() {
  if (!PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) {
    throw new Failure("unsupported");
  }
}

async function post(csrf: CsrfToken, path: string, body?: unknown) {
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin", redirect: "error",
    headers: { "Content-Type": "application/json", [csrf.headerName]: csrf.value },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) {
    throw new Failure("expired");
  }
  return response.json();
}

/** The registration ceremony: the server decides whether this session may add a credential. */
export async function registerPasskey(csrf: CsrfToken, label: string) {
  supported();
  const options = await post(csrf, "/webauthn/register/options");
  const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
  }) as PublicKeyCredential | null;
  if (!credential) throw new Failure("cancelled");
  await post(csrf, "/webauthn/register", { publicKey: { credential: credential.toJSON(), label } });
}

/**
 * Registers (first time) or verifies a passkey; the server owns every factor decision. {@code alternative} (the
 * other method) is offered only in the initial step: once a passkey is created, it is the one to verify with.
 */
export function Passkey({ csrf, initial, who, alternative }: {
  csrf: CsrfToken; initial: "register" | "authenticate"; who: string; alternative?: ReactNode;
}) {
  const { t } = useTranslation();
  const [step, setStep] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Problem | null>(null);
  const [registered, setRegistered] = useState(false);

  async function perform() {
    setBusy(true);
    setError(null);
    try {
      supported();
      if (step === "register") {
        await registerPasskey(csrf, "Passkey");
        setRegistered(true);
        setStep("authenticate");
      } else {
        const options = await post(csrf, "/webauthn/authenticate/options");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        }) as PublicKeyCredential | null;
        if (!credential) throw new Failure("cancelled");
        // Spring Security answers with the request that was interrupted for login (it consumes the saved
        // request); "/" means there was none, and the sign-in result page decides what comes next.
        const result = await post(csrf, "/login/webauthn", credential.toJSON());
        const target = typeof result.redirectUrl === "string" ? new URL(result.redirectUrl, window.location.origin) : null;
        window.location.assign(target && target.origin === window.location.origin && target.pathname !== "/"
          ? target.toString() : "/signin/complete");
      }
    } catch (cause) {
      setError(problem(cause));
    } finally {
      setBusy(false);
    }
  }

  const alert = error && <Alert>{t(`passkey.error.${error}`)}</Alert>;
  if (step === "register") {
    return <>
      <div className="lead-block">
        <h1>{t("passkey.createHeading")}</h1>
        <p className="lead">{t("passkey.createLead")}</p>
      </div>
      <div className="who"><span className="avatar" aria-hidden="true">{who.slice(0, 1).toUpperCase()}</span>
        <div><span>{who}</span><span>{t("passkey.justVerified")}</span></div></div>
      {alert}
      <button className="primary" type="button" disabled={busy} onClick={perform}>{busy ? t("passkey.waitingShort") : t("passkey.create")}</button>
      <p className="fine">{t("passkey.createHint")}</p>
      {alternative}
    </>;
  }
  return <>
    <div className="centered">
      <div className="badge-icon" aria-hidden="true">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M12 11c0 3-1 6-3 8" /><path d="M8 7a5 5 0 0 1 9 3c0 2 0 4-1 6" /><path d="M5 10a7 7 0 0 1 2-5" /><path d="M12 11c0 2 .5 4 1.5 6" />
        </svg>
      </div>
      <h1>{registered ? t("passkey.created") : t("passkey.verifyHeading")}</h1>
      <p className="lead">{registered ? t("passkey.createdLead") : t("passkey.verifyLead")}</p>
    </div>
    {alert}
    {busy && <p className="status" role="status">{t("passkey.waiting")}</p>}
    <button className="primary" type="button" disabled={busy} onClick={perform}>{error ? t("passkey.retry") : t("passkey.verify")}</button>
    {step === initial && alternative}
  </>;
}
