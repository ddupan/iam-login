import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Dialog } from "./Chrome";

type Account = {
  username: string; displayName: string; directory: string;
  passkeys: { label: string; created: string; lastUsed: string }[];
  /** Empty when none is set up. */
  authenticator: { created?: string; lastUsed?: string };
};
type Problem = "missing" | "forbidden" | "unavailable" | "failed";

/** Looks one account up and resets its two-step verification; the accounts themselves live in the directory. */
export function UsersPanel({ token, onExpired }: { token: string; onExpired: () => void }) {
  const { t, i18n } = useTranslation();
  const [account, setAccount] = useState<Account | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [reset, setReset] = useState(false);

  const time = (value?: string) => value
    ? new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "";
  const path = (username: string) => `/api/iam/users/${encodeURIComponent(username)}`;

  /** The response, or null once the problem is shown. */
  async function call(method: "GET" | "DELETE", url: string) {
    setBusy(true); setProblem(null);
    try {
      const response = await fetch(url, { method, cache: "no-store", redirect: "error", headers: { Authorization: `Bearer ${token}` } });
      if (response.status === 401) { onExpired(); return null; }
      if (response.ok) return response;
      setProblem(response.status === 404 ? "missing" : response.status === 403 ? "forbidden"
        : response.status === 502 ? "unavailable" : "failed");
    } catch {
      setProblem("failed");
    } finally {
      setBusy(false);
    }
    return null;
  }

  async function load(username: string) {
    const response = await call("GET", path(username));
    setAccount(response && await response.json());
  }

  function find(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setReset(false);
    load(String(new FormData(event.currentTarget).get("username")).trim());
  }

  async function confirmReset(username: string) {
    setConfirming(false);
    if (await call("DELETE", `${path(username)}/second-factors`)) {
      setReset(true);
      await load(username);
    }
  }

  const hasAuthenticator = Boolean(account?.authenticator.created);
  const dates = (created: string | undefined, lastUsed: string | undefined,
    createdKey: "account.passkeys.created" | "account.authenticator.created") => [
    created && t(createdKey, { time: time(created) }),
    lastUsed && t("account.passkeys.lastUsed", { time: time(lastUsed) }),
  ].filter(Boolean).join(" · ");

  return <section className="panel" aria-busy={busy}>
    <div className="lead-block">
      <h1>{t("users.heading")}</h1>
      <span className="hint">{t("users.lead")}</span>
    </div>
    <form role="search" className="search" onSubmit={find}>
      <div className="field">
        <label htmlFor="username">{t("users.username")}</label>
        <input id="username" name="username" required autoComplete="off" spellCheck={false} />
      </div>
      <button type="submit" className="primary" disabled={busy}>{t("users.find")}</button>
    </form>
    {problem && <Alert>{t(`users.error.${problem}`)}</Alert>}
    {reset && <p className="hint" role="status">{t("users.resetDone")}</p>}

    {account && <>
      <div className="lead-block">
        <h2>{account.username}</h2>
        <span className="hint">{account.displayName} · {account.directory}</span>
      </div>
      {account.passkeys.length + (hasAuthenticator ? 1 : 0) === 0
        ? <p className="hint">{t("users.noFactors")}</p>
        : <ul className="rows">
          {account.passkeys.map((passkey, index) => <li key={index}>
            <div className="row-main">
              <span className="row-title">{t("users.passkey", { label: passkey.label })}</span>
              <span className="hint">{dates(passkey.created, passkey.lastUsed, "account.passkeys.created")}</span>
            </div>
          </li>)}
          {hasAuthenticator && <li>
            <div className="row-main">
              <span className="row-title">{t("account.authenticator.set")}</span>
              <span className="hint">{dates(account.authenticator.created, account.authenticator.lastUsed, "account.authenticator.created")}</span>
            </div>
          </li>}
        </ul>}
      <div className="panel-head">
        <div className="lead-block">
          <span className="row-title">{t("users.reset")}</span>
          <span className="hint">{t("users.resetLead")}</span>
        </div>
        <button type="button" className="secondary danger" disabled={busy} onClick={() => setConfirming(true)}>{t("users.resetAction")}</button>
      </div>
    </>}

    {confirming && account && <Dialog title={t("users.resetTitle", { username: account.username })} onClose={() => setConfirming(false)}>
      <p className="lead">{t("users.resetLead")}</p>
      <div className="dialog-actions">
        <button type="button" className="secondary" onClick={() => setConfirming(false)}>{t("account.cancel")}</button>
        <button type="button" className="primary danger" disabled={busy} onClick={() => confirmReset(account.username)}>{t("users.resetAction")}</button>
      </div>
    </Dialog>}
  </section>;
}
