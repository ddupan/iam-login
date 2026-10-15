import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Dialog } from "./Chrome";
import { useAction, type Api } from "./consoleKit";

type Account = {
  username: string; displayName: string; directory: string;
  passkeys: { label: string; created: string; lastUsed: string }[];
  /** Empty when none is set up. */
  authenticator: { created?: string; lastUsed?: string };
};
type Problem = "missing" | "forbidden" | "unavailable" | "failed";

/** Looks one account up and resets its two-step verification; the accounts themselves live in the directory. */
export function UsersPanel({ api, onExpired }: { api: Api; onExpired: () => void }) {
  const { t, i18n } = useTranslation();
  const { busy, status, run } = useAction(onExpired);
  const [account, setAccount] = useState<Account | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [reset, setReset] = useState(false);

  const time = (value?: string) => value
    ? new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "";
  const path = (username: string) => `/api/iam/users/${encodeURIComponent(username)}`;
  const problem: Problem | null = status === null ? null
    : status === 404 ? "missing" : status === 403 ? "forbidden" : status === 502 ? "unavailable" : "failed";

  function find(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const username = String(new FormData(event.currentTarget).get("username")).trim();
    setReset(false);
    setAccount(null);
    run(async () => setAccount(await api<Account>("GET", path(username))));
  }

  function confirmReset(username: string) {
    setConfirming(false);
    run(async () => {
      await api("DELETE", `${path(username)}/second-factors`);
      setReset(true);
      setAccount(await api<Account>("GET", path(username)));
    });
  }

  const hasAuthenticator = Boolean(account?.authenticator.created);
  const dates = (created: string | undefined, lastUsed: string | undefined,
    createdKey: "account.passkeys.created" | "account.authenticator.created") => [
    created && t(createdKey, { time: time(created) }),
    lastUsed && t("account.passkeys.lastUsed", { time: time(lastUsed) }),
  ].filter(Boolean).join(" · ");

  return <>
    <div className="lead-block">
      <h1>{t("users.heading")}</h1>
      <span className="hint">{t("users.lead")}</span>
    </div>
    <section className="panel" aria-busy={busy}>
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
    </section>
  </>;
}
