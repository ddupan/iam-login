import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Brand } from "../components/Chrome";
import { problem, registerPasskey, type Problem } from "../components/Passkey";
import { SubmitForm } from "../components/SubmitForm";
import type { AccountContext } from "../page-context";

type Passkey = AccountContext["passkeys"][number];
type App = AccountContext["apps"][number];
/** Server codes plus "expired": the session needs both factors again (the server redirected or refused). */
type Failure = "expired" | "invalid" | "missing" | "last" | "failed";
type Pending = { kind: "rename"; passkey: Passkey } | { kind: "remove"; passkey: Passkey } | { kind: "revoke"; app: App };

const ACCOUNT_ERRORS: readonly Failure[] = ["expired", "invalid", "missing", "last", "failed"];
const SCOPES = ["openid", "profile", "email", "groups", "offline_access"] as const;

/** A modal confirmation; the native dialog gives focus trapping and Escape. */
function Dialog({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  return <dialog ref={ref} className="dialog" aria-labelledby="dialog-title" onClose={onClose}>
    <h2 id="dialog-title">{title}</h2>
    {children}
  </dialog>;
}

/** Profile, passkeys and granted applications of the signed-in account. Each change reloads the page. */
export function AccountPage({ context }: { context: AccountContext }) {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | Problem | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  useEffect(() => { document.title = t("account.title"); }, [t]);

  const time = (value: string) => value
    ? new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "";
  const scope = (name: string) => (SCOPES as readonly string[]).includes(name) ? t(`account.scope.${name as typeof SCOPES[number]}`) : name;

  async function send(method: "PUT" | "DELETE", path: string, body?: unknown) {
    setBusy(true);
    setFailure(null);
    try {
      const response = await fetch(path, {
        method, credentials: "same-origin", redirect: "error",
        headers: { "Content-Type": "application/json", [context.csrf.headerName]: context.csrf.value },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (response.ok) { window.location.reload(); return; }
      const code = await response.json().then(data => data?.error, () => undefined);
      setFailure(response.status === 401 || response.status === 403 ? "expired"
        : code === "invalid" || code === "missing" || code === "last" ? code : "failed");
    } catch {
      setFailure("expired");   // redirected to sign in: the factors are no longer fresh
    } finally {
      setBusy(false);
      setPending(null);
    }
  }

  async function add() {
    setBusy(true);
    setFailure(null);
    try {
      await registerPasskey(context.csrf, t("account.passkeys.defaultLabel"));
      window.location.reload();
    } catch (cause) {
      setFailure(problem(cause));
      setBusy(false);
    }
  }

  function rename(event: FormEvent<HTMLFormElement>, passkey: Passkey) {
    event.preventDefault();
    const label = new FormData(event.currentTarget).get("label");
    send("PUT", `/account/passkeys/${encodeURIComponent(passkey.id)}/label`, { label });
  }

  const only = context.passkeys.length <= 1;
  // Passkey ceremony problems reuse the sign-in catalogue; "expired" there means the same thing.
  const message = failure && (ACCOUNT_ERRORS.includes(failure as Failure)
    ? t(`account.error.${failure as Failure}`) : t(`passkey.error.${failure as Problem}`));
  const { profile } = context;

  return <div className="page">
    <header className="topbar">
      <div className="topbar-inner">
        <Brand host={false} />
        <nav aria-label={t("account.nav.label")}>
          <a href="/account" aria-current="page">{t("account.nav.account")}</a>
          <a href="/console">{t("account.nav.console")}</a>
        </nav>
        <div className="topbar-user">
          <span>{profile.username}</span>
          <SubmitForm action={context.action} csrf={context.csrf} label={t("common.signOut")} className="secondary small" />
        </div>
      </div>
    </header>
    <main className="account">
      <h1>{t("account.heading")}</h1>
      {message && <Alert>{message}{failure === "expired" && <> <a href="/account">{t("account.verifyAgain")}</a></>}</Alert>}

      <section className="panel" aria-labelledby="profile">
        <div className="panel-head">
          <h2 id="profile">{t("account.profile.heading")}</h2>
          <span className="hint">{t("account.profile.readOnly")}</span>
        </div>
        <dl className="facts">
          <div><dt>{t("account.profile.username")}</dt><dd>{profile.username}</dd></div>
          <div><dt>{t("account.profile.directory")}</dt><dd>{profile.directory}</dd></div>
          <div><dt>{t("account.profile.displayName")}</dt><dd>{profile.displayName}</dd></div>
          <div><dt>{t("account.profile.email")}</dt><dd>{profile.email || t("common.noEmail")}</dd></div>
          <div className="wide"><dt>{t("account.profile.groups")}</dt>
            <dd>{profile.groups.length > 0
              ? <span className="chips">{profile.groups.map(group => <span key={group} className="chip">{group}</span>)}</span>
              : t("consent.noGroups")}</dd></div>
        </dl>
      </section>

      <section className="panel" aria-labelledby="passkeys">
        <div className="panel-head">
          <div className="lead-block">
            <h2 id="passkeys">{t("account.passkeys.heading")}</h2>
            <span className="hint">{t("account.passkeys.lead")}</span>
          </div>
          <button type="button" className="primary" disabled={busy} onClick={add}>{t("account.passkeys.add")}</button>
        </div>
        <ul className="rows">
          {context.passkeys.map(passkey => <li key={passkey.id}>
            <div className="row-main">
              <span className="row-title">{passkey.label}</span>
              <span className="hint">{[
                passkey.created && t("account.passkeys.created", { time: time(passkey.created) }),
                passkey.lastUsed && t("account.passkeys.lastUsed", { time: time(passkey.lastUsed) }),
              ].filter(Boolean).join(" · ")}</span>
            </div>
            <div className="row-actions">
              <button type="button" className="secondary small" disabled={busy}
                onClick={() => setPending({ kind: "rename", passkey })}>{t("account.passkeys.rename")}</button>
              <button type="button" className="secondary small danger" disabled={busy || only}
                aria-describedby={only ? "only-factor" : undefined}
                onClick={() => setPending({ kind: "remove", passkey })}>{t("account.passkeys.remove")}</button>
            </div>
          </li>)}
        </ul>
        {only && <p id="only-factor" className="hint">{t("account.passkeys.onlyFactor")}</p>}
      </section>

      <section className="panel" aria-labelledby="apps">
        <div className="lead-block">
          <h2 id="apps">{t("account.apps.heading")}</h2>
          <span className="hint">{t("account.apps.lead")}</span>
        </div>
        {context.apps.length === 0 ? <p className="hint">{t("account.apps.empty")}</p> : <div className="scroll">
          <table>
            <thead><tr>
              <th>{t("account.apps.app")}</th><th>{t("account.apps.scopes")}</th><th>{t("account.apps.lastIssued")}</th>
              <th><span className="visually-hidden">{t("account.apps.actions")}</span></th>
            </tr></thead>
            <tbody>{context.apps.map(app => <tr key={app.clientId}>
              <td className="row-title">{app.name}</td>
              <td className="hint">{app.scopes.map(scope).join(t("account.apps.separator"))}</td>
              <td className="hint">{time(app.lastIssued)}</td>
              <td className="end"><button type="button" className="secondary small" disabled={busy}
                onClick={() => setPending({ kind: "revoke", app })}>{t("account.apps.revoke")}</button></td>
            </tr>)}</tbody>
          </table>
        </div>}
      </section>
    </main>

    {pending?.kind === "rename" && <Dialog title={t("account.passkeys.renameTitle")} onClose={() => setPending(null)}>
      <form onSubmit={event => rename(event, pending.passkey)}>
        <div className="field">
          <label htmlFor="label">{t("account.passkeys.label")}</label>
          <input id="label" name="label" required maxLength={64} defaultValue={pending.passkey.label} autoFocus />
        </div>
        <div className="dialog-actions">
          <button type="button" className="secondary" onClick={() => setPending(null)}>{t("account.cancel")}</button>
          <button type="submit" className="primary" disabled={busy}>{t("account.save")}</button>
        </div>
      </form>
    </Dialog>}
    {pending?.kind === "remove" && <Dialog title={t("account.passkeys.removeTitle", { label: pending.passkey.label })} onClose={() => setPending(null)}>
      <p className="lead">{t("account.passkeys.removeLead")}</p>
      <div className="dialog-actions">
        <button type="button" className="secondary" onClick={() => setPending(null)}>{t("account.cancel")}</button>
        <button type="button" className="primary danger" disabled={busy}
          onClick={() => send("DELETE", `/account/passkeys/${encodeURIComponent(pending.passkey.id)}`)}>{t("account.passkeys.remove")}</button>
      </div>
    </Dialog>}
    {pending?.kind === "revoke" && <Dialog title={t("account.apps.revokeTitle", { app: pending.app.name })} onClose={() => setPending(null)}>
      <p className="lead">{t("account.apps.revokeLead")}</p>
      <div className="dialog-actions">
        <button type="button" className="secondary" onClick={() => setPending(null)}>{t("account.cancel")}</button>
        <button type="button" className="primary danger" disabled={busy}
          onClick={() => send("DELETE", `/account/apps/${encodeURIComponent(pending.app.clientId)}`)}>{t("account.apps.revoke")}</button>
      </div>
    </Dialog>}
  </div>;
}
