import { useContext, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Alert, Dialog } from "./Chrome";
import { Link, Navigate, useAction, type Api } from "./consoleKit";

export type Client = {
  id: string; name: string; redirectUris: string[]; scopes: string[]; postLogoutRedirectUris: string[];
  loginEnabled: boolean; pkceRequired: boolean; publicClient: boolean; deviceAuthorization: boolean; audiences: string[];
  /** Kept as stored when editing; the form does not show it. */
  tokenEndpointAuthMethod?: string;
};
export type Secret = { id: string; value: string; kind: "created" | "rotated" };
type Props = { api: Api; onExpired: () => void };

const blank: Client = { id: "", name: "", redirectUris: [], scopes: ["openid", "profile", "email", "groups"],
  postLogoutRedirectUris: [], loginEnabled: true, pkceRequired: true, publicClient: false, deviceAuthorization: false, audiences: [] };
const path = (id: string) => `/api/iam/clients/${encodeURIComponent(id)}`;
export const clientPage = (id: string) => `/console/clients/${encodeURIComponent(id)}`;

function Problem({ status }: { status: number | null }) {
  const { t } = useTranslation();
  if (status === null) return null;
  const key = status === 400 || status === 403 || status === 404 || status === 409 ? String(status) as "400"
    : status === 502 ? "unavailable" : "failed";
  return <Alert>{t(`clients.error.${key}`)}</Alert>;
}

export function ClientList({ api, onExpired }: Props) {
  const { t } = useTranslation();
  const { busy, status, run } = useAction(onExpired);
  const [clients, setClients] = useState<Client[] | null>(null);
  // ponytail: first page only (the API pages before dropping unmanaged clients); add paging past 100 clients.
  useEffect(() => { run(async () => setClients(await api<Client[]>("GET", "/api/iam/clients?page=0&size=100"))); }, [api, run]);

  return <>
    <div className="page-head">
      <div className="lead-block">
        <h1>{t("clients.heading")}</h1>
        <span className="hint">{t("clients.lead")}</span>
      </div>
      <Link to="/console/clients/new" className="secondary">{t("clients.new")}</Link>
    </div>
    <Problem status={status} />
    {clients && (clients.length === 0 ? <p className="hint">{t("clients.empty")}</p> : <div className="panel flush scroll" aria-busy={busy}>
      <table>
        <thead><tr>
          <th>{t("clients.id")}</th><th>{t("clients.name")}</th><th>{t("clients.type")}</th><th>{t("clients.login")}</th>
          <th>{t("clients.status")}</th><th><span className="visually-hidden">{t("clients.actions")}</span></th>
        </tr></thead>
        <tbody>{clients.map(client => <tr key={client.id}>
          <td className="mono">{client.id}</td>
          <td>{client.name}</td>
          <td>{t(client.publicClient ? "clients.public" : "clients.confidential")}</td>
          <td>{[t("clients.browser"), client.deviceAuthorization && t("clients.device")].filter(Boolean).join(t("clients.separator"))}</td>
          <td className={client.loginEnabled ? undefined : "danger-text"}>{t(client.loginEnabled ? "clients.enabled" : "clients.disabled")}</td>
          <td className="end"><Link to={clientPage(client.id)}>{t("clients.view")}</Link></td>
        </tr>)}</tbody>
      </table>
    </div>)}
  </>;
}

type Confirm = "disable" | "enable" | "rotate" | "delete";

export function ClientDetail({ api, onExpired, id, onSecret }: Props & { id: string; onSecret: (secret: Secret) => void }) {
  const { t } = useTranslation();
  const navigate = useContext(Navigate);
  const { busy, status, run } = useAction(onExpired);
  const [client, setClient] = useState<Client | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  useEffect(() => { run(async () => setClient(await api<Client>("GET", path(id)))); }, [api, run, id]);

  const list = (values: string[]) => values.length ? <ul className="plain">{values.map(v => <li key={v} className="mono">{v}</li>)}</ul> : t("clients.none");
  const act = (kind: Confirm) => { setConfirm(null); run(async () => {
    if (!client) return;
    if (kind === "rotate") {
      onSecret({ id, value: (await api<{ secret: string }>("POST", `${path(id)}/secret`)).secret, kind: "rotated" });
    } else if (kind === "delete") {
      await api("DELETE", path(id));
      navigate("/console");
    } else {
      setClient(await api<Client>("PUT", path(id), { ...client, loginEnabled: kind === "enable" }));
    }
  }); };

  const action = (kind: Confirm, lead: ReactNode) => <li>
    <div className="row-main">
      <span className="row-title">{t(`clients.${kind}`)}</span>
      <span className="hint">{lead}</span>
    </div>
    <button type="button" className={kind === "enable" ? "secondary small" : "secondary small danger"} disabled={busy}
      onClick={() => setConfirm(kind)}>{t(`clients.${kind}`)}</button>
  </li>;

  return <>
    <Link to="/console" className="back">{t("clients.back")}</Link>
    <Problem status={status} />
    {client && <>
      <div className="page-head">
        <div className="lead-block">
          <h1>{client.name}</h1>
          <span className="hint mono">{client.id} · {t(client.loginEnabled ? "clients.enabled" : "clients.disabled")}</span>
        </div>
        <Link to={`${clientPage(id)}/edit`} className="secondary">{t("clients.edit")}</Link>
      </div>
      <section className="panel" aria-labelledby="config">
        <h2 id="config">{t("clients.config")}</h2>
        <dl className="facts">
          <div className="wide"><dt>{t("clients.redirectUris")}</dt><dd>{list(client.redirectUris)}</dd></div>
          <div className="wide"><dt>{t("clients.scopes")}</dt>
            <dd><span className="chips">{client.scopes.toSorted().map(scope => <span key={scope} className="chip">{scope}</span>)}</span></dd></div>
          <div><dt>{t("clients.type")}</dt><dd>{t(client.publicClient ? "clients.public" : "clients.confidential")}</dd></div>
          <div><dt>{t("clients.deviceLogin")}</dt><dd>{t(client.deviceAuthorization ? "clients.allowed" : "clients.notAllowed")}</dd></div>
          <div><dt>{t("clients.pkce")}</dt><dd>{t(client.pkceRequired ? "clients.required" : "clients.off")}</dd></div>
          <div><dt>{t("clients.refresh")}</dt><dd>{t(client.scopes.includes("offline_access") ? "clients.issued" : "clients.notIssued")}</dd></div>
          <div><dt>{t("clients.audiences")}</dt><dd>{list(client.audiences)}</dd></div>
          <div><dt>{t("clients.postLogoutRedirectUris")}</dt><dd>{list(client.postLogoutRedirectUris)}</dd></div>
        </dl>
      </section>
      <section className="panel" aria-labelledby="emergency">
        <h2 id="emergency">{t("clients.emergency")}</h2>
        <ul className="rows">
          {client.loginEnabled ? action("disable", t("clients.disableLead")) : action("enable", t("clients.enableLead"))}
          {!client.publicClient && action("rotate", t("clients.rotateLead"))}
          {action("delete", t("clients.deleteLead"))}
        </ul>
      </section>
    </>}
    {confirm && <Dialog title={t(`clients.confirm.${confirm}`, { id })} onClose={() => setConfirm(null)}>
      <p className="lead">{t(`clients.${confirm}Lead`)}</p>
      <div className="dialog-actions">
        <button type="button" className="secondary" onClick={() => setConfirm(null)}>{t("clients.cancel")}</button>
        <button type="button" className={confirm === "enable" ? "primary" : "primary danger"} disabled={busy}
          onClick={() => act(confirm)}>{t(`clients.${confirm}`)}</button>
      </div>
    </Dialog>}
  </>;
}

export function ClientForm({ api, onExpired, id, onSecret }: Props & { id?: string; onSecret: (secret: Secret) => void }) {
  const { t } = useTranslation();
  const navigate = useContext(Navigate);
  const { busy, status, run } = useAction(onExpired);
  const [client, setClient] = useState<Client | null>(id ? null : blank);
  useEffect(() => { if (id) run(async () => setClient(await api<Client>("GET", path(id)))); }, [api, run, id]);

  const save = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!client) return;
    const form = new FormData(event.currentTarget);
    const lines = (name: string) => String(form.get(name) ?? "").split("\n").map(line => line.trim()).filter(Boolean);
    // Starts from the stored client, so fields this form does not show are kept as they are.
    const next: Client = {
      ...client,
      id: id ?? String(form.get("id")).trim(),
      name: String(form.get("name")).trim(),
      redirectUris: lines("redirectUris"),
      scopes: [...new Set(["openid", ...String(form.get("scopes")).split(/\s+/).filter(Boolean)])],
      postLogoutRedirectUris: lines("postLogoutRedirectUris"),
      audiences: lines("audiences"),
      loginEnabled: form.get("loginEnabled") !== null,
      pkceRequired: form.get("pkceRequired") !== null,
      deviceAuthorization: form.get("deviceAuthorization") !== null,
      publicClient: id ? client.publicClient : form.get("publicClient") !== null,
    };
    run(async () => {
      if (id) {
        await api("PUT", path(id), next);
      } else {
        const created = await api<{ secret: string | null }>("POST", "/api/iam/clients", next);
        if (created.secret) onSecret({ id: next.id, value: created.secret, kind: "created" });
      }
      navigate(clientPage(next.id));
    });
  };

  return <>
    <Link to={id ? clientPage(id) : "/console"} className="back">{id ? t("clients.backTo", { id }) : t("clients.back")}</Link>
    <h1>{id ? t("clients.editTitle", { id }) : t("clients.newTitle")}</h1>
    <Problem status={status} />
    {client && <form className="panel" onSubmit={save}>
      {!id && <div className="field"><label htmlFor="id">{t("clients.id")}</label>
        <input id="id" name="id" required pattern="[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}" autoComplete="off" spellCheck={false} /></div>}
      <div className="field"><label htmlFor="name">{t("clients.name")}</label>
        <input id="name" name="name" required maxLength={200} defaultValue={client.name} /></div>
      <div className="field"><label htmlFor="redirectUris">{t("clients.redirectUrisInput")}</label>
        <textarea id="redirectUris" name="redirectUris" required rows={3} defaultValue={client.redirectUris.join("\n")} /></div>
      <div className="field"><label htmlFor="scopes">{t("clients.scopesInput")}</label>
        <input id="scopes" name="scopes" required defaultValue={client.scopes.join(" ")} spellCheck={false} /></div>
      <div className="field"><label htmlFor="postLogoutRedirectUris">{t("clients.postLogoutInput")}</label>
        <textarea id="postLogoutRedirectUris" name="postLogoutRedirectUris" rows={2} defaultValue={client.postLogoutRedirectUris.join("\n")} /></div>
      <div className="field"><label htmlFor="audiences">{t("clients.audiencesInput")}</label>
        <textarea id="audiences" name="audiences" rows={2} defaultValue={client.audiences.join("\n")} /></div>
      {!id && <label className="check"><input type="checkbox" name="publicClient" defaultChecked={client.publicClient} />{t("clients.publicInput")}</label>}
      <label className="check"><input type="checkbox" name="deviceAuthorization" defaultChecked={client.deviceAuthorization} />{t("clients.deviceInput")}</label>
      <label className="check"><input type="checkbox" name="pkceRequired" defaultChecked={client.pkceRequired} />{t("clients.pkceInput")}</label>
      <label className="check"><input type="checkbox" name="loginEnabled" defaultChecked={client.loginEnabled} />{t("clients.loginInput")}</label>
      <div className="dialog-actions">
        <Link to={id ? clientPage(id) : "/console"} className="secondary">{t("clients.cancel")}</Link>
        <button className="primary" type="submit" disabled={busy}>{t(id ? "clients.save" : "clients.create")}</button>
      </div>
    </form>}
  </>;
}

/** Shown once, right after creation or rotation; afterwards the secret can only be replaced. */
export function SecretOnce({ secret, onDone }: { secret: Secret; onDone: () => void }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard.writeText(secret.value).then(() => setCopied(true), () => setCopied(false));
  return <section className="panel narrow" aria-labelledby="secret-title">
    <h1 id="secret-title">{t(`clients.secret.${secret.kind}`)}</h1>
    <p className="lead"><Trans i18nKey="clients.secret.once" values={{ id: secret.id }} components={{ strong: <strong className="mono" /> }} /></p>
    <div className="field">
      <label htmlFor="secret-value">{t("clients.secret.label")}</label>
      <div className="copy-row">
        <output id="secret-value" className="secret mono">{secret.value}</output>
        <button type="button" className="secondary small" onClick={copy}>{t(copied ? "clients.secret.copied" : "clients.secret.copy")}</button>
      </div>
      <span className="hint">{t("clients.secret.store")}</span>
    </div>
    <label className="check"><input type="checkbox" checked={saved} onChange={event => setSaved(event.target.checked)} />{t("clients.secret.saved")}</label>
    <button type="button" className="primary" disabled={!saved} onClick={onDone}>{t("clients.secret.done")}</button>
  </section>;
}
