import type { ReactNode } from "react";
import type { TFunction } from "i18next";
import { Trans, useTranslation } from "react-i18next";
import { Brand } from "../components/Chrome";
import type { ConsentContext } from "../page-context";

const ICONS: Record<string, ReactNode> = {
  identity: <><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></>,
  profile: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M7 10h6M7 14h10" /></>,
  groups: <><circle cx="9" cy="9" r="3" /><circle cx="17" cy="10" r="2.5" /><path d="M3 19a6 6 0 0 1 12 0M14 19a4 4 0 0 1 7 0" /></>,
  offline: <><path d="M20 12a8 8 0 1 1-2.3-5.7" /><path d="M20 4v5h-5" /></>,
  other: <><circle cx="12" cy="12" r="9" /><path d="M8 12h8" /></>,
};

type Grant = { key: string; icon: keyof typeof ICONS; what: string; detail?: ReactNode };

/** Requested scopes in plain words; profile and email read as one line, unknown scopes by name. */
function grants({ consent }: ConsentContext, t: TFunction): Grant[] {
  const scopes = new Set(consent.scopes);
  const list: Grant[] = [{ key: "openid", icon: "identity", what: t("consent.identity"), detail: t("consent.identityDetail", { client: consent.clientName }) }];
  if (scopes.has("profile") || scopes.has("email")) {
    const parts = [scopes.has("profile") && consent.username, scopes.has("email") && (consent.email || t("common.noEmail"))].filter(Boolean);
    list.push({ key: "profile", icon: "profile", what: scopes.has("email") ? t("consent.profileEmail") : t("consent.profile"), detail: parts.join(" · ") });
  }
  if (scopes.has("groups")) {
    list.push({ key: "groups", icon: "groups", what: t("consent.groups"), detail: consent.groups.length
      ? <span className="chips">{consent.groups.map(group => <span key={group} className="chip">{group}</span>)}</span> : t("consent.noGroups") });
  }
  if (scopes.has("offline_access")) {
    list.push({ key: "offline_access", icon: "offline", what: t("consent.offline"), detail: t("consent.offlineDetail") });
  }
  for (const scope of consent.scopes) {
    if (!["openid", "profile", "email", "groups", "offline_access"].includes(scope)) list.push({ key: scope, icon: "other", what: scope });
  }
  return list;
}

export function ConsentPage({ context }: { context: ConsentContext }) {
  const { t } = useTranslation();
  const { consent } = context;
  return (
    <main className="single wide">
      <div className="column">
        <div className="brand-row"><Brand host={false} /><span className="lead">{consent.username}</span></div>
        <section className="card" aria-labelledby="consent-title">
          <div className="lead-block">
            <h1 id="consent-title">{t("consent.heading", { client: consent.clientName })}</h1>
            {consent.returnHosts.length > 0 && <p className="lead"><Trans i18nKey="consent.returnsTo"
              values={{ hosts: consent.returnHosts.join(t("consent.hostSeparator")) }} components={{ code: <code /> }} /></p>}
          </div>
          <ul className="grants">
            {grants(context, t).map(grant => (
              <li key={grant.key}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">{ICONS[grant.icon]}</svg>
                <div><span className="what">{grant.what}</span>{grant.detail && <span className="detail">{grant.detail}</span>}</div>
              </li>
            ))}
          </ul>
          <div className="actions">
            <form method="post" action={context.action}>
              <input type="hidden" name="client_id" value={consent.clientId} />
              <input type="hidden" name="state" value={consent.state} />
              {consent.userCode && <input type="hidden" name="user_code" value={consent.userCode} />}
              <button className="secondary" type="submit">{t("consent.deny")}</button>
            </form>
            <form method="post" action={context.action}>
              <input type="hidden" name="client_id" value={consent.clientId} />
              <input type="hidden" name="state" value={consent.state} />
              {consent.userCode && <input type="hidden" name="user_code" value={consent.userCode} />}
              {consent.scopes.map(scope => <input key={scope} type="hidden" name="scope" value={scope} />)}
              <button className="primary" type="submit">{t("consent.allow")}</button>
            </form>
          </div>
          <p className="fine">{t("consent.remembered")}</p>
        </section>
      </div>
    </main>
  );
}
