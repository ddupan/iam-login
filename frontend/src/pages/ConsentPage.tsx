import type { ReactNode } from "react";
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
function grants({ consent }: ConsentContext): Grant[] {
  const scopes = new Set(consent.scopes);
  const list: Grant[] = [{ key: "openid", icon: "identity", what: "确认你的身份", detail: `账号标识，用于在 ${consent.clientName} 中关联你` }];
  if (scopes.has("profile") || scopes.has("email")) {
    const parts = [scopes.has("profile") && consent.username, scopes.has("email") && (consent.email || "未设置邮箱")].filter(Boolean);
    list.push({ key: "profile", icon: "profile", what: scopes.has("email") ? "用户名、显示名和邮箱" : "用户名和显示名", detail: parts.join(" · ") });
  }
  if (scopes.has("groups")) {
    list.push({ key: "groups", icon: "groups", what: "你所在的组", detail: consent.groups.length
      ? <span className="chips">{consent.groups.map(group => <span key={group} className="chip">{group}</span>)}</span> : "没有直接所属组" });
  }
  if (scopes.has("offline_access")) {
    list.push({ key: "offline_access", icon: "offline", what: "在你离开后保持访问", detail: "无需你在场即可续期，直到你撤销授权" });
  }
  for (const scope of consent.scopes) {
    if (!["openid", "profile", "email", "groups", "offline_access"].includes(scope)) list.push({ key: scope, icon: "other", what: scope });
  }
  return list;
}

export function ConsentPage({ context }: { context: ConsentContext }) {
  const { consent } = context;
  return (
    <main className="single wide">
      <div className="column">
        <div className="brand-row"><Brand host={false} /><span className="lead">{consent.username}</span></div>
        <section className="card" aria-labelledby="consent-title">
          <div className="lead-block">
            <h1 id="consent-title">{consent.clientName} 请求访问你的账号</h1>
            {consent.returnHosts.length > 0 && <p className="lead">完成后返回 <code>{consent.returnHosts.join("、")}</code></p>}
          </div>
          <ul className="grants">
            {grants(context).map(grant => (
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
              <button className="secondary" type="submit">拒绝</button>
            </form>
            <form method="post" action={context.action}>
              <input type="hidden" name="client_id" value={consent.clientId} />
              <input type="hidden" name="state" value={consent.state} />
              {consent.userCode && <input type="hidden" name="user_code" value={consent.userCode} />}
              {consent.scopes.map(scope => <input key={scope} type="hidden" name="scope" value={scope} />)}
              <button className="primary" type="submit">允许</button>
            </form>
          </div>
          <p className="fine">允许后，下次同样的请求不再询问。</p>
        </section>
      </div>
    </main>
  );
}
