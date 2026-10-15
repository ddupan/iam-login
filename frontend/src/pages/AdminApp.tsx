import { useCallback, useEffect, useMemo, useState } from "react";
import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import { useTranslation } from "react-i18next";
import { Alert, Brand } from "../components/Chrome";
import { ClientDetail, ClientForm, ClientList, SecretOnce, clientPage, type Secret } from "../components/Clients";
import { bearerApi, Link, Navigate } from "../components/consoleKit";
import { UsersPanel } from "../components/UsersPanel";
import type { AdminContext } from "../page-context";

type Problem = "" | "unreachable" | "incomplete" | "expired";
const CALLBACK = "/console/callback";

/** Path → view. Anything unknown is the client list. */
function route(path: string) {
  if (path === "/console/users") return { view: "users" as const };
  if (path === "/console/clients/new") return { view: "new" as const };
  const client = /^\/console\/clients\/([^/]+)(\/edit)?$/.exec(path);
  if (client) return { view: client[2] ? "edit" as const : "client" as const, id: decodeURIComponent(client[1]) };
  return { view: "clients" as const };
}

/** Ordinary OIDC public client of this server; it holds no privileges beyond the access token it is granted. */
export function AdminApp({ context }: { context: AdminContext }) {
  const { t } = useTranslation();
  const [manager] = useState(() => new UserManager({
    authority: context.authority,
    client_id: context.clientId,
    redirect_uri: `${window.location.origin}${CALLBACK}`,
    post_logout_redirect_uri: `${window.location.origin}/signin`,
    // groups carries the identity facts the API authorizes on; its audience is registered with this client.
    scope: "openid profile groups",
    // Tokens stay in memory: a reload signs in again rather than leaving a bearer token in storage.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: false,
    monitorSession: false,
    loadUserInfo: false,
  }));
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<Problem>("");
  const [path, setPath] = useState(window.location.pathname);
  const [secret, setSecret] = useState<Secret | null>(null);

  // The path asked for survives the round trip through sign-in.
  const signIn = useCallback((target: string) => {
    setError("");
    manager.signinRedirect({ state: target }).catch(() => setError("unreachable"));
  }, [manager]);

  useEffect(() => {
    if (window.location.pathname !== CALLBACK) { signIn(window.location.pathname); return; }
    manager.signinRedirectCallback().then(signedIn => {
      const target = typeof signedIn.state === "string" && signedIn.state.startsWith("/console") ? signedIn.state : "/console";
      window.history.replaceState(null, "", target);
      setPath(target);
      setUser(signedIn);
    }).catch(() => setError("incomplete"));
  }, [manager, signIn]);

  useEffect(() => {
    const back = () => setPath(window.location.pathname);
    window.addEventListener("popstate", back);
    return () => window.removeEventListener("popstate", back);
  }, []);

  const navigate = useCallback((to: string) => {
    window.history.pushState(null, "", to);
    setPath(to);
    window.scrollTo(0, 0);
  }, []);
  const expired = useCallback(() => { setUser(null); setError("expired"); }, []);
  const api = useMemo(() => user && bearerApi(user.access_token), [user]);
  const showSecret = useCallback((value: Secret) => setSecret(value), []);
  const current = route(path);
  const section = current.view === "users" ? "users" : "clients";
  const name = user?.profile.preferred_username ?? user?.profile.sub;

  let view = null;
  if (api) {
    const props = { api, onExpired: expired };
    view = current.view === "users" ? <UsersPanel {...props} />
      : current.view === "new" ? <ClientForm {...props} onSecret={showSecret} />
      : current.view === "edit" ? <ClientForm {...props} id={current.id} onSecret={showSecret} />
      : current.view === "client" ? (secret?.id === current.id
        ? <SecretOnce secret={secret} onDone={() => { setSecret(null); navigate(clientPage(current.id)); }} />
        : <ClientDetail {...props} id={current.id} onSecret={showSecret} />)
      : <ClientList {...props} />;
  }

  return <Navigate.Provider value={navigate}>
    <div className="page">
      <header className="topbar">
        <div className="topbar-inner wide">
          <Brand host={false} />
          <nav aria-label={t("account.nav.label")}>
            <a href="/account">{t("account.nav.account")}</a>
            <a href="/console" aria-current="page">{t("account.nav.console")}</a>
          </nav>
          {user && <div className="topbar-user">
            <span>{name}</span>
            <button type="button" className="secondary small" onClick={() => manager.signoutRedirect()}>{t("common.signOut")}</button>
          </div>}
        </div>
      </header>
      <div className="console">
        {user && <nav className="console-nav" aria-label={t("admin.sections")}>
          <Link to="/console" current={section === "clients"}>{t("admin.nav.clients")}</Link>
          <Link to="/console/users" current={section === "users"}>{t("admin.nav.users")}</Link>
        </nav>}
        <main className="console-main">
          {error && <>
            <Alert>{t(`admin.error.${error}`)}</Alert>
            <button type="button" className="primary" onClick={() => signIn(path)}>{t("admin.signInAgain")}</button>
          </>}
          {!error && !user && <p className="hint" role="status">{t("admin.redirecting")}</p>}
          {view}
        </main>
      </div>
    </div>
  </Navigate.Provider>;
}
