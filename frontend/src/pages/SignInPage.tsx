import { Passkey } from "../components/Passkey";
import { SubmitForm } from "../components/SubmitForm";
import type { SignInContext } from "../page-context";

export function SignInPage({ context }: { context: SignInContext }) {
  if (context.step === "logout") return <main><section className="card">
    <h1>退出统一登录</h1>
    <p>将结束本次登录，并通知支持统一注销的应用。</p>
    <SubmitForm action={context.action} csrf={context.csrf} label="确认退出">
      <input type="hidden" name="binding" value={context.binding} />
    </SubmitForm>
  </section></main>;
  if (context.step === "authorize") return <main><section className="card">
    <h1>继续登录 {context.client}</h1>
    <p>{context.name}，密码与 passkey 已验证。</p>
    <p>本次向应用提供以下范围的信息：</p>
    <ul>{context.scopes.map(scope => <li key={scope}>{scope}</li>)}</ul>
    <SubmitForm action={context.action} csrf={context.csrf} label="继续至应用">
      <input type="hidden" name="binding" value={context.binding} />
    </SubmitForm>
    <SubmitForm action="/signin/restart" csrf={context.csrf} label="取消并退出" />
  </section></main>;
  return (
    <main>
      <header><a href="/signin" className="brand">i<span>am</span></a></header>
      <section className="card" aria-labelledby="title">
        <div className="eyebrow">AD 登录验证</div>
        <h1 id="title">
          {context.step === "password" ? "登录你的账号" : context.step === "mfa-complete" ? "MFA 已验证" : "密码已验证，等待 MFA"}
        </h1>
        <p className="intro">
          {context.step === "password"
            ? "使用 AD 用户名或完整 UPN 登录。"
            : context.step === "mfa-complete"
              ? `${context.name}，密码与 passkey 已验证。尚未向应用授权。`
              : context.passkey === "unavailable"
                ? `${context.name}，目录验证成功。第二因素尚未接入，本次没有完成登录或向应用授权。`
                : `${context.name}，请使用 passkey 完成第二因素验证。`}
        </p>
        {context.error && <p className="error" role="alert">{context.error}</p>}
        {context.step !== "password" && (
          <div className="directory-result">
            <dl>
              <dt>账号</dt><dd>{context.identity.username}</dd>
              <dt>目录标识</dt><dd>{context.identity.subjectId}</dd>
              <dt>邮箱</dt><dd>{context.identity.email || "未设置"}</dd>
            </dl>
            <h2>直接所属组</h2>
            {context.identity.groups.length
              ? <ul>{context.identity.groups.map(group => <li key={group}>{group}</li>)}</ul>
              : <p>没有直接所属组。</p>}
            <details>
              <summary>组 DN</summary>
              <ul>{context.identity.groupDns.map(dn => <li key={dn}>{dn}</li>)}</ul>
            </details>
            <p>当前仅读取 memberOf，不展开嵌套组，也不包含主组。</p>
          </div>
        )}
        {context.step === "mfa-pending" && context.passkey !== "unavailable" &&
          <Passkey csrf={context.csrf} initial={context.passkey} />}
        <SubmitForm action={context.action} csrf={context.csrf}
          label={context.step === "password" ? "继续" : "退出并重新验证"}>
          {context.step === "password" && <>
            <label>用户名
              <input name="username" autoComplete="username" autoFocus required
                maxLength={256} defaultValue={context.name} />
            </label>
            <label>密码
              <input name="password" type="password" autoComplete="current-password"
                required maxLength={1024} />
            </label>
          </>}
        </SubmitForm>
        {context.step === "mfa-complete" && context.logoutAction &&
          <SubmitForm action={context.logoutAction} csrf={context.csrf} label="退出所有应用" />}
      </section>
      <footer>独立 IAM · AD 接入验证</footer>
    </main>
  );
}
