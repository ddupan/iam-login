import { SubmitForm } from "../components/SubmitForm";
import type { SignInContext } from "../page-context";

export function SignInPage({ context }: { context: SignInContext }) {
  return (
    <main>
      <header><a href="/signin" className="brand">i<span>am</span></a></header>
      <section className="card" aria-labelledby="title">
        <div className="eyebrow">AD 登录验证</div>
        <h1 id="title">
          {context.step === "password" ? "登录你的账号" : "密码已验证，等待 MFA"}
        </h1>
        <p className="intro">
          {context.step === "password"
            ? "使用 AD 用户名或完整 UPN 登录。"
            : `${context.name}，目录验证成功。第二因素尚未接入，本次没有完成登录或向应用授权。`}
        </p>
        {context.error && <p className="error" role="alert">{context.error}</p>}
        {context.step === "mfa-pending" && (
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
      </section>
      <footer>独立 IAM · AD 接入验证</footer>
    </main>
  );
}
