import { Alert, Single, Steps } from "../components/Chrome";
import { Passkey } from "../components/Passkey";
import { SubmitForm } from "../components/SubmitForm";
import type { SignInContext } from "../page-context";

/** Leave this sign-in (POST /signin/restart) and start over with another account. */
function Restart({ context, label }: { context: SignInContext; label: string }) {
  return <SubmitForm action={context.action} csrf={context.csrf} label={label} className="link" />;
}

export function SignInPage({ context }: { context: SignInContext }) {
  if (context.step === "password") {
    return (
      <Single below={<span>忘记密码请联系管理员</span>}>
        <div className="lead-block">
          <h1>登录</h1>
          {context.app && <p className="lead">继续前往 <strong>{context.app}</strong>。</p>}
        </div>
        {context.error && <Alert kind={context.error.includes("暂时不可用") ? "warn" : "error"}>{context.error}</Alert>}
        <SubmitForm action={context.action} csrf={context.csrf} label="继续">
          <div className="field">
            <label htmlFor="username">用户名</label>
            <input id="username" name="username" autoComplete="username" autoFocus required maxLength={256}
              defaultValue={context.name} aria-invalid={context.error ? true : undefined} />
          </div>
          <div className="field">
            <label htmlFor="password">密码</label>
            <input id="password" name="password" type="password" autoComplete="current-password" required
              maxLength={1024} aria-invalid={context.error ? true : undefined} />
          </div>
        </SubmitForm>
      </Single>
    );
  }
  const who = context.identity.username;
  if (context.step === "mfa-pending") {
    return (
      <Single below={<><Restart context={context} label="换一个账号" /><span>丢失 passkey？请联系管理员</span></>}>
        <Steps current={2} />
        {context.app && context.passkey === "authenticate" && <p className="lead">继续前往 <strong>{context.app}</strong>。</p>}
        {context.passkey === "unavailable"
          ? <Alert>第二步验证暂不可用，请联系管理员。</Alert>
          : <Passkey csrf={context.csrf} initial={context.passkey} who={who} />}
      </Single>
    );
  }
  return (
    <Single>
      <div className="lead-block"><h1>已登录</h1></div>
      <div className="who"><span className="avatar" aria-hidden="true">{who.slice(0, 1).toUpperCase()}</span>
        <div><span>{who}</span><span>{context.identity.email || "未设置邮箱"}</span></div></div>
      {context.identity.groups.length > 0 && (
        <div className="chips" aria-label="所属组">{context.identity.groups.map(group => <span key={group} className="chip">{group}</span>)}</div>
      )}
      <SubmitForm action={context.action} csrf={context.csrf} label="退出" className="secondary" />
    </Single>
  );
}
