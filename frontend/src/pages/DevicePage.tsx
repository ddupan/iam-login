import { Alert, Brand, Single } from "../components/Chrome";
import type { DeviceContext } from "../page-context";

/** The device grant's verification page: the code a device shows, then the outcome. */
export function DevicePage({ context }: { context: DeviceContext }) {
  const { device } = context;
  const top = <div className="brand-row"><Brand host={false} /><span className="lead">{device.username}</span></div>;
  if (device.result === "done" || device.result === "denied") {
    return (
      <Single top={top}>
        <div className="lead-block">
          <h1>{device.result === "done" ? "设备已连接" : "已拒绝"}</h1>
          <p className="lead">{device.result === "done" ? "回到设备上继续。" : "设备没有获得访问权限。"}</p>
        </div>
      </Single>
    );
  }
  return (
    <Single top={top}>
      <div className="lead-block"><h1>连接设备</h1></div>
      {device.result === "invalid" && <Alert>代码无效或已过期。</Alert>}
      {/* GET: the framework's verification endpoint takes the code as a query parameter, without CSRF. */}
      <form method="get" action={context.action}>
        <div className="field">
          <label htmlFor="user_code">设备上显示的代码</label>
          <input id="user_code" name="user_code" required autoFocus autoComplete="off" spellCheck={false}
            maxLength={20} className="mono" defaultValue={device.userCode}
            aria-invalid={device.result === "invalid" ? true : undefined} />
        </div>
        <button className="primary" type="submit">继续</button>
      </form>
    </Single>
  );
}
