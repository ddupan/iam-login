export type CsrfToken = { name: string; value: string; headerName: string };

type PageBase = {
  name: string;
  error: string;
  action: string;
  csrf: CsrfToken;
  logoutAction?: string;
};

export type SignInContext = PageBase & (
  | { step: "password" }
  | { step: "logout"; binding: string }
  | { step: "authorize"; binding: string; client: string; scopes: string[] }
  | {
      step: "mfa-pending" | "mfa-complete";
      passkey: "unavailable" | "register" | "authenticate";
      identity: {
        username: string;
        subjectId: string;
        email: string;
        groups: string[];
        groupDns: string[];
      };
    }
);

export function readPageContext(): SignInContext {
  const data = document.getElementById("login-context")?.textContent;
  if (!data) throw new Error("Missing login page context");
  const context: SignInContext = JSON.parse(data);
  if (context.step !== "logout" && context.step !== "authorize" && context.step !== "password" && context.step !== "mfa-pending" && context.step !== "mfa-complete") {
    throw new Error("Unknown login step");
  }
  return context;
}
