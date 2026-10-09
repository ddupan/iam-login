export type CsrfToken = { name: string; value: string; headerName: string };

type PageBase = {
  name: string;
  error: string;
  action: string;
  csrf: CsrfToken;
};

export type SignInContext = PageBase & { app: string } & (
  | { step: "password" }
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

export type ConsentContext = PageBase & {
  step: "consent";
  consent: {
    clientId: string;
    clientName: string;
    state: string;
    scopes: string[];
    previouslyGranted: string[];
    returnHosts: string[];
    username: string;
    email: string;
    groups: string[];
  };
};

export type AdminContext = { step: "admin"; authority: string; clientId: string };

export type PageContext = SignInContext | ConsentContext | AdminContext;

const STEPS = ["admin", "password", "mfa-pending", "mfa-complete", "consent"];

export function readPageContext(): PageContext {
  const data = document.getElementById("login-context")?.textContent;
  if (!data) throw new Error("Missing login page context");
  const context: PageContext = JSON.parse(data);
  if (!STEPS.includes(context.step)) throw new Error("Unknown login step");
  return context;
}
