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
      step: "mfa-pending";
      /** "choose": nothing set up yet; otherwise the method to verify with. */
      factor: "unavailable" | "choose" | "passkey" | "totp";
      /** The other method is set up too, so the page offers to switch. */
      other: boolean;
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
    /** Present for the device grant: the decision goes to the device verification endpoint. */
    userCode?: string;
  };
};

export type DeviceContext = PageBase & {
  step: "device";
  device: {
    username: string;
    userCode: string;
    result: "" | "done" | "invalid" | "denied";
  };
};

export type TotpSetupContext = PageBase & {
  step: "totp-setup";
  totp: { uri: string; secret: string; account: string; issuer: string };
  back: string;
};

export type AdminContext = { step: "admin"; authority: string; clientId: string };

export type ErrorContext = { step: "error"; status: number };

export type AccountContext = PageBase & {
  step: "account";
  profile: { username: string; displayName: string; email: string; directory: string; groups: string[] };
  /** Times are ISO instants, "" when unknown. */
  passkeys: { id: string; label: string; created: string; lastUsed: string }[];
  /** Empty when no authenticator app is set up. */
  authenticator: { created?: string; lastUsed?: string };
  apps: { clientId: string; name: string; scopes: string[]; lastIssued: string }[];
};

export type PageContext = SignInContext | TotpSetupContext | ConsentContext | DeviceContext | AdminContext | AccountContext
  | ErrorContext;

const STEPS = ["admin", "password", "mfa-pending", "totp-setup", "consent", "device", "account", "error"];

export function readPageContext(): PageContext {
  const data = document.getElementById("login-context")?.textContent;
  if (!data) throw new Error("Missing login page context");
  const context: PageContext = JSON.parse(data);
  if (!STEPS.includes(context.step)) throw new Error("Unknown login step");
  return context;
}
