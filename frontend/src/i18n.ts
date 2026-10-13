import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import zhCN from "./locales/zh-CN.json";

// Adding a language = a file under locales/ plus an entry here; the first entry is the fallback.
export const resources = { "zh-CN": { translation: zhCN } } as const;
type Language = keyof typeof resources;

declare module "i18next" {
  // Keys are checked against the fallback catalogue, so a missing or misspelt key fails `tsc`.
  interface CustomTypeOptions { resources: (typeof resources)["zh-CN"] }
}

/** The browser's first preferred language we have, by exact tag, then by primary subtag (zh-TW → zh-CN). */
function preferred(): Language {
  const supported = Object.keys(resources) as Language[];
  for (const tag of navigator.languages) {
    const exact = supported.find(lng => lng.toLowerCase() === tag.toLowerCase());
    if (exact) return exact;
    const primary = supported.find(lng => lng.split("-")[0] === tag.split("-")[0].toLowerCase());
    if (primary) return primary;
  }
  return supported[0];
}

const lng = preferred();
await i18next.use(initReactI18next).init({
  resources, lng, fallbackLng: "zh-CN",
  // React escapes; escaping here as well would show entities.
  interpolation: { escapeValue: false },
});
document.documentElement.lang = lng;
document.title = i18next.t("title");
