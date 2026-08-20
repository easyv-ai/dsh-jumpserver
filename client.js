// dsh-jumpserver 浏览器设置卡片。
// AccessKeyID / AccessKeySecret 走 DSH 凭证库的 loopback same-origin RPC：仅写不读，
// describe 只返回 configured 布尔，客户端永远不会读回明文，故以星号占位。
// baseUrl / orgId 不是敏感信息，存 settings namespace（jumpserver）：settings.describe 对
// 非 secret 字段返回明文 value，因此保存后可直接回显核对。
window.__ModuleLoader__.load({
  id: "dsh-jumpserver",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
    let react_jsx_runtime = require("react/jsx-runtime");
    let react = require("react");

    const AK_REF = "JUMPSERVER_ACCESS_KEY_ID";
    const SK_REF = "JUMPSERVER_ACCESS_KEY_SECRET";
    const SETTINGS_NS = "jumpserver";
    // 仅用于视觉提示的占位符，永远不会写入凭证库。
    const MASK = "*".repeat(28);
    const inject = ["slots", "connection"];

    const STRINGS = {
      zh: {
        title: "JumpServer 资产查询",
        desc: "通过对话查询 JumpServer 资产。AccessKey 仅保存在本地，永远不会被显示。",
        akLabel: "AccessKeyID",
        skLabel: "AccessKeySecret",
        configured: "已配置",
        notConfigured: "未配置",
        akPlaceholder: "留空则保留当前值；输入新 AccessKeyID 以替换",
        skPlaceholder: "留空则保留当前值；输入新 AccessKeySecret 以替换",
        hintConfigured: "已配置。星号只是占位符，并非存储的值。",
        hintEmpty: "存储在本地 DSH 凭证库中，凭证值永远不会被读回。",
        removeAk: "移除 AccessKeyID",
        removeSk: "移除 AccessKeySecret",
        urlPlaceholderConfigured: "输入新 URL 以替换",
        urlPlaceholderEmpty: "https://jumpserver.example.com",
        urlHint: "支持 HTTP 与 HTTPS。URL 保存在设置中，保存后会在此显示以便核对。",
        removeUrl: "移除 URL",
        orgLabel: "组织 ID（可选）",
        orgPlaceholder: "留空则不发送 X-JMS-ORG",
        orgHint: "对应 JumpServer 的组织 ID，多组织部署时可填写。",
        saving: "保存中…",
        save: "保存",
        saved: "已保存。新会话将使用更新后的配置。",
        invalidUrl: "JumpServer URL 必须是不含凭证、查询参数或片段的绝对 HTTP(S) 地址。",
        confirmRemoveAk: "确定要移除已存储的 AccessKeyID 吗？",
        confirmRemoveSk: "确定要移除已存储的 AccessKeySecret 吗？",
        confirmRemoveUrl: "确定要移除已存储的 JumpServer URL 吗？"
      },
      en: {
        title: "JumpServer asset lookup",
        desc: "Query JumpServer assets through conversation. The AccessKey is stored locally and never displayed.",
        akLabel: "AccessKeyID",
        skLabel: "AccessKeySecret",
        configured: "Configured",
        notConfigured: "Not configured",
        akPlaceholder: "Leave blank to keep the current value; enter a new AccessKeyID to replace it",
        skPlaceholder: "Leave blank to keep the current value; enter a new AccessKeySecret to replace it",
        hintConfigured: "Configured. The stars are a placeholder, not the stored value.",
        hintEmpty: "Stored in the local DSH credential store; the value is never read back.",
        removeAk: "Remove AccessKeyID",
        removeSk: "Remove AccessKeySecret",
        urlPlaceholderConfigured: "Enter a new URL to replace it",
        urlPlaceholderEmpty: "https://jumpserver.example.com",
        urlHint: "HTTP and HTTPS are both supported. The URL is stored in settings and shown here after saving.",
        removeUrl: "Remove URL",
        orgLabel: "Organization ID (optional)",
        orgPlaceholder: "Leave blank to omit X-JMS-ORG",
        orgHint: "JumpServer organization ID, useful for multi-org deployments.",
        saving: "Saving…",
        save: "Save",
        saved: "Saved. New conversations will use the updated configuration.",
        invalidUrl: "JumpServer URL must be an absolute HTTP(S) URL without credentials, query, or fragment.",
        confirmRemoveAk: "Remove the stored AccessKeyID?",
        confirmRemoveSk: "Remove the stored AccessKeySecret?",
        confirmRemoveUrl: "Remove the stored JumpServer URL?"
      }
    };

    // 非浏览器环境（如测试沙箱）中没有 navigator，回退为英文。
    function detectLanguage() {
      try {
        if (typeof navigator !== "undefined" && String(navigator.language || "").toLowerCase().startsWith("zh")) return "zh";
      } catch { /* 忽略，走默认。 */ }
      return "en";
    }

    const S = {
      // 折叠卡片外壳对齐官方 PluginCard（ui-settings-plugins 包）的观感：
      // 收起时用 bg-layer-3，展开后切换到 bg-layer-2。
      card: { border: "1px solid var(--dsw-alias-border-l2)", borderRadius: "12px", background: "var(--dsw-alias-bg-layer-3)", marginBottom: "12px" },
      cardOpen: { background: "var(--dsw-alias-bg-layer-2)" },
      header: { display: "flex", alignItems: "center", gap: "12px", width: "100%", padding: "16px", margin: 0, background: "none", border: "none", cursor: "pointer", textAlign: "left", font: "inherit", color: "inherit" },
      headerText: { display: "flex", flexDirection: "column", gap: "4px", flex: "1 1 auto", minWidth: 0 },
      chevron: { flexShrink: 0, display: "inline-flex", transition: "transform .16s", color: "var(--dsw-alias-label-tertiary)" },
      body: { borderTop: "1px solid var(--dsw-alias-border-l2)", margin: "0 16px", padding: "16px 0", display: "flex", flexDirection: "column", gap: "12px" },
      title: { margin: 0, fontSize: "15px", fontWeight: 600, color: "var(--dsw-alias-label-primary)" },
      desc: { margin: 0, fontSize: "13px", color: "var(--dsw-alias-label-secondary)" },
      row: { display: "flex", flexDirection: "column", gap: "6px" },
      head: { display: "flex", alignItems: "center", gap: "8px" },
      label: { fontSize: "13px", fontWeight: 500, color: "var(--dsw-alias-label-primary)" },
      inputRow: { display: "flex", alignItems: "center", gap: "8px" },
      input: { border: "1px solid var(--dsw-alias-border-l2)", background: "var(--dsw-alias-bg-layer-3)", height: "34px", color: "var(--dsw-alias-label-primary)", borderRadius: "8px", padding: "0 12px", fontSize: "13px", flex: "1 1 auto", minWidth: 0 },
      hint: { margin: 0, fontSize: "12px", color: "var(--dsw-alias-label-tertiary)" },
      badge: { whiteSpace: "nowrap", borderRadius: "999px", padding: "1px 8px", fontSize: "11px", fontWeight: 500, background: "var(--dsw-alias-bg-module-platform)", color: "var(--dsw-alias-label-secondary)", display: "inline-block" },
      badgeOk: { color: "#2f9e44" },
      footer: { display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" },
      button: { border: "1px solid var(--dsw-alias-border-l2)", background: "var(--dsw-alias-bg-layer-3)", color: "var(--dsw-alias-label-primary)", borderRadius: "8px", height: "32px", padding: "0 14px", fontSize: "13px", cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0 },
      msg: { margin: 0, fontSize: "12px", color: "var(--dsw-alias-label-secondary)" },
      err: { margin: 0, fontSize: "12px", color: "var(--dsw-alias-label-error)" }
    };

    function JumpServerCard(props) {
      const face = props.jumpserverCard;
      const [status, setStatus] = react.useState({ loaded: false, ak: false, sk: false, base: false });
      const [akDraft, setAkDraft] = react.useState("");
      const [skDraft, setSkDraft] = react.useState("");
      const [baseDraft, setBaseDraft] = react.useState("");
      const [orgDraft, setOrgDraft] = react.useState("");
      const [saving, setSaving] = react.useState(false);
      const [saved, setSaved] = react.useState(false);
      const [error, setError] = react.useState("");
      const [akFocus, setAkFocus] = react.useState(false);
      const [skFocus, setSkFocus] = react.useState(false);
      const [lang, setLang] = react.useState(detectLanguage);
      // 展开状态是卡片本地的阅读手势，Host 与设置页都不参与（同官方 PluginCard）。
      const [open, setOpen] = react.useState(false);
      const T = STRINGS[lang] ?? STRINGS.en;

      // 已配置时显示虚假掩码；聚焦后展示空白的替换草稿。
      const akValue = status.ak && !akFocus && akDraft === "" ? MASK : akDraft;
      const skValue = status.sk && !skFocus && skDraft === "" ? MASK : skDraft;

      react.useEffect(() => {
        let alive = true;
        face.describe().then((r) => {
          if (!alive) return;
          setStatus({ loaded: true, ak: r.akConfigured, sk: r.skConfigured, base: r.baseConfigured });
          // URL/orgId 存 settings namespace（非 secret），describe 直接返回明文，可靠回显。
          if (r.baseUrl) setBaseDraft(r.baseUrl);
          if (r.orgId) setOrgDraft(r.orgId);
        }).catch(() => {});
        return () => { alive = false; };
      }, [face]);

      // GUI 自身的语言偏好（locale 命名空间）优先于浏览器语言。
      react.useEffect(() => {
        let alive = true;
        face.localePreference().then((p) => {
          if (alive && (p === "zh" || p === "en")) setLang(p);
        }).catch(() => {});
        return () => { alive = false; };
      }, [face]);

      async function onSave() {
        setSaving(true);
        setSaved(false);
        setError("");
        try {
          const ak = akDraft.trim();
          const sk = skDraft.trim();
          const b = baseDraft.trim();
          const org = orgDraft.trim();
          if (ak !== "") await face.setAk(ak);
          if (sk !== "") await face.setSk(sk);
          if (b !== "") {
            const url = new URL(b);
            if (!["https:", "http:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
              throw new Error(T.invalidUrl);
            }
            await face.setBaseUrl(b);
          }
          await face.setOrgId(org);
          const r = await face.describe();
          setStatus({ loaded: true, ak: r.akConfigured, sk: r.skConfigured, base: r.baseConfigured });
          setAkDraft("");
          setSkDraft("");
          setAkFocus(false);
          setSkFocus(false);
          setBaseDraft(b !== "" ? b : (r.baseConfigured ? r.baseUrl : ""));
          setOrgDraft(r.orgId || "");
          setSaved(true);
        } catch (e) {
          setError(String(e?.message ?? e));
        } finally {
          setSaving(false);
        }
      }

      async function onClear(kind) {
        const message = kind === "ak" ? T.confirmRemoveAk : kind === "sk" ? T.confirmRemoveSk : T.confirmRemoveUrl;
        if (!window.confirm(message)) return;
        setSaving(true);
        setSaved(false);
        setError("");
        try {
          // AK/SK 走凭证库；base URL 走 settings namespace，移除路径不同。
          if (kind === "ak") await face.unsetAk();
          else if (kind === "sk") await face.unsetSk();
          else await face.unsetBaseUrl();
          const r = await face.describe();
          setStatus({ loaded: true, ak: r.akConfigured, sk: r.skConfigured, base: r.baseConfigured });
          if (kind === "ak") { setAkDraft(""); setAkFocus(false); }
          if (kind === "sk") { setSkDraft(""); setSkFocus(false); }
          if (kind === "base") setBaseDraft("");
          setSaved(true);
        } catch (e) {
          setError(String(e?.message ?? e));
        } finally {
          setSaving(false);
        }
      }

      return (0, react_jsx_runtime.jsxs)("section", { style: open ? { ...S.card, ...S.cardOpen } : S.card, children: [
        (0, react_jsx_runtime.jsxs)("button", { type: "button", style: S.header, "aria-expanded": open, onClick: () => setOpen(!open), children: [
          (0, react_jsx_runtime.jsxs)("span", { style: S.headerText, children: [
            (0, react_jsx_runtime.jsx)("span", { style: S.title, children: T.title }),
            (0, react_jsx_runtime.jsx)("span", { style: S.desc, children: T.desc })
          ] }),
          (0, react_jsx_runtime.jsx)("svg", { width: 14, height: 14, viewBox: "0 0 14 14", fill: "none", "aria-hidden": "true", style: { ...S.chevron, transform: open ? "rotate(180deg)" : "none" }, children:
            (0, react_jsx_runtime.jsx)("path", { d: "M3.5 5.25 7 8.75 10.5 5.25", stroke: "currentColor", strokeWidth: 1.4, strokeLinecap: "round", strokeLinejoin: "round" })
          })
        ] }),
        open ? (0, react_jsx_runtime.jsxs)("div", { style: S.body, children: [
          (0, react_jsx_runtime.jsxs)("div", { style: S.row, children: [
            (0, react_jsx_runtime.jsxs)("div", { style: S.head, children: [
              (0, react_jsx_runtime.jsx)("label", { style: S.label, children: T.akLabel }),
              status.loaded ? (0, react_jsx_runtime.jsx)("span", { style: { ...S.badge, ...(status.ak ? S.badgeOk : {}) }, children: status.ak ? T.configured : T.notConfigured }) : null
            ] }),
            (0, react_jsx_runtime.jsxs)("div", { style: S.inputRow, children: [
              (0, react_jsx_runtime.jsx)("input", { type: "password", style: S.input, placeholder: T.akPlaceholder, value: akValue, onFocus: () => setAkFocus(true), onBlur: () => { if (akDraft === "") setAkFocus(false); }, onChange: (e) => {
                let v = e.target.value;
                if (v.startsWith(MASK)) v = v.slice(MASK.length);
                setAkDraft(v);
              } }),
              status.ak ? (0, react_jsx_runtime.jsx)("button", { style: S.button, disabled: saving, onClick: () => onClear("ak"), children: T.removeAk }) : null
            ] }),
            (0, react_jsx_runtime.jsx)("p", { style: S.hint, children: status.ak ? T.hintConfigured : T.hintEmpty })
          ] }),
          (0, react_jsx_runtime.jsxs)("div", { style: S.row, children: [
            (0, react_jsx_runtime.jsxs)("div", { style: S.head, children: [
              (0, react_jsx_runtime.jsx)("label", { style: S.label, children: T.skLabel }),
              status.loaded ? (0, react_jsx_runtime.jsx)("span", { style: { ...S.badge, ...(status.sk ? S.badgeOk : {}) }, children: status.sk ? T.configured : T.notConfigured }) : null
            ] }),
            (0, react_jsx_runtime.jsxs)("div", { style: S.inputRow, children: [
              (0, react_jsx_runtime.jsx)("input", { type: "password", style: S.input, placeholder: T.skPlaceholder, value: skValue, onFocus: () => setSkFocus(true), onBlur: () => { if (skDraft === "") setSkFocus(false); }, onChange: (e) => {
                let v = e.target.value;
                if (v.startsWith(MASK)) v = v.slice(MASK.length);
                setSkDraft(v);
              } }),
              status.sk ? (0, react_jsx_runtime.jsx)("button", { style: S.button, disabled: saving, onClick: () => onClear("sk"), children: T.removeSk }) : null
            ] }),
            (0, react_jsx_runtime.jsx)("p", { style: S.hint, children: status.sk ? T.hintConfigured : T.hintEmpty })
          ] }),
          (0, react_jsx_runtime.jsxs)("div", { style: S.row, children: [
            (0, react_jsx_runtime.jsxs)("div", { style: S.head, children: [
              (0, react_jsx_runtime.jsx)("label", { style: S.label, children: "JumpServer URL" }),
              status.loaded ? (0, react_jsx_runtime.jsx)("span", { style: { ...S.badge, ...(status.base ? S.badgeOk : {}) }, children: status.base ? T.configured : T.notConfigured }) : null
            ] }),
            (0, react_jsx_runtime.jsxs)("div", { style: S.inputRow, children: [
              (0, react_jsx_runtime.jsx)("input", { type: "url", style: S.input, placeholder: status.base ? T.urlPlaceholderConfigured : T.urlPlaceholderEmpty, value: baseDraft, onChange: (e) => setBaseDraft(e.target.value) }),
              status.base ? (0, react_jsx_runtime.jsx)("button", { style: S.button, disabled: saving, onClick: () => onClear("base"), children: T.removeUrl }) : null
            ] }),
            (0, react_jsx_runtime.jsx)("p", { style: S.hint, children: T.urlHint })
          ] }),
          (0, react_jsx_runtime.jsxs)("div", { style: S.row, children: [
            (0, react_jsx_runtime.jsxs)("div", { style: S.head, children: [
              (0, react_jsx_runtime.jsx)("label", { style: S.label, children: T.orgLabel })
            ] }),
            (0, react_jsx_runtime.jsx)("div", { style: S.inputRow, children:
              (0, react_jsx_runtime.jsx)("input", { type: "text", style: S.input, placeholder: T.orgPlaceholder, value: orgDraft, onChange: (e) => setOrgDraft(e.target.value) })
            }),
            (0, react_jsx_runtime.jsx)("p", { style: S.hint, children: T.orgHint })
          ] }),
          (0, react_jsx_runtime.jsxs)("div", { style: S.footer, children: [
            (0, react_jsx_runtime.jsx)("button", { style: S.button, disabled: saving, onClick: onSave, children: saving ? T.saving : T.save }),
            saved ? (0, react_jsx_runtime.jsx)("p", { style: S.msg, children: T.saved }) : null,
            error ? (0, react_jsx_runtime.jsx)("p", { style: S.err, children: error }) : null
          ] })
        ] }) : null
      ] });
    }

    function apply(ctx) {
      const { api } = ctx.get("connection");
      const face = {
        describe: async () => {
          // AK/SK 走凭证库（只返回 configured）；URL/orgId 走 settings namespace（非 secret，返回明文）。
          const [credRes, setRes] = await Promise.all([
            api.credentials.describe({ refs: [AK_REF, SK_REF] }),
            api.settings?.describe ? api.settings.describe({}) : Promise.resolve(null),
          ]);
          const creds = credRes?.result?.value?.credentials ?? {};
          const jsNs = (setRes?.result?.value?.namespaces ?? []).find((n) => n?.ns === SETTINGS_NS);
          const baseUrl = typeof jsNs?.value?.baseUrl === "string" ? jsNs.value.baseUrl : "";
          const orgId = typeof jsNs?.value?.orgId === "string" ? jsNs.value.orgId : "";
          return {
            akConfigured: creds[AK_REF]?.configured ?? false,
            skConfigured: creds[SK_REF]?.configured ?? false,
            baseConfigured: Boolean(baseUrl),
            baseUrl,
            orgId,
          };
        },
        setAk: (value) => api.credentials.set({ ref: AK_REF, value }),
        setSk: (value) => api.credentials.set({ ref: SK_REF, value }),
        // URL/orgId 存 settings namespace：update 做 deep-merge，不动其它字段。
        setBaseUrl: (value) => api.settings.update({ ns: SETTINGS_NS, patch: { baseUrl: value } }),
        setOrgId: (value) => api.settings.update({ ns: SETTINGS_NS, patch: { orgId: value } }),
        // AK/SK 移除走凭证库。
        unsetAk: () => api.credentials.unset({ ref: AK_REF }),
        unsetSk: () => api.credentials.unset({ ref: SK_REF }),
        // URL 移除走 settings.mutate：浏览器只持有 redacted 视图，
        // replace wholesale 会误删 schema 里其它已存字段，故用单字段 op。
        unsetBaseUrl: () => api.settings.mutate({ ns: SETTINGS_NS, ops: [{ op: "unset", path: ["baseUrl"] }] }),
        // 读取 GUI 的语言偏好（locale 命名空间的 preference 字段）；不可用时返回空串。
        localePreference: async () => {
          if (!api.settings?.describe) return "";
          const res = await api.settings.describe({});
          const namespaces = res?.result?.value?.namespaces ?? [];
          const locale = namespaces.find((n) => n?.ns === "locale");
          const pref = locale?.value?.preference;
          return typeof pref === "string" ? pref : "";
        }
      };

      ctx.slots.inject("settings.plugin.item", () => ctx.slots.register({
        // keyed slot：设置页按 Host 端 settings namespace（见 index.js 的
        // SETTINGS_NAMESPACE）派发卡片，没有 key 的注册永远不会被渲染。
        name: "settings.plugin.item",
        key: "jumpserver",
        inject: () => ({ jumpserverCard: face })
      }, JumpServerCard));
    }

    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  }
});
