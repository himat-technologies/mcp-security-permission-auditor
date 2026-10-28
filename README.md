<div align="center">

# 🛡️ MCP Security & Permission Auditor

### Inspect. Evaluate. Harden.

**A local-first security review workspace for Model Context Protocol configurations.**

[![Live Demo](https://img.shields.io/badge/LIVE_DEMO-Open_Auditor-7A2335?style=for-the-badge)](https://himat.tech/free-tools/mcp-security-permission-auditor)
[![Repository](https://img.shields.io/badge/GITHUB-Repository-292524?style=for-the-badge&logo=github)](https://github.com/himat-technologies/mcp-security-permission-auditor)
![Local analysis](https://img.shields.io/badge/PRIVACY-Local_Analysis-47634D?style=for-the-badge)

**Review risky permissions, identify exposed credentials, and prioritize configuration hardening—with no command execution.**

[Live Demo](https://himat.tech/free-tools/mcp-security-permission-auditor) · [Website](https://himat.co.in) · [Contact](mailto:info@himat.co.in)

</div>

---

## ✨ Features

- **MCP JSON editor** — edit, paste, upload, clear, and download configurations. JSON file uploads are limited to 1 MB.
- **Vulnerability presets** — root filesystem access, shell risk, synthetic credential exposure, wildcard approvals, and a hardened example.
- **Static security checks** — broad filesystem paths, parent-directory traversal, risky command strings, wildcard permissions, credential-like values, missing schema constraints, and malformed server definitions.
- **Risk score** — deterministic score from 0–100 with severity counts and an explanation of its heuristic nature.
- **Findings review** — rule IDs, affected paths, evidence, severity, confidence, and remediation guidance.
- **Conservative remediation workflow** — highlights manual-review items rather than silently guessing permission replacements; offers a secret-placeholder helper.
- **Exports** — JSON report, Markdown report, and current configuration download.
- **Privacy-first design** — analysis runs in browser memory; no backend, API key, telemetry, or command execution is required by this app.
- **Responsive dashboard** — cream/off-white canvas, charcoal typography, burgundy and muted neutral accents.

## 🖥️ Screenshots

Capture screenshots from the running app and place them in `docs/screenshots/` if you want to include them here.

| Dashboard | Findings and remediation |
|---|---|
| `docs/screenshots/dashboard.png` (add screenshot) | `docs/screenshots/findings.png` (add screenshot) |

## 🧰 Technology stack

- React + Vite
- TypeScript
- Tailwind CSS utilities and custom responsive styling
- Lucide React icons
- Vitest

## 📋 Prerequisites

- Node.js 20 or newer (Node.js 22 LTS recommended)
- npm
- A modern browser

No paid service, API key, database, or backend server is required.

## ⚡ Run locally

```bash
npm install
npm run dev
```

Vite prints the local development URL in the terminal, usually `http://localhost:5173`.

### Build, test, and type-check

```bash
npm run typecheck
npm run test
npm run build
npm run preview
```

Exact commands are defined in `package.json`.

## 🧭 Example usage

1. Start the app and choose a preset, or paste your MCP JSON configuration.
2. Select **Analyze configuration**.
3. Review the score and severity counts, then expand each finding to see evidence and recommended action.
4. Open **Remediation** to inspect suggestions. Wildcard/path changes are flagged for manual review rather than automatically rewritten.
5. Export a JSON report, Markdown report, or the current editor configuration.
6. Validate and test any modified configuration in a controlled development environment before deployment.

## 📂 Configuration formats

The scanner accepts JSON text and checks common structures such as `mcpServers` and `servers`. It can inspect values from files such as `mcp.json`, `.cursor/mcp.json`, or `.claude.json` when their contents are JSON. Client-specific extensions and non-JSON formats are not guaranteed to be understood.

## 🧪 Security methodology

The scanner parses input as JSON and inspects the resulting data structure. It **never launches MCP servers or executes command strings**. Current rule families include:

| Rule family | Examples |
|---|---|
| Filesystem | Root-level paths, parent-directory traversal |
| Command patterns | Destructive command strings, download-to-interpreter patterns |
| Secrets | Common token patterns and credential-like property names |
| Permissions | Wildcard approvals and unusually broad permission lists |
| Schemas | Object schemas without required fields; unbounded string/array parameters |
| Configuration | Missing or malformed common server definitions |

### Score bands

| Score | Classification |
|---:|---|
| 90–100 | Low Risk |
| 70–89 | Moderate Risk |
| 40–69 | High Risk |
| 0–39 | Critical Risk |

Scoring starts at 100 and deducts points per unique finding: Critical 35, High 22, Medium 12, Low 5. The score is clamped to 0–100. These weights are prioritization heuristics, not a formal risk model.

## 🔒 Privacy guarantees and safe use

- The application does not send the configuration to a backend or external analysis API.
- It does not store the configuration in localStorage.
- It does not run shell commands, start MCP servers, contact configured hosts, or connect to databases.
- Common detected token patterns and credential-like values are redacted in report evidence.
- Uploaded JSON files are checked by extension/MIME type and size.

**Review sensitive data before sharing exports.** Static redaction is not infallible, and a report may contain configuration details unrelated to recognized secret patterns. If a real secret was exposed, revoke or rotate it; replacing its value in a file does not invalidate the credential.

## ⚠️ Known limitations

- Rule-based analysis can produce false positives and false negatives.
- No findings does not prove that a configuration or MCP server is secure.
- The tool cannot inspect runtime behavior, supply-chain provenance, server-side authorization, or every client-specific setting.
- Remediation is intentionally conservative. Ambiguous changes need a human decision.
- This is a developer aid, not a substitute for a professional security review.

## 🗺️ Future improvements

- Broader client-specific schemas and rule coverage
- Rule fixtures for false-positive regression testing
- Detailed before/after diffs for safe remediation proposals
- Additional export formats and configurable rule severity
- Reproducible security test corpus

## 🤝 Contributing

Please include a clear reproduction and expected behavior when opening an issue or pull request. Use synthetic configurations and never commit real tokens, credentials, private keys, or customer data.

## 📄 License

No license has been selected in this repository. Until a `LICENSE` file is added, do not assume that reuse, redistribution, or modification is permitted. Add the intended license before publishing reuse terms.

---

<div align="center">

## 🧡 Built by Himat Technologies

**Build systems, not just websites.**

| Channel | Link |
|---|---|
| 🌐 Website | [himat.co.in](https://himat.co.in) |
| 💻 GitHub repository | [himat-technologies/mcp-security-permission-auditor](https://github.com/himat-technologies/mcp-security-permission-auditor) |
| 🚀 Live demo | [MCP Security & Permission Auditor](https://himat.tech/free-tools/mcp-security-permission-auditor) |
| 📘 Facebook | [Himat Technologies](https://www.facebook.com/people/Himat-technologies/61593829197445/) |
| 💼 LinkedIn | [Himat Technologies](https://www.linkedin.com/in/himat-technologies-14b1051b4) |
| 📸 Instagram | [@himat_technologies](https://www.instagram.com/himat_technologies?stkn=djdmcGxweWtwYWI0) |
| ✉️ Email | [info@himat.co.in](mailto:info@himat.co.in) |
| ☎️ Call / WhatsApp | [+91 94452 34023](https://wa.me/919445234023) |

</div>
