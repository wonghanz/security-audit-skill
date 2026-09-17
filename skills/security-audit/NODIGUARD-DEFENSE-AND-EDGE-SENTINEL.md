# NodiGuard AI Defense and Edge Sentinel Hunting

#### When to use this file

Reach for this file when reviewing systems that integrate AI pair-programming agents (Cursor, Windsurf, Claude Code, Continue, autonomous coding agents), edge CDNs or reverse proxies (Cloudflare, Fastly, AWS CloudFront, Nginx ingress), credential lifecycle vaults, local LLM execution runtimes (Ollama, vLLM), or systems executing tool commands on host machines. This domain evaluates whether the application prevents credential leaks during vibe-coding, protects cloud-edge rulesets against unauthorized redirect hijacking, neutralizes steganographic prompt injections, gates destructive shell actions, and bounds workstation resource exhaustion.

Use alongside `AI-AND-LLM.md` for conversational/RAG model logic, `CLOUD-AND-DEPLOYMENT.md` for cloud IAM/k8s, and `WEB-PROTOCOL-AND-AUTH.md` for standard web auth.

## Core discipline (include in every agent prompt for this domain)

```
- A plain secret reference or environment variable name is not a vulnerability. Require code that outputs, logs, hardcodes, or transmits plaintext credentials across a trust boundary without ephemeral scoping or client-side masking.
- Edge configuration and CDN rulesets are authoritative boundaries. Prove that unauthorized API access, leaked tokens, or unverified rule updates can mutate edge traffic routing (e.g., 301/302 redirects to unverified third parties).
- Distinguish intentional origin stealth defenses (e.g., Nginx HTTP 444 / Cloudflare 502 Bad Gateway blackhole drops) from true availability outages. Do not report intentional origin cloaking as an availability failure.
- A prompt injection alone is not a finding. Require a code-level boundary failure: steganographic evasion (zero-width characters, homoglyphs, direction overrides), privilege escalation, or reaching an unverified execution sink.
- Autonomous agent tools must enforce blast-radius constraints. Flag any destructive sink (recursive deletions, table/database drops, uncontained subprocess execution) that lacks deterministic boundary checks and human approval gates.
- Classify candidates as `confirmed` only with source evidence and bounded local checks. Use `needs_validation` when live CDN control planes or SaaS token scopes cannot be inspected from the repository.
```

## Anti-Vibe-Coding DLP and credential hygiene attack classes (subagent_type: `general`)

**Hardcoded secrets in AI prompts, codebases, or generated templates**
Developers or automated agents embed long-lived API keys (`sk-...`, `AKIA...`, `ghp_...`, Cloudflare API keys, database connection strings with plaintext passwords) directly into source code, sample scripts, or prompts transmitted to cloud LLMs. Verify whether credentials are hardcoded or loaded exclusively via environment variables (`os.environ.get(...)`) and `.env` files ignored by version control.

**Absence of ephemeral credential scoping**
Workloads and developer testing harnesses use long-lived, high-privilege credentials where short-lived tokens are required. Check whether testing suites request ephemeral, scoped credentials (e.g., 60-second TTL tokens via Hardware Security Modules or Vault) or store master credentials in plaintext on disk.

**Client-side zero-knowledge tokenization bypass**
Prompt assembly transmits internal network topology (RFC 1918 addresses `10.0.0.0/8`, `192.168.0.0/16`, internal hostnames), local filesystem paths (`C:\Users\...`, `/home/...`), or employee PII to third-party model inference APIs unmasked. Review whether the client-side proxy tokenizes sensitive identifiers in volatile RAM before network egress and reverses them locally upon model response.

## Edge CDN, Cloudflare ruleset, and routing integrity attack classes (subagent_type: `general`)

**Unauthorized edge ruleset mutation and 301/302 redirect hijacking**
Over-privileged or leaked edge SaaS credentials (such as Cloudflare API tokens or Global API Keys) can be leveraged to inject rogue Redirect Rules (e.g., HTTP 301/302 redirects) matching broad traffic (`All incoming requests` or specific subdomains) to external malicious destinations (such as Traffic Direction Systems, credential phishing sites, or ClickFix malware droppers). Review whether:
- SaaS API tokens are strictly scoped to least privilege (e.g., DNS-only or specific Zone Rulesets) rather than account-wide admin.
- Edge ruleset modifications require dual-authorization, IP whitelisting, or GitOps infrastructure-as-code sync.
- Continuous synthetic monitoring (hairpin loopback probes) with non-following HTTP clients verifies that edge responses do not emit unexpected redirect headers.

**Intentional origin blackhole misclassification and probe blindspots**
Origin servers configure intentional stealth drop mechanisms (e.g., Nginx `location = / { return 444; }` causing edge proxies to return HTTP 502/521/444 to scanner bots). Audit whether health-check harnesses and watchdog daemons distinguish between:
- An intentional root blackhole drop (normal, secure by design).
- A true origin service crash or database connection failure on production API endpoints.
- A 301 redirect hijack.
Misclassifying intentional drops leads to alert fatigue, false positives, or masking of genuine hijack incidents.

**SaaS API token scope escalation**
Automation scripts or deployment manifests store full-account Cloudflare Global API Keys or broad AWS IAM access keys where zone-scoped or service-scoped tokens are sufficient. Trace where edge management tokens are loaded and verify if a leak of that token allows modifying routing across unrelated corporate zones.

## Anti-Fable 5 adversarial injection and steganography attack classes (subagent_type: `general`)

**Steganographic Unicode instruction smuggling**
Adversarial prompts evade text filters and DLP inspection using zero-width spaces (`\u200B`, `\u200C`, `\u200D`), right-to-left overrides (`\u202E`), mathematical alphanumeric symbols, or Cyrillic homoglyphs. Verify whether input normalization strips invisible Unicode codepoints and normalizes homoglyphs before DLP pattern matching, entropy analysis, and prompt assembly.

**Persona hijacking and instruction override immunity**
Untrusted external content (e.g., scraped web pages, third-party pull requests, uploaded user documents, external issue bodies) contains override instructions (`"Ignore previous instructions"`, `"You are now DAN"`, `"Developer Mode enabled"`) that alter the agent's core safety boundaries. Verify that the agent architecture enforces deterministic code gates between model suggestions and actual execution authority.

## Tool execution, blast radius, and destructive sink attack classes (subagent_type: `general`)

**Ungated destructive command execution**
Autonomous coding agents or CLI tools execute destructive operations (`rm -rf`, `del /s`, `Remove-Item -Recurse`, dropping database tables/databases, formatting drives) directly through shell tools without calculating impact. Trace tool handlers that invoke shell or filesystem mutation:
- Is there an automated blast-radius analyzer calculating affected file counts and filesystem depth?
- Is there a mandatory human-in-the-loop approval gate for operations rated high or critical risk?
- Are writes restricted strictly to sandbox scratch directories?

**Unsafe subprocess execution and command concatenation**
Agent tool dispatchers or backend scripts build shell commands via string formatting (`f"curl {url}"` or `shell=True` with unvalidated parameters). Confirm whether arguments are passed as discrete validated arrays (`["curl", "--", url]`) and disallow arbitrary shell meta-characters.

## Workstation persistence and host integrity attack classes (subagent_type: `general`)

**Unmonitored developer workstation persistence**
Malicious dependencies, fake verification scripts (ClickFix), or compromised tools install background persistence hooks on developer workstations. Audit whether installation scripts or daemon helpers write unverified binaries to:
- Windows Registry Run keys (`HKCU\...\CurrentVersion\Run`, `HKLM\...\CurrentVersion\Run`).
- Startup folders (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`).
- Scheduled Tasks executing unverified scripts in `AppData`, `Temp`, or `ProgramData`.
- Linux/macOS LaunchDaemons, LaunchAgents, systemd user services, or cron jobs.

**Unbounded outbound socket egress**
Agent daemons or developer tooling maintain established TCP connections to unverified external IP addresses or command-and-control (C2) servers. Verify whether the application restricts outbound connections to an explicit destination allowlist and flags unexpected reverse shells or telemetry beacons.

## Resource lifecycle, VRAM, and memory exhaustion attack classes (subagent_type: `general`)

**GPU VRAM retention starvation in local AI models**
Local inference engines (Ollama, vLLM, llama.cpp) hold model weights in GPU VRAM indefinitely after request completion, starving host processes, graphics workloads, and subsequent tasks. Check whether the client proxy or orchestrator issues explicit eviction signals (`keep_alive: 0`) or manages VRAM retention lifecycles post-task.

**Working set memory bloat in background agent daemons**
Long-running AI agent sidecars or security proxies accumulate uncollected memory pages in resident working sets. Verify whether native memory compaction (e.g., Windows native `EmptyWorkingSet` via PSAPI, or `malloc_trim` on Linux) is triggered periodically to reclaim dormant working set pages.

## Universal moves (apply across the above)

- Map the entire lifecycle: Developer IDE / Agent Prompt ➔ Local Sidecar Proxy ➔ Central Security Gateway ➔ Cloud Inference / Local GPU ➔ Tool Execution Sink.
- Check edge ingress independently from origin security: an origin server may be secure while Cloudflare/CDN routing is hijacked due to a leaked SaaS token.
- Inspect both the prompt assembler and the tool execution dispatcher. Enforce deterministic safety gates on both sides of the model.

## Validation rules (apply before reporting ANY finding here)

1. For credential leakage claims, establish the source trace showing a plaintext secret, its lack of ephemeral scoping, and where it crosses an external boundary.
2. For edge ruleset hijacking claims, prove that an edge configuration or API token allows modifying redirects or routing without dual approval or IP restriction.
3. For intentional blackhole claims, verify whether the HTTP 444/502 response is an intentional server defense (e.g., Nginx dropped connection) or a true service failure. Do not flag intentional stealth behavior as a bug.
4. For destructive tool claims, identify the exact tool handler that executes file/database deletion without blast-radius analysis or an explicit confirmation gate.
5. For steganography claims, demonstrate that invisible Unicode characters bypass an upstream filter and alter downstream tool arguments or model intent.
6. Return `confirmed` only with complete source trace and bounded local reproduction. Use `needs_validation` when live CDN settings or cloud IAM scopes are outside the repository.
