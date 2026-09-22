# R1 candidate origins and why each was probed

Added to `CANDIDATES` in `research/survey_directories.py` on 22 Sep 2026. Results:
`evidence/directory_survey.json` (curated list) and `evidence/signed_agents_survey.json`
(every registered signer). Command: `scripts/verify.sh --network`.

Main source for most entries: the community mirror of Cloudflare Radar's bot directory,
https://github.com/microlinkhq/cloudflare-bot-directory (`src/index.json`, field
`signatureAgentUrl`). The official list is https://radar.cloudflare.com/bots/directory and the
policy is https://developers.cloudflare.com/bots/concepts/bot/signed-agents.

| Origin probed | Who / why | Public source |
| --- | --- | --- |
| https://agent.bot.goog | Google-Agent. Google says it sends `Signature-Agent: g="https://agent.bot.goog"` on a subset of requests | https://developers.google.com/crawling/docs/crawlers-fetchers/web-bot-auth |
| https://xhah6q48pbxb4.keydirectory.signer.us-east-1.on.aws | Amazon Bedrock AgentCore Browser, us-east-1 (one directory per region) | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-web-bot-auth.html ; host names from the Radar mirror |
| https://c3drvlj8gw240.keydirectory.signer.eu-west-1.on.aws | AgentCore Browser, eu-west-1 | same as above |
| https://api.anchorbrowser.io | Anchor Browser, a Cloudflare signed-agents launch partner | https://blog.cloudflare.com/signed-agents/ ; Radar mirror |
| https://www.kernel.sh | Kernel browser agent | Radar mirror |
| https://api.manus.im | Manus Bot (the manus.im apex publishes nothing) | Radar mirror |
| https://api.apify.com | Apify Website Content Crawler | Radar mirror |
| https://api.link.com | "Link CLI". Probably Stripe's Link, **not confirmed** | Radar mirror |
| https://nekuda-agent-registry.onrender.com | Nekuda Payment Executor (agent payments) | Radar mirror |
| https://www.meta.com | Meta-ExternalTest agent | Radar mirror |
| https://assistbot.duckduckgo.com | DuckAssistBot | Radar mirror |
| https://you.com | YouBot | Radar mirror |
| https://www.klaviyo.com | KlaviyoAIBot | Radar mirror |
| https://rye.xyz | Rye, an agentic-commerce API | Radar mirror |
| https://signatures.cardsavr.io | Strivve automation (card-on-file) | Radar mirror |
| https://payroll-bot.adp.com | ADP payroll bot | Radar mirror |
| https://www.browserless.io | Browser automation. Not listed; probed to check | own probe |
| https://www.shopify.com | Shopify verifies agents at its edge; probed to see whether it also publishes a directory | own probe |
| https://steel.dev, https://hyperbrowser.ai | Browser-automation services, not listed | own probe |
| https://stripe.com, https://coinbase.com | Agent payment companies (Link, x402) | own probe |

Also checked, but not Web Bot Auth: `https://mcp.visa.com/.well-known/jwks` (Visa TAP, RSA JWKS,
https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications)
and `https://api.skyfire.xyz/.well-known/jwks.json` (ES256 JWT keys for KYAPay). Neither is a
Signature-Agent directory, so they are not in `CANDIDATES`.
