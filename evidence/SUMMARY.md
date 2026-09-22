# Verification summary

- Run at: 2026-09-22T13:01:30Z
- Git commit: 2174b1e
- Python: Python 3.14.7; Node: v24.13.0
- Network checks: yes
- Overall: PASS

| Step | Result | Log |
| --- | --- | --- |
| Install Python deps | PASS | install.log |
| Spec vectors + unit + security tests | PASS | pytest-offline.log |
| Install Cloudflare reference library | PASS | npm.log |
| Interop with Cloudflare web-bot-auth (both directions) | PASS | pytest-interop.log |
| End-to-end demo with expected outcomes | PASS | demo.log |
| Verifier benchmark (10,000 verifications, cached key) | PASS | bench.log |
| Live network checks | PASS | pytest-network.log |
| Key directory survey | PASS | survey.log |
| Survey of every registered signed agent | PASS | signed_agents_survey.log |
| Production-mode walkthrough against live ChatGPT/Google directories | PASS | walkthrough.log |
| Drift check of baseline surprises | PASS | drift.log |

## Evidence file hashes (sha256)

```
fe1a9a68980a3b25f3b08a9bae8bc1d0dc7589aa85005182cace4282d8858087  ./bench.json
d0d4882e7c777fc70ad9662ec2a70d2210b9243049b88da75b202e384e30512d  ./demo.json
50237aa7dce2409ef31775608307be19c11a7081d439e95e9ef8b29f272f36d6  ./directory_survey.json
378e16c8659f082b490a83fe24a6a17e5a021b81cb184e451793f450e8955e7d  ./drift.json
2a2da44fd7314ef5920ba05f87a9d89c6874fb653444b318e0d90b7752c9ea51  ./signed_agents_survey.json
e846c970f656ae6e1e11b4be39edbd78e6e16908126f65f456ace66caba9b68a  ./walkthrough.json
97611a428b5b8d055f190aa69cc168688e36f5d4f2870a1504565d4886970891  ./pytest-interop.xml
7bda534f518b21048521b119680fd779f4ac47fb38529fe1681df0504815ec00  ./pytest-network.xml
6970dc1bbf9d3f2f199b36165aad504a88041cc7eb45279b80652c34531ef54a  ./pytest-offline.xml
57219d5451a205381df69c294608ff6c6985cc26f73f24676955e48b2bb77ac1  ./bench.log
5e15508f437c4c275ea2e1a3b7a5ac70c74c07f7136e0cf40ba12c03ad7d2242  ./demo.log
f5b78507e8b7cccbf2e81e576b3baf924e27a1527396b2b93b44b75effbca528  ./drift.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./install.log
706525084ea533c9626230bdb40ba1e6bd4f6010390ec109dc71bd5a23223cfb  ./npm.log
d8f308cc52b81b370c1514b4a941afd5861d8be3df2233a135e1a77c2307f829  ./pytest-interop.log
7533a08f8fdf6553ae96425896dfd62daefe219d4bbe3a7723840b6b51e12b09  ./pytest-network.log
27bf494c1d5e2b19f6348f411088fa8c2bd13529b1f042d828726f7841bbd332  ./pytest-offline.log
3e91f125ecca6d9e1ed42a586d201ed72b0fbe8c8e39fb693bc181c11030db71  ./signed_agents_survey.log
fb83a869c5fa5083fcfa5bad012d0f62cc3c9909105746152a4de507bc383448  ./survey.log
371c9cdee558a1eb2cbfea09caf81367d3864f3b35425e9c02c4c5ef07ecb4d7  ./walkthrough.log
01509fe4b98e689397c15437315679625352d28e8c9be23d821a11d58b54e9a1  ./dashboard_snapshot.html
```
