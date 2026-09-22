# Verification summary

- Run at: 2026-09-22T13:06:19Z
- Git commit: 5ff70ab
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
ce107b6d9bf1fd71824e2fd59354f4a93757ccf505ab5ca4942b0e0212453571  ./bench.json
d0d4882e7c777fc70ad9662ec2a70d2210b9243049b88da75b202e384e30512d  ./demo.json
e0fd71d5e836d65aa68ec25afa80ca710c4c3b09a9f082c7e7b44253ec594bd0  ./directory_survey.json
1ff70f320287f230a78461052333193d870fbbcc9843f4c4ef74e355554e407a  ./drift.json
2aca11a99ec20997f33b24c9c3be7182476b64352ccec291b49b3f2686e9d456  ./signed_agents_survey.json
e846c970f656ae6e1e11b4be39edbd78e6e16908126f65f456ace66caba9b68a  ./walkthrough.json
c45a570053bb74a31f6ef01ef5f29102f144d6c9eac8448285df080f29db84c5  ./pytest-interop.xml
511359a2b9ef9d865e9115389b5c5eb7cd7695ae1bec8690fedb7b956bff76d6  ./pytest-network.xml
405405d6842eafd71fc6eeeb51d0cdf49866e87d9ae64b5f9a788c3fe0a2860e  ./pytest-offline.xml
16037d1a61526ef7639967a1a8cfcf82b07becd9933217cd4becc707d6216735  ./bench.log
5e15508f437c4c275ea2e1a3b7a5ac70c74c07f7136e0cf40ba12c03ad7d2242  ./demo.log
58dd136fba67845c8ea00be529bc3586ac2453006d0a209e5bf8a86f0b12cc13  ./drift.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./install.log
cb418be4e38f07cf936c67caea2ea0cebfa85be72e846c1fbfc1853cd8fd7c84  ./npm.log
43fdde9259d61867bc3cfdf708de3be9ac4dabd8755c01233904eae2d3a0af09  ./pytest-interop.log
bd4c41d990f61b38b5d6ed4f1e478c3beef782e04731fd605e35d8227d776c0f  ./pytest-network.log
cbc8d87ced87cc2862578f649f145b09068a1b26dbbe47153e2ec70404759a6d  ./pytest-offline.log
3e91f125ecca6d9e1ed42a586d201ed72b0fbe8c8e39fb693bc181c11030db71  ./signed_agents_survey.log
fb83a869c5fa5083fcfa5bad012d0f62cc3c9909105746152a4de507bc383448  ./survey.log
371c9cdee558a1eb2cbfea09caf81367d3864f3b35425e9c02c4c5ef07ecb4d7  ./walkthrough.log
e805b63d541086e33356f6be226dfa1d00f8e1bdb151f6eacf4f2c18cfbcc73b  ./dashboard_snapshot.html
```
