# Verification summary

- Run at: 2026-09-24T16:29:35Z
- Git commit: f2ef89d
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
fbbf8dd466e599cbab0ae3e787f65fac533026b20bc61330fe151b2c8c5190f5  ./bench.json
d0d4882e7c777fc70ad9662ec2a70d2210b9243049b88da75b202e384e30512d  ./demo.json
79e798689c6f355370453ee91f297777b9521c81a1ada529cd80f5196668dc09  ./directory_survey.json
f78c1bcdadc3983dd17c8b44ad171dc3063f1fe705620d4e0eb5793427601e0c  ./drift.json
c2faae7691480a12a9c9951661b24de93ca34b00b1b5aec24ee352c1711014d5  ./signed_agents_survey.json
e846c970f656ae6e1e11b4be39edbd78e6e16908126f65f456ace66caba9b68a  ./walkthrough.json
3577e19a2702e0179c198e527db008f26f36335d749425079b7f44377f205fbd  ./pytest-interop.xml
b00aad08209d95f5616de4389af7f3dc882128f07cb6914ef32e52d9cbf52111  ./pytest-network.xml
af0bc422cced23438ebce588d6027e0f7fc40b4716a75e2b2807f9756a75cb53  ./pytest-offline.xml
50b0df430755fee4f01acdf9f87a21b11dcbd7e8728aff6f29d98f51d802725c  ./bench.log
5e15508f437c4c275ea2e1a3b7a5ac70c74c07f7136e0cf40ba12c03ad7d2242  ./demo.log
a7c8464300b85c49575451a551599d1028afafc2e698a2e2ef392321d8ae1647  ./drift.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./install.log
b08072ff3e42c5a5341f38e80a694ccac6e0f0b1c6b85a21a60e01433b5b03f4  ./npm.log
e63f1aabf6150974d79afeeae97f514ee3bb8dec98e442130c458be1e06d0bdb  ./pytest-interop.log
6a7857873cf31343f8506373abf10fb8df10e8966071310768b318b62ca2b3e2  ./pytest-network.log
dedfcfaee05deb9d4676e347949fec49a0d7dd81a766b35329a1918e2bdbebfd  ./pytest-offline.log
528f3120257a7e5385b956395d1112fd1c250edbcf9d12768da43cc58fe3b471  ./signed_agents_survey.log
9f3842326ef4298368a95d6c632ece5e375eca8cf1fe6603b2fa335840b2cb15  ./survey.log
371c9cdee558a1eb2cbfea09caf81367d3864f3b35425e9c02c4c5ef07ecb4d7  ./walkthrough.log
35d3ae558e46a0b5bb08d91b640f7b31daccac9959bb7bf6e22f65fe31d5bab6  ./dashboard_snapshot.html
```
