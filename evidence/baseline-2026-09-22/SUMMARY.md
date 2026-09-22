# Verification summary

- Run at: 2026-09-22T12:31:40Z
- Git commit: not a git repo
- Python: Python 3.12.3; Node: v22.22.2
- Network checks: yes
- Overall: PASS

| Step | Result | Log |
| --- | --- | --- |
| Install Python deps | PASS | install.log |
| Spec vectors + unit + security tests | PASS | pytest-offline.log |
| Install Cloudflare reference library | PASS | npm.log |
| Interop with Cloudflare web-bot-auth (both directions) | PASS | pytest-interop.log |
| End-to-end demo with expected outcomes | PASS | demo.log |
| Live network checks | PASS | pytest-network.log |
| Key directory survey | PASS | survey.log |

## Evidence file hashes (sha256)

```
e7c01f2d1736a530661446f22239ae6341a1305f35416ca71285fb707f9d8165  ./demo.json
574983a3adb61a719b9f043602b6835ebea61965a97d93a1e253cafd2880118e  ./directory_survey.json
c76d8a62aa824a39b75a8a07f0739a73eb42cecc24c263cf126a208ad64abfed  ./pytest-interop.xml
946a9be75cbe959e11a6a79f646ff8de95628f9392fced101475198e54d915d0  ./pytest-network.xml
50f536ed9f386536f6aa9888c26b7a72a4faa3b97db86a806626eb34425a1e83  ./pytest-offline.xml
fa39aaddbf634d0faa58280c2ad25d5cc10dc11474bec12180085e608cc99480  ./demo.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./install.log
3e6d575c2df57e2c2b6a1556c8a02960febbfab71048cb7966e5c8bd65be8b04  ./npm.log
7770f6b4074046955790a8ef1ebcc643d69420ed9982cefdcc915e73b48ef4d2  ./pytest-interop.log
eea9c6e3492444ba9dcb1a0c40cdf9e452225e8d8f3063e55466a4f0c9aaa7b7  ./pytest-network.log
bdd5d242d61454b8979fdbf84f5c9fc7737d79d61f7c4e56f40e4cc27f3143b2  ./pytest-offline.log
5057c36d2825a2b9568735f0402a2e4af9cc5dcac9b3f908864dbafcd3ab28ff  ./survey.log
050acdfcc1baeee0569120955220b1fef15bc1b1682248379f931aa555688948  ./dashboard_snapshot.html
```
