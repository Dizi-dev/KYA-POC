# Verification summary

- Run at: 2026-09-22T12:46:23Z
- Git commit: 16ee01b
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
| Live network checks | PASS | pytest-network.log |
| Key directory survey | PASS | survey.log |

## Evidence file hashes (sha256)

```
e7c01f2d1736a530661446f22239ae6341a1305f35416ca71285fb707f9d8165  ./demo.json
93f8e7ab6bef28abf7412b2033832eb1ef738b7bd74156db36fa24449c611fa1  ./directory_survey.json
3379fd65eb3cfc158662f0899159e6bbec4d57fd1dd4a554378f7969d2b05281  ./pytest-interop.xml
0a5dd6f5284ce2ad274b8eb4e33778a2e62be2836954c907043d5b3782dd917f  ./pytest-network.xml
c5105a81385b82713212dcc5f0c54b96403d7d3c524fed92fc10db9324c82c7a  ./pytest-offline.xml
fa39aaddbf634d0faa58280c2ad25d5cc10dc11474bec12180085e608cc99480  ./demo.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./install.log
2d2b52e05ccd037dba46e794e0e4fef3abc95e493b102780859625ecda8e3b7a  ./npm.log
210a3bbc0928ea48180e1a2c779ee089c9e0c132aa1a8466f8359701735be437  ./pytest-interop.log
4650696e35980630966289edf86ee27b3fef396e6af17bed17cee33860633a18  ./pytest-network.log
6c6625d8d5df75289e72a49feeefd70ec895c259dd4a4ce7e25f6d81100c65c7  ./pytest-offline.log
31b94f608372cdd1703006e9de6301474a0a638bddd58dbf56eb7e90056435bd  ./survey.log
2cdab9488b0f45563fd2e2cd3c68975718cac4779b412c4445c32e717d749e93  ./dashboard_snapshot.html
```
