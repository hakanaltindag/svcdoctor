# Why `users.acl` carries no comments

Redis 8.2.1 — the version this environment pins — refuses to start when its ACL
file contains a comment line:

```
Aborting Redis startup because of ACL errors: /etc/redis/users.acl:1 should
start with user keyword followed by the username.
```

Comment support in the ACL file arrived in Redis 8.8. Measured here rather than
read from a changelog: the first version of this fixture had explanatory
comments and the container exited at startup.

So the explanation lives in this file instead.

| user | why it exists |
|---|---|
| `default` | Keeps `nopass`, so the server admits an unauthenticated connection and the two AUTH forms can be measured against a real `nopass` user. This is R-06, and it is the scenario that proves `AUTH <user> <anything>` succeeds while `AUTH <password>` errors. |
| `app` | Authenticates and may run the usability probe. R-03. |
| `noperm` | Authenticates and may **not** run the usability probe. R-07. It is a correct least-privilege configuration, not a broken one, which is exactly why svcdoctor must report it as UNKNOWN rather than as a failure. |
| `disabled` | Exists and is switched off. R-05. Redis answers `WRONGPASS` — byte-identical to what it answers for an unknown user and for a wrong password, which is the point of the scenario. |

There is no `unknown` user, deliberately: R-04 asks for a username this file does
not define, and the assertion is that its reply is indistinguishable from R-02's
and R-05's.
