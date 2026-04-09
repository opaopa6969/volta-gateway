# Gap Analysis: Java volta-auth-proxy → Rust auth-core

> Date: 2026-04-09
> Purpose: Java 版完全置き換えに必要な作業の特定

## 現状

| | Java (volta-auth-proxy) | Rust (auth-core) |
|---|---|---|
| **種類** | HTTP サーバー (Javalin) | ライブラリ crate |
| **エンドポイント** | 100+ REST API | 0 (HTTP 層なし) |
| **SqlStore メソッド** | 150+ | 30 (6 traits) |
| **DB テーブル** | 21 | 7 |
| **SM フロー** | 5 (OIDC, MFA, Passkey, Invite, Token) | 5 (同じ) |
| **認証方式** | OIDC, SAML, Passkey, Magic Link, M2M | OIDC, Passkey(partial) |

## 最大のギャップ: HTTP API サーバーが無い

Java は Javalin で 100+ エンドポイントを公開。Rust は library のみ。
**`auth-server` crate を新設し、Axum で HTTP 層を構築する必要がある。**

## カテゴリ別差分

### A. HTTP エンドポイント (全 94 件)

#### Auth (認証フロー) — 10 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /login | ✅ | ❌ |
| GET | /callback | ✅ | ❌ (AuthService.oidc_callback は lib) |
| POST | /auth/callback/complete | ✅ | ❌ |
| POST | /auth/refresh | ✅ | ❌ (AuthService.token_refresh は lib) |
| GET/POST | /auth/logout | ✅ | ❌ |
| POST | /auth/switch-account | ✅ | ❌ |
| POST | /auth/switch-tenant | ✅ | ❌ |
| GET | /select-tenant | ✅ | ❌ |
| POST | /auth/magic-link/send | ✅ | ❌ |
| GET | /auth/magic-link/verify | ✅ | ❌ |

#### SAML — 2 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /auth/saml/login | ✅ | ❌ (DD-005: Java sidecar) |
| POST | /auth/saml/callback | ✅ | ❌ |

#### MFA — 6 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /mfa/challenge | ✅ | ❌ |
| POST | /auth/mfa/verify | ✅ | ❌ (AuthService.mfa_verify は lib) |
| POST | /api/v1/users/{id}/mfa/totp/setup | ✅ | ❌ |
| POST | /api/v1/users/{id}/mfa/totp/verify | ✅ | ❌ |
| DELETE | /api/v1/users/{id}/mfa/totp | ✅ | ❌ |
| POST | /api/v1/users/{id}/mfa/recovery-codes/regenerate | ✅ | ❌ |

#### Passkey — 6 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| POST | /auth/passkey/start | ✅ | ❌ (PasskeyService は lib) |
| POST | /auth/passkey/finish | ✅ | ❌ |
| POST | /api/v1/users/{id}/passkeys/register/start | ✅ | ❌ |
| POST | /api/v1/users/{id}/passkeys/register/finish | ✅ | ❌ |
| GET | /api/v1/users/{id}/passkeys | ✅ | ❌ |
| DELETE | /api/v1/users/{id}/passkeys/{id} | ✅ | ❌ |

#### Invite — 5 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /invite/{code} | ✅ | ❌ |
| POST | /invite/{code}/accept | ✅ | ❌ (AuthService.invite_accept は lib) |
| POST | /api/v1/tenants/{id}/invitations | ✅ | ❌ |
| GET | /api/v1/tenants/{id}/invitations | ✅ | ❌ |
| DELETE | /api/v1/tenants/{id}/invitations/{id} | ✅ | ❌ |

#### Session — 6 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /api/me/sessions | ✅ | ❌ |
| DELETE | /api/me/sessions | ✅ | ❌ |
| DELETE | /api/me/sessions/{id} | ✅ | ❌ |
| DELETE | /auth/sessions/{id} | ✅ | ❌ |
| POST | /auth/sessions/revoke-all | ✅ | ❌ |
| GET | /admin/sessions | ✅ | ❌ |

#### User — 10 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /api/v1/users/me | ✅ | ❌ |
| GET | /api/v1/users/me/tenants | ✅ | ❌ |
| GET | /api/v1/users/me/mfa | ✅ | ❌ |
| GET | /api/v1/users/{id} | ✅ | ❌ |
| PATCH | /api/v1/users/{id} | ✅ | ❌ |
| PATCH | /api/v1/users/{id}/locale | ✅ | ❌ |
| DELETE | /api/v1/users/me | ✅ | ❌ |
| POST | /api/v1/users/me/data-export | ✅ | ❌ |
| POST | /api/v1/users/{id}/export | ✅ | ❌ |
| DELETE | /api/v1/users/{id}/data | ✅ | ❌ |

#### Tenant — 7 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| POST | /api/v1/tenants | ✅ | ❌ |
| GET | /api/v1/tenants/{id} | ✅ | ❌ |
| PATCH | /api/v1/tenants/{id} | ✅ | ❌ |
| POST | /api/v1/tenants/{id}/transfer-ownership | ✅ | ❌ |
| GET | /api/v1/tenants/{id}/billing | ✅ | ❌ |
| POST | /api/v1/tenants/{id}/billing/subscription | ✅ | ❌ |
| GET | /api/v1/tenants/{id}/members | ✅ | ❌ |

#### Member — 4 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /api/v1/tenants/{id}/members/{id} | ✅ | ❌ |
| PATCH | /api/v1/tenants/{id}/members/{id} | ✅ | ❌ |
| DELETE | /api/v1/tenants/{id}/members/{id} | ✅ | ❌ |
| DELETE | /api/v1/tenants/{id}/members/{id}/mfa | ✅ | ❌ |

#### Device Trust — 3 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /api/v1/users/me/devices | ✅ | ❌ |
| DELETE | /api/v1/users/me/devices/{id} | ✅ | ❌ |
| DELETE | /api/v1/users/me/devices | ✅ | ❌ |

#### Webhook — 6 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| POST | /api/v1/tenants/{id}/webhooks | ✅ | ❌ |
| GET | /api/v1/tenants/{id}/webhooks | ✅ | ❌ |
| GET | /api/v1/tenants/{id}/webhooks/{id} | ✅ | ❌ |
| PATCH | /api/v1/tenants/{id}/webhooks/{id} | ✅ | ❌ |
| DELETE | /api/v1/tenants/{id}/webhooks/{id} | ✅ | ❌ |
| GET | /api/v1/tenants/{id}/webhooks/{id}/deliveries | ✅ | ❌ |

#### IdP Config / M2M / Policy — 8 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET/POST | /api/v1/tenants/{id}/idp-configs | ✅ | ❌ |
| GET/POST | /api/v1/tenants/{id}/m2m-clients | ✅ | ❌ |
| GET/POST | /api/v1/tenants/{id}/policies | ✅ | ❌ |
| POST | /api/v1/tenants/{id}/policies/evaluate | ✅ | ❌ |

#### SCIM — 8 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET/POST | /scim/v2/Users | ✅ | ❌ |
| GET/PUT/PATCH/DELETE | /scim/v2/Users/{id} | ✅ | ❌ |
| GET/POST | /scim/v2/Groups | ✅ | ❌ |

#### Admin — 13 件
| メソッド | パス | Java | Rust |
|----------|------|------|------|
| GET | /admin/{members,invitations,webhooks,idp,tenants,users,sessions,audit} | ✅ | ❌ |
| GET | /api/v1/admin/{keys,tenants,users,audit} | ✅ | ❌ |
| POST | /api/v1/admin/keys/rotate | ✅ | ❌ |
| POST | /api/v1/admin/outbox/flush | ✅ | ❌ |

### B. Store/DAO 不足メソッド

| ドメイン | 不足メソッド |
|----------|-------------|
| Session | listAllActive, countGlobal, revokeOldest, revokeByUserTenant |
| OIDC Flow | saveOidcFlow, consumeOidcFlow |
| Magic Link | createMagicLink, consumeMagicLink |
| Signing Key | save, loadActive, list, rotate, revoke |
| Audit | insert, list, anonymize |
| Webhook | create, list, find, update, deactivate, markSuccess/Failure |
| Outbox | enqueue, claimPending, markPublished, markRetry, clearLock |
| Webhook Delivery | insert, list |
| M2M Client | create, find, list |
| IdP Config | upsert, list, find |
| MFA | upsertUserMfa, findUserMfa, hasActive, recovery codes (5 methods) |
| Device Trust | upsert/find/create/touch/delete/list/evict (8 methods) |
| Security Policy | find, upsert |
| Passkey | create, list, findByCredentialId, updateCounter, delete, count |
| Policy | create, list, findMatching |
| Plan/Subscription | listPlans, findSubscription, upsertSubscription |
| Tenant (advanced) | findDetail, updateSettings, listAdmin, setActive, transferOwnership |
| User (advanced) | listUsers, setLocale, findTenantInfos, hardDelete, findToHardDelete, cancelDeletion |
| SCIM | listScimUsers, findScimUser, createScimUser, updateScimUser |

### C. DB テーブル不足

| テーブル | Java | Rust |
|----------|------|------|
| users | ✅ | ✅ |
| tenants | ✅ | ✅ |
| memberships | ✅ | ✅ |
| sessions | ✅ | ✅ (trait のみ, PG migration なし) |
| invitations | ✅ | ✅ |
| invitation_usages | ✅ | ✅ |
| auth_flows | ✅ | ✅ |
| auth_flow_transitions | ✅ | ✅ |
| signing_keys | ✅ | ❌ |
| oidc_flows | ✅ | ❌ |
| user_identities | ✅ | ❌ |
| user_mfa | ✅ | ❌ |
| mfa_recovery_codes | ✅ | ❌ |
| known_devices | ✅ | ❌ |
| user_passkeys | ✅ | ❌ |
| magic_links | ✅ | ❌ |
| m2m_clients | ✅ | ❌ |
| webhook_subscriptions | ✅ | ❌ |
| webhook_deliveries | ✅ | ❌ |
| outbox_events | ✅ | ❌ |
| idp_configs | ✅ | ❌ |
| audit_logs | ✅ | ❌ |
| policies | ✅ | ❌ |
| plans | ✅ | ❌ |
| subscriptions | ✅ | ❌ |
| tenant_domains | ✅ | ❌ |
| tenant_security_policies | ✅ | ❌ |
| trusted_devices | ✅ | ❌ |

### D. 機能別サマリ

| 機能 | Rust 充足度 | 不足詳細 |
|------|-----------|----------|
| HTTP API サーバー | **0%** | auth-server crate が必要 |
| OIDC 認証 | 60% | IdpClient + AuthService あり。エンドポイント化・マルチ IdP DB 保存なし |
| SAML | 0% | DD-005: Java sidecar 維持 |
| MFA | 30% | TOTP verify のみ。setup/recovery codes/policy なし |
| Passkey | 40% | PasskeyService あり。DB 永続化・エンドポイントなし |
| Magic Link | 0% | テーブル・ロジック・エンドポイント全て不足 |
| M2M | 0% | client_credentials grant 未実装 |
| Session 管理 | 40% | 基本 CRUD あり。LRU eviction, admin view なし |
| Device Trust | 0% | テーブル・サービス不足 |
| Webhook + Outbox | 0% | イベント配信基盤不足 |
| Audit | 0% | ログ挿入・閲覧・匿名化不足 |
| GDPR | 10% | soft_delete あり。hard delete/export/anonymize なし |
| SCIM | 0% | プロビジョニング API 不足 |
| 署名鍵管理 | 10% | JwtIssuer あり。ローテーション・DB 保存なし |
| Billing | 0% | Plans/Subscriptions/Stripe 不足 |
| Policy Engine | 20% | 基本 RBAC あり。DB policy evaluation なし |
| Admin UI | 0% | HTML 管理画面不足 |
