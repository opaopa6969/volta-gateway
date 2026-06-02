# volta-gateway — Beyond-Traefik 要件 / 設計仕様（生きた文書）

> Status: ドラフト / 随時追記。最終更新 2026-06-02
>
> 本書は「Traefik 同等性」（達成済み機能は [`parity.md`](./parity.md)）の**先**、
> すなわち **この環境で Traefik 系製品を超えるための要件**を蓄積する場所。
> 関連: 設定永続化の設計判断 [`config-persistence.md`](./config-persistence.md)、
> デプロイ手順 `volta-platform/docs/DEPLOY-volta-gateway.md`。

凡例： ✅ 実装済 / 🟡 設計中 / 🔵 提案（未着手） / 💡 アイデア

---

## 1. 環境コンテキスト（前提）

| 項目 | 現状 |
|---|---|
| 本番ホスト | 単一 VM「HVU」`192.168.1.50`（postgres / volta-console / gateway / code-server / headscale / ttyd 等が**同居**） |
| エッジ | Cloudflare（CF Tunnel）。`CF-Connecting-IP` / `CF-IPCountry` を信頼 |
| 認証 | gateway は認証を **volta-auth-proxy** に委譲（ForwardAuth 風 `/auth/verify`）。JWT ローカル検証も対応 |
| 制御プレーン候補 | volta-console（**Postgres 稼働中**）。設定 UI / 監査の置き場になり得る |
| メッシュ | Headscale（`docs/MESH-VPN-SPEC.md`） |
| デプロイ | release バイナリを scp → debian-slim コンテナにマウントして起動（git 管理外） |
| 設定永続化 | YAML(base) + JSON overlay（`PATCH /admin/config`）。✅ 実装済 |

**最大の構造的リスク：本番が 1 ホストに集約されている（VM 単体が SPOF）。**

---

## 2. 可用性 / HA（最重要トラック）

SPOF は 3 層に分かれる。①を冗長化しても②が残る限り本質的 HA にならない、という優先度で扱う。

| 層 | 障害 | 現状 |
|---|---|---|
| ① gateway プロセス | crash / hang | `restart: unless-stopped` のみ（バイナリ更新で数秒瞬断） |
| ② **VM ホスト** | 電源 / kernel / NIC | **冗長化なし＝本質的 SPOF** |
| ③ エッジ(CF) | — | Cloudflare 前段で HA |

### 要件
- **BT-HA-1** 🔵 **プロセス層の自己修復**：Docker healthcheck で `/healthz` を監視し、hang 時も再起動。
- **BT-HA-2** 🔵 **ゼロダウンタイム配信**：バイナリ更新で :80 を落とさない。案：
  - (a) **SO_REUSEPORT 対応をコードに実装** → 同一 :80 に複数プロセスを bind、カーネル分散＋1個ずつローリング更新（同一ホストで最も簡潔。`/admin/drain` 既存を活用）
  - (b) 薄いフロント（nginx/HAProxy）+ gateway 2 本の blue-green
- **BT-HA-3** 🔵 **本命 HA：Cloudflare Load Balancing × 冗長な stateless gateway**
  ```
  Cloudflare (TLS終端 + LB + health check)
     ├── cloudflared(host A) → volta-gateway A (HTTP-only, stateless)
     └── cloudflared(host B) → volta-gateway B
                 └── 同一設定を中央(console/Postgres)から pull
  ```
  - 2 台目ホストに gateway を立て、各々 cloudflared。CF が health check＋フェイルオーバー。
  - TLS は CF 終端 → gateway は HTTP のみで HA が容易（ACME 証明書共有問題が消える）。
- **BT-HA-4** 🟡 **複数インスタンス整合性**：per-instance ファイル overlay は乖離する。→ **console(Postgres) を真実の源に、各 gateway は既存 HTTP polling ConfigSource で pull**（[`config-persistence.md`](./config-persistence.md) の発展形）。
- **BT-HA-5** 🔵 **グローバルレート制限**：現状プロセス内カウンタ（N 台で実効 N 倍）。厳密化が要れば **Redis 等の共有カウンタ**。当面は近似で可。
- **BT-HA-6** 💡 **アクティブ-スタンバイ簡易版**：2 台目が無い間は、別ホスト/別環境にコールドスタンバイ＋CF フェイルオーバー先だけ用意。

### Traefik との差
Traefik も LB/HA は可能だが、本要件の肝は **Cloudflare をエッジ HA とし、gateway を stateless 化して設定を中央 pull する**という、この環境に最適化した形に落とすこと。

### Open Questions（方針が分岐）
1. 2 台目のホストは用意できる？（無ければ ①②の短期改善に集中）
2. TLS は Cloudflare 終端？ それとも gateway が ACME 終端？
3. 狙いは「無停止デプロイ」寄り / 「ホスト障害耐性」寄り？

---

## 3. 制御プレーン / 設定管理

- **BT-CP-1** ✅ **API 設定変更＋永続化**（overlay, RFC7386 merge patch, 原子的書き込み）。
- **BT-CP-2** 🔵 **集中ソース・オブ・トゥルース**：volta-console が設定を所有（Postgres）、gateway は ConfigSource で pull。UI・履歴を console に集約。
- **BT-CP-3** 🔵 **変更監査 / 履歴**：誰が・いつ・何を変えたか。ロールバック可能なバージョン履歴（DB 化の唯一の明確な動機。[`config-persistence.md`](./config-persistence.md) 参照）。
- **BT-CP-4** 💡 **GitOps モード**：設定 repo を真実の源にして pull/反映（宣言的運用）。
- **BT-CP-5** 🔵 **設定の差分プレビュー / dry-run 適用**（`--validate` の API 版、影響範囲＝hot/restart の事前提示）。UI の前提機能。
- **BT-CP-6** 🔵 **管理 UI（設定編集 ＋ 現状確認の二役）**。Traefik dashboard 相当。
  - 置き場：**volta-console**（既にフロント＋Postgres）。console backend を **BFF** にし、gateway の admin token を保持して mesh/loopback 経由で叩く（gateway admin をブラウザに直接露出しない／CORS 問題回避）。
  - **(A) 現状確認（read-only ダッシュボード）** — *先行可・低リスク*：`GET /admin/routes`（ルーティング表）/ `GET /admin/backends`（health＋circuit breaker）/ `GET /admin/stats`（RPS・エラー・レイテンシ・cache・ws・mirror）/ `GET /metrics`。**gateway 側の追加実装ほぼ不要**、console BFF だけで成立。
  - **(B) 設定編集** — *要前提機能*：`GET /admin/config`（実効設定）/ `PATCH /admin/config`（保存、応答 `hot_applied`/`requires_restart` を表示）/ `DELETE /admin/config/overlay`（リセット）。フォーム駆動には **JSON Schema 自動生成**（`schemars` 等）＋ **dry-run（BT-CP-5）**。当面は routes/backends 専用フォーム＋生 JSON エディタでも可。
  - 段階：**Phase 1 = (A) 現状ダッシュボード**（read-only、すぐ作れる）→ **Phase 2 = (B) 編集**（BT-SEC-7 認証 + BT-CP-5 dry-run + schema が前提）。
  - 依存：admin 認証（BT-SEC-7）、dry-run（BT-CP-5）、監査（BT-CP-3）、Admin UI（BT-OBS-5）。

---

## 4. セキュリティ（本 gateway の差別化の核）

汎用 Traefik に対し、**SaaS 認証特化**が最大の武器。

- **BT-SEC-1** ✅ volta-auth-proxy 連携（ForwardAuth）/ JWT ローカル検証 / セッション Cookie 認識。
- **BT-SEC-2** ✅ per-route CORS（secure-by-default, deny）/ IP allowlist / geo allow-deny。
- **BT-SEC-3** ✅ mTLS backend。
- **BT-SEC-4** 🔵 **JA3/JA4 フィンガープリント＋ FraudAlert 連携**（製品方針）。bot/不正クライアント検知をエッジで。
- **BT-SEC-5** 💡 リクエスト署名検証 / WAF 風ルール（SQLi/XSS パターン、レート異常）。
- **BT-SEC-6** 💡 機密の取り扱い：設定内 secret の参照化（env/Vault 参照）、overlay に平文を残さない。
- **BT-SEC-7** 🔵 **Admin API 認証**（重要・現状ギャップ）：今は `/admin/*` は **`is_loopback()` のみ**で**無認証**。`PATCH /admin/config` が設定を改変・永続化できるようになったため、認証情報を要求すべき。多層防御：
  - **L1 ネットワーク**：データプレーン(:80)と分離し、admin を **専用リスナー**（Headscale/mesh I/F や loopback）にのみ bind。
  - **L2 資格情報**：まず **Bearer トークン**（`admin.token` / `VOLTA_ADMIN_TOKEN`、定数時間比較）。将来は **session JWT + `admin` ロール**（既存 JWT 検証を再利用、監査 BT-CP-3 と接続）。auth-proxy 障害時の **break-glass 静的トークン**を必ず併設（エッジ proxy の循環依存回避）。
  - 変更系（PATCH/DELETE）は**識別情報付きで監査ログ**に残す。

---

## 5. マルチテナンシー（Traefik にない領域）

- **BT-MT-1** ✅ tenancy config（single/multi）、slug routing、`X-Volta-Tenant-*` 透過。
- **BT-MT-2** 🔵 テナント別レート制限 / クォータ / 課金フック（`Monetizer` plugin の発展）。
- **BT-MT-3** 💡 テナント別ルーティング隔離・per-tenant 設定 overlay。

---

## 6. 観測性 / 運用

- **BT-OBS-1** ✅ Prometheus `/metrics`、`/admin/stats`、構造化ログ。
- **BT-OBS-2** 🔵 OpenTelemetry trace エクスポート（traceparent は伝播済、収集先連携）。
- **BT-OBS-3** 💡 **ライブリクエストタップ**（admin で特定 host/route の実トラフィックを覗く）。
- **BT-OBS-4** 💡 per-route SLO / エラーバジェット表示、異常検知アラート。
- **BT-OBS-5** 🔵 **Admin UI ダッシュボード**（現状 API のみ。console 連携で可視化）。
- **BT-OPS-1** 🔵 graceful drain（`/admin/drain` ✅）＋ blue-green / ローリングの運用手順整備。

---

## 7. ルーティング / トラフィック制御

- **BT-RT-1** ✅ weighted LB / circuit breaker / health check / mirroring / cache / per-route timeout。
- **BT-RT-2** 🔵 **アウトライア検知**（応答遅延/エラー率でバックエンドを自動退避）。
- **BT-RT-3** 💡 カナリア / 重み付き段階リリース（mirror＋weight の発展、自動ロールバック）。
- **BT-RT-4** 💡 リトライ / ヘッジング、レスポンス書き換え（body transform）。
- **BT-RT-5** 💡 gRPC / HTTP3(QUIC) 対応。

---

## 8. 拡張性 / エコシステム

- **BT-EXT-1** ✅ ネイティブ Rust plugin（ApiKeyAuth / RateLimitByUser / Monetizer / HeaderInjector）。
- **BT-EXT-2** 🟡 **Wasm plugin ランタイム**（wasmtime）。Traefik の middleware エコシステムに対抗する拡張点。
- **BT-EXT-3** 💡 plugin の hot-load / per-route 有効化 UI。

> Traefik の強み（巨大な provider/middleware エコシステム、K8s ネイティブ、成熟 LB/HA、ダッシュボード）は正面から張り合わない。**この環境特化（CF＋console＋auth-proxy＋マルチテナント＋Rust の安全性/性能）で「超える」**のが戦略。

---

## 9. 優先順位（たたき台）

1. **短期**：BT-HA-1（healthcheck）／ BT-HA-2(a)（SO_REUSEPORT で無停止）— 1 ホストのまま即効。
2. **中期**：BT-HA-3 + BT-HA-4（CF LB＋2 ホスト＋中央設定 pull）— VM SPOF を実際に解消。
3. **随時**：BT-CP-3（監査履歴）、BT-SEC-4（JA3/Fraud）、BT-OBS-5（Admin UI）。

---

## 10. 実装スケッチ（着手予定のもの）

### BT-SEC-7 Admin API 認証（短期：専用リスナー + Bearer）
- `config.rs`: `AdminConfig { token: Option<String>, bind: Option<String> }` を追加（`VOLTA_ADMIN_TOKEN` / `VOLTA_ADMIN_BIND` で env 上書き）。
- `main.rs` の `/admin/*` 分岐：既存 `is_loopback()` に加え、`Authorization: Bearer <token>` を**定数時間比較**（`subtle` クレート or 手書き）。不一致は 401。token 未設定時は現状（loopback のみ）を維持しつつ起動時 WARN。
- 可能なら admin をデータプレーン(:80)と別リスナーに分離し `bind`（loopback / mesh I/F）に限定。
- 変更系（PATCH/DELETE）は識別子付きで監査ログ（→ BT-CP-3 へ発展）。
- break-glass 静的トークンは JWT ロール導入後も残す。

### BT-HA-2(a) SO_REUSEPORT 無停止ローリング
- リスナー bind に `SO_REUSEPORT` を付与（同一 :80 に複数プロセス）。`/admin/drain` で in-flight を流し切ってから差し替え。デプロイ手順（`DEPLOY-volta-gateway.md`）に rolling を追記。

## 11. 追記欄（要件はここに足していく）

- _(新しい要件を `BT-XXX-n` 形式で追記。Status 凡例を付ける)_
