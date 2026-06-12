# volta-console ↔ volta-gateway 連携：現状調査と設計比較

> このドキュメントは **volta-gateway** と **volta-console（volta-platform）** の両リポジトリに
> 同内容で配置している。最終更新 2026-06-03。
> 関連: gateway `docs/beyond-traefik-requirements.md`（BT-CP-2/6）、`docs/config-persistence.md`。

## 1. 背景

API（`PATCH /admin/config`）で gateway 設定を書き換え・永続化できるようになった（overlay 方式）。
これを使って **volta-console から gateway を設定する管理 UI** を作れるか検討する。その前提として、
現状の console↔gateway の接続構造を調査した。

## 2. 調査結果：現状の接続構造

**volta-console は「gateway とだけ繋がる」構造ではない。** 広域のコントロールプレーン／
オーケストレータであり、gateway とは **直接 API ではなく `services.json` 経由の間接連携**。

```
                     volta-console-backend (Node, :5000)  ── frontend(:3000 → backend:5000/api)
  ┌──────────┬──────────┬───────────────┬────────────────┬──────────────┬───────────────┐
  │          │          │               │                │              │               │
Postgres   Redis   Docker socket    Cloudflare API     prod VM(SSH)    services.json   traefik-dynamic/
(volta_    (REDIS  (/var/run/       (DNS/Access        192.168.1.50    を書き出す      設定ファイル
 console)   _URL)   docker.sock)     provisioning)      deploy/管理      （ファイル）     生成（ファイル）
                    コンテナ起動管理
```

console-backend の compose（`environment` / `volumes`）から確認した接続先：
- **自前 Postgres**（`volta_console` DB）＋ **Redis** … 直結
- **Docker socket** … コンテナを直接起動・管理
- **Cloudflare API** … DNS / Access プロビジョニング
- **prod VM へ SSH**（`PROD_VM_HOST=192.168.1.50`, `SSH_IDENTITY_FILE`）… デプロイ・運用
- **`services.json`**（`SERVICES_JSON_PATH`）と **Traefik dynamic 設定ディレクトリ**（`TRAEFIK_DYNAMIC_PATH`）… **ファイルとして書き出す**

### gateway との関係＝間接（ファイル経由）
- console が **`services.json` を書き出す** → gateway が **ConfigSource（`ServicesJsonSource`, `config_source.rs`）** で読み込み、`ArcSwap` でホットリロード。これが現在の唯一のリンク。
- **直接の HTTP/API 接続は無い**。
- 両者は **別の docker ネットワーク**（console=`volta-net` / gateway=`traefik-public`）。共有しているのは **ホスト上のファイル**だけ。
- console は歴史的に **Traefik 用 dynamic 設定**も生成しており、gateway へは services.json で並行対応している。

## 3. 連携方式の設計

UI／集中管理のために console→gateway を繋ぐ方式は 2 つ。両方を設計し比較する。

### 方式 A：services.json（ファイル）方式 — 既存の延長

```
console UI → console backend → services.json を書く
                                      │ (ファイル共有 or 配布)
                            gateway ConfigSource (watch/poll) → ArcSwap reload
```

- **対象**：`ServiceEntry` のフィールド＝ルーティング中心（`name/host/port/public/auth_bypass_paths/cors_origins/strip_prefix/app_id`）。
- **真実の源**：console（ファイルを所有）。
- **到達性**：HTTP 不要。ファイルが見えればよい（同一ホスト or 配布）。別ネットワークのままで可。
- **反映**：watch/poll 経由（わずかな遅延）。
- **認証**：ファイルパーミッション。
- 既存実装そのまま。**追加実装ほぼ不要**。

**限界**：`ServiceEntry` で表現できる範囲のみ。`tls` / `rate_limit` / `plugins` / `server` / `l4_proxy` /
per-route の `cache`・`mirror`・`backend_tls`・header 操作などの **full config は扱えない**。

### 方式 B：Admin API（HTTP）方式 — 新規

```
console UI → console backend (BFF, admin token 保持)
                  │ HTTP (mesh/loopback)
            gateway Admin API  GET/PATCH /admin/config, GET /admin/{routes,backends,stats}
                  │
            overlay file に永続化（gateway 側）
```

- **対象**：**full `GatewayConfig`**（overlay の JSON Merge Patch）。read 系で routes/backends/stats も取得。
- **真実の源**：gateway（base YAML ⊕ overlay）。console は編集クライアント。
- **到達性**：**HTTP 経路が必要**。現状 console(`volta-net`) と gateway(`traefik-public`) は**別ネットワークで未接続** → 共有ネットワーク追加 / Headscale(mesh) / ホスト経由のいずれかが前提（新規作業）。
- **反映**：`PATCH` で即時（hot 項目）＋ `requires_restart` を応答で明示。
- **認証**：**admin token 必須**（現状 admin は loopback のみ＝無認証。BT-SEC-7 が前提）。
- **BFF 設計**：console backend が token を保持し mesh/loopback 経由で叩く。gateway admin をブラウザに直接露出しない／CORS 回避。read-only ダッシュボード（routes/backends/stats）は低リスクで先行可能。

**限界／注意**：真実の源が gateway 側になり、console が別途 services.json も書くと **二重管理**になる。
HA で複数 gateway があると **各インスタンスへ個別 PATCH**（or console からの broadcast）が必要。

## 4. 比較

| 観点 | A: services.json | B: Admin API |
|---|---|---|
| 対象範囲 | routing 中心（ServiceEntry サブセット） | **full config**（tls/plugins/server/rate_limit/per-route 全部） |
| 真実の源 | **console**（疎結合） | gateway(base+overlay)。console は編集者 |
| ネットワーク | ファイル共有のみ（経路追加不要） | **HTTP 経路が必要**（現状無し＝新規） |
| 反映速度 | watch/poll（やや遅延） | **即時**（hot 項目） |
| 認証 | ファイルパーミッション | **admin token 必須**（BT-SEC-7 前提） |
| 監査履歴 | console 側で実装 | console BFF or gateway 側で実装 |
| 現状確認(stats/health) | 不可（routing のみ） | **可**（/admin/{backends,stats}） |
| HA/複数インスタンス | 配布で対応しやすい | 各インスタンスへ個別 PATCH 必要 |
| 結合度 | 疎 | 密 |
| 追加実装 | ほぼ不要 | 経路 + 認証 + BFF |

## 5. 推奨：ハイブリッド（役割分担）

どちらか一方ではなく、**特性で使い分ける**のが最善：

- **動的サービス登録（routing）= services.json を継続**。疎結合・既存・HA で配布しやすい。日常のサービス追加/削除はこのまま。
- **full config の閲覧と編集（tls / plugins / rate_limit / server / per-route 詳細）と現状確認 = Admin API 方式**。services.json では表現不可能な領域と、health/stats のライブ表示をカバー。
- **二重管理の回避**：console を最終的な単一コントロールプレーンにするなら、console が「services.json を書く」「Admin API を叩く」の**両方を所有**し、どのキーをどちらで管理するか責務を明確化する。理想形は BT-CP-2（console=真実の源、gateway は ConfigSource で pull）への収束。

### 段階
1. **Phase 1**：Admin API read-only で **現状確認ダッシュボード**（routes/backends/stats）。低リスク・即着手可（gateway 変更ほぼ不要）。ネットワーク経路だけ用意。
2. **Phase 2**：Admin API で **full config 編集**。前提＝ admin 認証（BT-SEC-7 / #73）＋ dry-run（BT-CP-5 / #78）＋ ネットワーク到達性。
3. routing の日常運用は services.json のまま温存。

## 6. 未決事項（要 ADR）
- console↔gateway の HTTP 経路をどう確保するか（共有 docker network / Headscale mesh / ホスト経由）。
- 真実の源を console に寄せるか（BT-CP-2）、gateway overlay を正とするか。二重管理の責務分割。
- 複数 gateway 時の設定配布（services.json 配布 vs Admin API broadcast vs ConfigSource pull）。

## 7. 実際の接続手順（方式 A：services.json 直読み）

console の `config/services.json` を **唯一の起点**にして gateway が直接読む一方通行パイプラインの、
prod での実構成・設定・運用手順。BT-CP-2（console=真実の源、gateway は ConfigSource で pull）の最小実装。

### 7.1 console 形式への対応

gateway の `ServicesJsonSource`（`gateway/src/config_source.rs`）は **2 つの形式を自動判別**する：

- **JSON オブジェクト（`{ "<key>": {...} }`）** … console（volta-platform）形式。`config/services.json` の実物。
- **JSON 配列（`[ {...} ]`）** … gateway 旧来のフラット形式（後方互換、変更なし）。

console 形式のマッピング（実 seed `volta-platform/config/services.json.seed` で検証済み）：

| console フィールド | → route | 補足 |
|---|---|---|
| `cloudflare.hostname`（or `cloudflare.hostnames[env]`） | route host | per-env hostname が優先 |
| `environments.<env>.port` | backend URL の port | 無ければ **skip**（変換不可） |
| `environments.<env>.host` | backend URL の host | 無ければ設定の `prod_host`（デフォルト backend ホスト）を使用 |
| `public` / `access.public` / `access.visibility=="public"` | `public` フラグ | いずれかが真で public |
| `cloudflare.authentication` or `cloudflare.auth_required=true` | 認証あり → `app_id`=サービスキー | public でない時のみ。`X-Volta-App-Id` ヘッダになる |
| `auth_bypass_paths` | `auth_bypass_paths` | ForwardAuth バイパス |

**skip 条件**（テーブル全体は落とさず warn ログで個別スキップ）：
- `cloudflare.enabled == false`
- `environments.<env>.enabled == false`（`enabled` 省略時は **有効扱い** … seed の実サービスは省略多数）
- `<env>` 環境が無い／port が無い（backend を作れない）

`<env>` は `config_sources[].prod_env`（デフォルト `prod`）で切替可能。

### 7.2 gateway 側の設定（YAML）

```yaml
config_sources:
  - type: services-json
    path: /etc/volta/services.json   # console が書き出すファイル（マウント先）
    prod_host: "192.168.1.50"        # env.host 未指定サービスのデフォルト backend ホスト
    prod_env: "prod"                 # 読む environment キー（省略時 prod）
    watch: true                      # ファイル変更を検知して自動ホットリロード（デフォルト false）
```

- `watch: false`（デフォルト）… 起動時に **1 回だけ**読み込んでルートに反映。以後は再読み込みしない。
- `watch: true`（opt-in）… 起動時ロード後、2 秒間隔のポーリングで mtime 変化を検知し、既存の `ArcSwap`
  リロード経路（`spawn_watchers`）で無停止反映。`notify` crate を増やさずポーリング実装（HTTP polling と同方式・低リスク）。

### 7.3 prod での file mount 構成

console と gateway は **別 docker ネットワーク**（`volta-net` / `traefik-public`）だが、`services.json` は
**ホスト上のファイル**で共有する（HTTP 経路は不要）。

```
console-backend  ── SERVICES_JSON_PATH=/data/services.json を書き出す
       │  （bind mount: /srv/volta/services.json:/data/services.json）
   ホスト: /srv/volta/services.json   ← 単一の真実
       │  （bind mount: /srv/volta/services.json:/etc/volta/services.json:ro）
volta-gateway   ── config_sources.path=/etc/volta/services.json （read-only 推奨）
```

- gateway 側は **read-only マウント**（`:ro`）。gateway は書かない（一方通行）。
- console は **アトミックに書き出す**（tmp に書いて rename）こと。書きかけの半端な JSON を gateway が読むと
  パースに失敗するが、その回は warn ログで握りつぶし **前回のルートを維持**する（テーブルは落ちない）。

### 7.4 SIGHUP との関係

gateway には別経路の reload トリガとして **SIGHUP**（base YAML + overlay の再読込）がある。これと
services.json watch は **別系統**で、現状の実装では次の関係になる：

- **SIGHUP**（`main.rs` の `rebuild_hot_with_dynamic`）… base YAML / overlay（`/admin/config` の永続化分）から
  `HotState` を作り直す際に、**config source（services.json 等）由来の動的ルートも再マージ**する。
  `config_sources` のソース watcher は起動時に一度だけ spawn され SIGHUP では再 spawn されないが、
  watcher が publish した最新の動的ルートは共有スナップショット（`DynamicRoutes` = `ArcSwap<RoutingTable>`）に
  保持されており、SIGHUP/admin reload の rebuild でそこから読み直して静的ルートにマージする。
- **services.json watch / 初回ロード**（`spawn_watchers` → 各ソースの merge タスク）… 静的ルートに
  services.json 由来の動的ルートを **マージ**して `HotState` を差し替えると同時に、その動的ルートを
  共有スナップショットへ publish する。

> **根治済み（旧・既知の相互作用）**: 以前は `rebuild_hot` が静的ルートのみで `HotState` を再構築していたため、
> SIGHUP 直後に services.json 由来のルートが一時的に消えていた。現在は `rebuild_hot_with_dynamic` が共有
> スナップショットから動的ルートを再マージするため、**watch の有無に関わらず SIGHUP / `/admin/reload` /
> `/admin/config` PATCH の後も services.json ルートは消えない**。ホスト衝突時は動的（config source）ルートが
> 静的ルートを上書きする（`spawn_watchers` のマージ優先度と一致）。回帰テスト:
> `config_overlay::tests::rebuild_hot_with_dynamic_keeps_services_json_routes` と
> 結合テスト `sighup_rebuild_keeps_services_json_routes`。

役割の整理：「**サービスの増減 = services.json + watch で自動反映**」「**gateway 自体の設定変更
（tls / plugins / rate_limit / server 等）= YAML/overlay 編集 + SIGHUP（or 再起動）**」。`watch: false` 運用では
services.json を書き換えても **起動時の 1 回しか読まない**ため、反映には gateway 再起動が必要になる点に注意。
