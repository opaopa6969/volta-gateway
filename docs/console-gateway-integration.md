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
