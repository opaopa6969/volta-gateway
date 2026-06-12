# 設定の永続化：設計判断（ファイルオーバーレイ vs DB）

## 現状の方式

API 経由（`PATCH /admin/config`）の設定変更は、手書き YAML の隣の **オーバーレイファイル**
（RFC 7386 JSON Merge Patch、既定 `<config>.overlay.json` または `VOLTA_CONFIG_OVERLAY`）に
永続化される。実効設定 = `deep_merge(base_yaml, overlay)`。書き込みは temp→fsync→rename の
原子的更新で、validate を通った patch のみコミットする。実装は `gateway/src/config_overlay.rs`。

- ホット反映：`routing` / `cors` / `ip_allowlist` / `error_pages_dir` / `server.trusted_proxies`
- 保存のみ（再起動で反映）：`server.port` / `tls` / `l4_proxy` / `plugins` / `auth` など

## Admin API の認証（BT-SEC-7）

`/admin/*`（`/admin/routes`, `/admin/backends`, `/admin/stats`, `GET/PATCH /admin/config`,
`POST /admin/reload`, `POST /admin/drain`, `DELETE /admin/config/overlay` など）は
従来 loopback（127.0.0.1 / ::1）チェックのみで無認証だった。BT-SEC-7 でトークン認証を追加した。

- **トークン設定方法**：YAML の `admin.token`、または環境変数 `VOLTA_ADMIN_TOKEN`（env が優先）。
- **トークンあり**：すべての `/admin/*` リクエストに `Authorization: Bearer <token>` を要求。
  欠如／不一致は `401`（比較は `subtle::ConstantTimeEq` による定数時間比較でタイミング攻撃を回避）。
- **トークンなし（後方互換）**：loopback 限定で**読み取り系のみ**従来どおり許可。
  書き込み系（PATCH/POST/DELETE などの mutating エンドポイント）は `403` で拒否し、
  起動時に `warn` ログ「admin token未設定のため書き込みAPI無効」を出す。
- `/healthz` と `/metrics` は対象外（従来挙動を維持）。

```yaml
# volta-gateway.yaml
admin:
  token: "REPLACE_WITH_LONG_RANDOM_TOKEN"   # 省略時は VOLTA_ADMIN_TOKEN を参照
```

```bash
# 例：トークンありの書き込み
curl -X PATCH http://127.0.0.1:8080/admin/config \
  -H "Authorization: Bearer $VOLTA_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"server":{"trusted_proxies":["10.0.0.0/8"]}}'
```

実装：`gateway/src/admin_auth.rs`（認証判定 + 単体テスト）、ゲートは `gateway/src/main.rs` の
`/admin/` ハンドラ先頭。本番では compose/env に `VOLTA_ADMIN_TOKEN` を必ず設定すること。

## 結論：当面 DB 化はしない

gateway は **単一インスタンスのエッジ proxy**。設定変更は低頻度・低並行で、JSON ファイル＋
原子的書き込みで一貫性は確保できている。DB を入れるほどの要件は今は無い（"そこまでやるか" が妥当）。

DB 依存はエッジ proxy にとってむしろリスク：起動時に DB が落ちていると proxy 自体が上がれない
（フェイルクローズで全断）恐れがある。結局「DB が真実、無ければローカルにフォールバック」が必要になり、
**現在のファイル二層（base + overlay）と同じ構造を再発明**することになる。

### 注意：デプロイ時のマウント
単一ファイルの bind mount だと、temp ファイル（コンテナ層）と本体（別マウント）が別 FS になり
`rename` が `EXDEV` で失敗する。**書き込み可能なディレクトリをマウントし、`VOLTA_CONFIG_OVERLAY`
でその中のファイルを指す**こと（temp と本体を同一マウントに置く）。手順は
`volta-platform/docs/DEPLOY-volta-gateway.md` 参照。

## DB を検討すべきトリガー

| トリガー | 推奨手段 |
|---|---|
| HA / 複数 gateway で設定共有 | 共有ストア。ただし下記 console 経由が綺麗 |
| 変更履歴・監査（誰がいつ何を） | 履歴を持つストア＝DB。これは明確な動機 |
| 集中管理 UI から設定したい | volta-console（既に Postgres 稼働中）を真実の源に |

## 発展形（DB を足すなら）

gateway に DB クライアントを埋め込むのではなく：

1. **volta-console が設定を所有**（既存 Postgres に保存。UI・監査も console 側）
2. gateway は **既存の HTTP polling ConfigSource**（`config_source.rs` に実装済み）で console から pull

こうすれば gateway は **DB 非依存のまま**・ローカル YAML でフェイルオープン可能で、
永続化・UI・履歴を console に集約できる。プロダクト方針（console 連携）とも整合する。

## まとめ

- 当面：ファイルオーバーレイ＋ディレクトリマウントで確定。
- DB 化は時期尚早。やるとしても gateway 内蔵ではなく **console(Postgres) を源 → gateway は
  ConfigSource で pull** の形を推奨。
- 監査履歴が早期に必要なら、そこだけ先行検討の価値あり。
