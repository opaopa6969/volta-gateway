# 設定の永続化：設計判断（ファイルオーバーレイ vs DB）

## 現状の方式

API 経由（`PATCH /admin/config`）の設定変更は、手書き YAML の隣の **オーバーレイファイル**
（RFC 7386 JSON Merge Patch、既定 `<config>.overlay.json` または `VOLTA_CONFIG_OVERLAY`）に
永続化される。実効設定 = `deep_merge(base_yaml, overlay)`。書き込みは temp→fsync→rename の
原子的更新で、validate を通った patch のみコミットする。実装は `gateway/src/config_overlay.rs`。

- ホット反映：`routing` / `cors` / `ip_allowlist` / `error_pages_dir` / `server.trusted_proxies`
- 保存のみ（再起動で反映）：`server.port` / `tls` / `l4_proxy` / `plugins` / `auth` など

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
