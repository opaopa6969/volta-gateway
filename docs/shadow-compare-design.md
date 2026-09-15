---
status: draft
canonicalFor: shadow-compare
lastVerified: 2026-09-16
language: ja
supersedes: []
supersededBy: null
---

# 影に流して答え合わせをする（shadow compare）

**secondary が primary と同じ答えを返せているかを、本番の実トラフィックで常時測る。**
いまは「切り替えられるか」が訓練をした日にしか分からない。本番のリクエストを影に複製して
答え合わせをすれば、毎分わかるようになる。しかも**利用者からは何も変わらない**（影のレスポンスは
捨てる。primary の応答も遅くしない）。

関連: volta-index `deploy/failover/README.md`（訓練の段取り）、`config/failover-drills.json`（訓練の台帳）

## なぜ要るか

2026-09-15 の訓練で、**部品は全部健全なのに切り替えたら落ちる**という穴が出た。
auth DB の standby は streaming、backup も新しい、コネクタも足りている。それでも
aerie の gateway が fence 中の silver-hawk の auth を見続けて、配下の全ホストが 4 分間 502 になった。

`ha-watch` が見ているのは**部品の健全さ**で、「切り替えたら本当に流れるか」ではない。
後者を知るには実際に切り替えるしかなく、切り替えれば断が出る（前回 61 秒）。
**影に流せば、切り替えずに「流れるか」が分かる。**

## いまあるもの（実装の実態）

`routing[].mirror` が既にある（`gateway/src/config.rs` の `MirrorConfig`、`proxy.rs` 1635 行）。

```yaml
routing:
  - host: index.unlaxer.org
    backend: http://192.168.1.8:5055
    mirror:
      backend: http://192.168.1.61:5055   # p52
      sample_rate: 0.1
```

実際の挙動:

| 項目 | いま |
|---|---|
| 送るもの | メソッドと URI、`X-Volta-Mirror: true`、`X-Request-Id`（primary と同じ値） |
| 送らないもの | **body**（`Empty::new()`）、`Cookie`、`Authorization`、`X-Volta-*`（GW-61 / #54 で意図的に落とす） |
| レスポンス | **見ていない。捨てている** |
| 記録 | `mirror_total` と `mirror_errors`。ただし errors は**タイムアウトのみ** |
| タイムアウト | 10 秒 |

つまり **影が 500 を返し続けていても、いまの計器は何も言わない**。
`mirror_errors` が 0 でも「影が生きている」ことの証明にはならない。

## 足りないもの

1. **答え合わせ**（status / body を突き合わせる）
2. **認証が要る経路の扱い** — Cookie を落としているので、影は必ず 401 を返す。
   いまの mirror で測れるのは「認証の要らない公開パス」だけ
3. **body** — GET なら無くてよいが、POST を測るなら要る
4. 差が出たときに「なぜ」を後から追えること（レプリケーション遅延なのか、設定ずれなのか）

## 2 本立てで見る

影のコピーだけでは、**副作用・認証・レプリケーション遅延**の 3 つと永久に戦うことになる
（4 節）。そこで軸を 2 本にする。

| 軸 | 何が分かるか | 弱点 |
|---|---|---|
| **A. 実トラフィックのコピー**（1〜8 節） | 実データ・実セッションでしか出ない差 | 副作用のあるパスを避ける必要がある。lag で「正しい不一致」が出る |
| **B. 判定用の口**（9 節） | 構成のずれ（版・設定・スキーマ・依存先・データの追随） | 実トラフィック固有の差は出ない |

**切り替えられるかの大半は B で分かる。** 版がずれている、マイグレーションが当たっていない、
依存先に届いていない — このどれかなら、実トラフィックを比べるまでもなく切り替えは失敗する。
A は B が緑になった後の「最後の 1 割」を見るためのもの。

## 設計

### 1. 何を「同じ」とみなすか

3 段で記録する。上の段が合わないときだけ下を見る必要はなく、**常に 3 つとも記録**して、
どの段まで一致したかを結果ラベルにする。

| 段 | 内容 |
|---|---|
| `status_class` | 2xx / 3xx / 4xx / 5xx のクラスが同じか（最低限。ここが割れたら切り替えは無理） |
| `status` | ステータスコードが同じか |
| `body_digest` | **正規化した** body の先頭 64 KiB のハッシュが同じか |

**必ず違うので比較から外すもの**（正規化）:

- ヘッダ: `Date`, `Set-Cookie`, `ETag`, `Age`, `X-Request-Id`, `Server-Timing`, `Content-Length`
- body 中: ISO 8601 の日時、`csrf` / `nonce` / `_token` を含む値、UUID
  （**正規表現は設定で足せるようにする**。艦隊ごとに違うため）
- 64 KiB を超える body は「長さと先頭 64 KiB のハッシュ」で比較する。
  ストリーミングを壊さないため、それ以上はバッファしない

### 2. 認証情報をどう渡すか（ここが一番の判断）

いま Cookie / Authorization を落としているのは**正しい既定**で、これは変えない。
影の宛先が第三者なら、落とさないのは資格情報の漏洩そのものになる（GW-61 / #54）。

一方で、**自分の艦隊の中の secondary** に渡さないと答え合わせにならない。そこで:

```yaml
    mirror:
      backend: http://192.168.1.61:5055
      trust: internal          # 既定は none（いまの挙動のまま）
      compare: { ... }
```

- `trust: internal` を**明示したときだけ** `Cookie` / `Authorization` / `X-Volta-*` を転送する
- 設定バリデーションで宛先を縛る: ループバック、プライベート IP、
  もしくは volta-index の `config/fleet-topology.json` に宣言済みの machine の IP のみ。
  それ以外を `internal` にしたら**起動時に落とす**（exit code 1）
- 転送するときも `X-Volta-Shadow: 1` を必ず付ける。バックエンド側は「これは影だ」を見て、
  副作用のある処理を拒否できる（**影である印は、影の側で使えて初めて意味がある**）

### 3. auth の検証は影で通る（確認済み）

`/auth/verify` は **セッションを SELECT するだけで UPDATE しない**。

- `auth-server/src/handlers/auth.rs` の `verify` は `SessionStore::find` だけを呼ぶ
- `find` は `SELECT ... FROM sessions`（`auth-core/src/store/pg.rs`）。
  `last_active_at` を更新する `touch` は**別のメソッドで、verify からは呼ばれない**（0 箇所）

つまり **read-only replica でも ForwardAuth の検証は完了する**。
`trust: internal` で Cookie を渡せば、認証が要る経路もそのまま影で測れる。

ひとつだけ「正しい不一致」が残る: **ログインした直後のセッションは、replica にまだ届いていない**
（lag 4 秒前後）。その数秒のあいだ、影は 401 を返す。これは設定ずれではないので、
不一致を記録するときに lag を添えて切り分けられるようにする（下の 4 節）。

### 4. 何を影に流してよいか（メソッドだけでは決まらない）

**「GET なら安全」は嘘。** HTTP の規約では GET は safe / idempotent だが、実装は守っていない
ことがある。**副作用のある GET を影に流すと、その副作用が二重に起きる。**

うちにも実例がある:

| 経路 | メソッド | 実際に起きること |
|---|---|---|
| `GET /api/topology?refresh=1` | GET | **艦隊の全機に probe を投げ直す**（hub が runner / ssh / 子プロセスで python を流す） |
| `GET /logout` 系 | GET | セッションを壊す（不可逆） |
| 一般に、カウンタ・ジョブ起動・キャッシュ温め | GET | 数える / 動かす |

なので **メソッドで許すのではなく、パスで許す**。既定は deny、許可したものだけ流す。

```yaml
      compare:
        methods: [GET, HEAD]       # 必要条件。これだけでは足りない
        allow:                     # 十分条件。ここに書いたものだけ影に流す
          - prefix: /              # 画面（HTML・静的資産）
          - prefix: /api/topology
            deny_query: [refresh]  # ?refresh=1 は全機に probe を投げるので外す
          - prefix: /api/services
        deny:
          - prefix: /api/agent/    # agent を動かす
          - prefix: /api/exec      # コマンドを流す
          - prefix: /logout
```

**許可してよいかの判定基準**（この 3 つを全部満たすこと）:

1. **冪等** — 同じリクエストを何度出しても結果が変わらない
2. **stateless** — サーバ側の状態を変えない。DB だけでなく、**ファイル・キュー・外部 API・通知**も
3. **実装を読んで確かめた** — 「読むだけに見える」で決めない。`?refresh=1` は読むだけに見える

### 4.1 read-only replica は「DB の副作用」しか止めない

secondary の DB が read-only replica なので POST は失敗する。**ここで安心しないこと。**
replica が止めるのは DB への書き込みだけで、次のものは**そのまま起きる**:

- ファイルの書き込み（ログ・キャッシュ・生成物）
- 外部 API の呼び出し（Cloudflare API、GitHub、決済）
- 通知（ntfy・メール）
- ジョブやプロセスの起動（hub の runner RPC、agent 実行）

だから **影のバックエンドは「副作用を切った構成」で起動する**。環境変数で通知・ジョブ実行・
外部 API を無効にした状態で立てる（p52 を warm にするときの条件にする）。

さらに保険として `X-Volta-Shadow: 1` を送る。**バックエンドがこれを見て副作用のある処理を
拒否できる**ようにするのが最終形（hub / auth への対応は別の作業）。
影である印は、影の側で使えて初めて意味がある。

### 4.2 POST を測るか

測らない。secondary の DB は read-only なので必ず失敗し、失敗が正常な状態を比較しても情報が増えない。
将来測るなら「期待するのは 5xx か 403」という形の設定が要る。

### 5. レプリケーション遅延をどう扱うか

p52 の replay lag は 4 秒前後。**直前に書いた内容を読む GET は、影では古い。**
これは設定ずれではなく正しい不一致なので、0% を目標にしてはいけない。

- 不一致を記録するときに、そのときの `lagSec`（volta-index の `/api/topology` が持っている）を
  一緒に残せるようにする。後から「lag 由来か、設定ずれか」を切り分けるため（3 節のログイン直後の 401 もこれで分かる）
- 判定は**絶対値ではなく悪化**で見る。直近 24 時間の一致率を基準に、そこから落ちたら知らせる

### 6. 計器

```
gateway_shadow_compare_total{host, result}
  result = match | status_class_diff | status_diff | body_diff
         | shadow_error | shadow_timeout | skipped
gateway_shadow_latency_ms{host, side=primary|shadow}   (histogram)
```

volta-index は既に gateway の `/metrics` を topology に取り込んでいる（`machines[].gateway`）。
同じ経路で `/topology.html` の重要サービス欄に

```
影の一致率: 99.2%（直近 1h · GET のみ · n=1,240 · 不一致の 90% は lag 4s 以内）
```

を出し、`tools/ha-watch.sh` が**悪化**を ntfy に流す。

### 7. primary を遅くしない実装

影の比較のために primary のパスに `await` を足さない。

- primary のレスポンス body は**すでにバッファしている経路がある**（圧縮とキャッシュのため。
  `proxy.rs` の cache store のコメント）。そこから先頭 64 KiB のダイジェストを取る
- 影への送信と比較は `tokio::spawn` の中だけで行う（いまの mirror と同じ）
- 影のタイムアウトは既定 2 秒（いまの 10 秒は長い。影が詰まったときに tokio のタスクが溜まる）
- 影が落ちていても遅くても、primary の応答には触れない。これは**いまの fire-and-forget の
  性質をそのまま保つ**ということ

### 8. 安全装置

- `sample_rate` の既定は 0.05。加えて `max_rps`（影への秒あたり上限）を持つ。
  本番の負荷が上がったときに影が二重の負荷にならないように
- `X-Volta-Mirror` / `X-Volta-Shadow` が付いたリクエストは**再び影に流さない**（ループ防止）
- 影の宛先が primary と同じなら設定エラー
- `enabled: false` と、管理 API からの即時停止（kill switch）
- 影のエラーは**影の側の問題**として記録する。primary の SLO には混ぜない

### 9. 判定用の口を、サービス側に実装させる（interface）

`/healthz` は「生きているか」しか言わない。**生きていても、版がずれていれば切り替えは失敗する。**
そこで health と同じ性質（**副作用ゼロ・内部からのみ・軽い**）を持つ別の口を規約にする。

```
GET /__volta/shadow        ループバック / プライベート IP からのみ。認証不要。副作用ゼロ
200 application/json
{
  "service": "volta-index",
  "role": "primary" | "standby",
  "version":  { "git": "7e97c51", "config": "sha256:1a2b…", "schema": 12 },
  "deps":     { "db": "ok", "auth": "ok", "runner_hub": "ok" },
  "digest":   { "users": 145, "sessions": 38, "as_of": "2026-09-16T05:12:00Z" },
  "shadow":   { "safe_paths": ["/", "/api/topology"], "unsafe_paths": ["/api/agent/", "/api/exec"] }
}
```

primary と standby で突き合わせると、**切り替え前に落ちる理由がそのまま出る**:

| 項目 | 違っていたら |
|---|---|
| `version.git` | 配布が届いていない（standby が古いコードで動く） |
| `version.config` | 設定がずれている（前回の ForwardAuth の穴はこの類） |
| `version.schema` | マイグレーションが当たっていない。**切り替えたら壊れる** |
| `deps` | 依存先に届いていない（standby から DB / auth が見えない） |
| `digest` | データが追いついていない。lag の実測値そのもの |
| `shadow.safe_paths` | **サービス自身が「影に流してよいパス」を申告する。** gateway の allowlist をここから生成できる（4 節を手で書かなくて済む） |

規約の要点:

- **副作用ゼロを規約にする。** この口自体が何かを書いたら意味がない
- **認証を要求しない。代わりに到達元を縛る**（ループバック / プライベート IP）。
  `/healthz` と同じ扱いにして、gateway の外には出さない
- **重い集計をしない。** `digest` はインデックスで数えられるものだけ。毎分叩かれる前提
- `role` は自己申告（standby は自分が standby だと知っている）。
  **primary が 2 つ見えたら二重マネージャ**で、それ自体が検出したい事故

### 9.1 実装しているかを見張る

規約は「書いてあるだけ」だと守られない。volta-index 側で:

- catalog（サービスの登録簿）に「この口を実装しているか」を持ち、**critical なサービスに無ければ
  `/topology.html` の drift に出す**（`no-shadow-interface`）
- 重要サービス（hub / auth-server / gateway）は必須。それ以外は任意
- 突き合わせの結果（版・スキーマ・依存の差）も drift にする（`standby-version-drift` など）

### 9.2 順番

**B（判定用の口）を先に作る。** A（実トラフィックのコピー）は B が緑になってからでよい。
理由は上の表のとおりで、B で落ちるものを A で探しても手間が増えるだけ。

## 設定の形（案）

```yaml
routing:
  - host: index.unlaxer.org
    backend: http://192.168.1.8:5055
    mirror:
      backend: http://192.168.1.61:5055
      sample_rate: 0.05
      trust: internal            # none（既定） | internal
      timeout_ms: 2000
      max_rps: 5
      compare:
        methods: [GET, HEAD]
        max_body_bytes: 65536
        ignore_headers: [date, set-cookie, etag, age, x-request-id]
        ignore_patterns:         # body の中で必ず変わるもの
          - '"(csrf|nonce|_token)":"[^"]*"'
          - '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
```

`mirror` に任意フィールドを足すだけなので `config_version: 3` のまま
（contract 上、v3 内での additive な追加は認められている）。

## やらないこと

- **一致率を見て自動で切り替えることはしない。** 知らせるところまで。
  切替の引き金を機械に握らせると、lag の一時的な増大のような**正しい不一致**で本番が動く。
  切替は人が決める（`deploy/failover/README.md` の `full` は人が立ち会う、と同じ理由）
- POST / PUT / DELETE の比較（read-only replica では意味がないため。将来の課題）
- 影の応答を利用者に返すこと（影はあくまで影）

## 段階

**B（判定用の口）が先、A（コピーの答え合わせ）が後。**

1. `/__volta/shadow` の規約を決めて、**hub（volta-index）に実装**する。
   p52 の standby と突き合わせて、版・設定・スキーマ・依存・データの差を出す
2. volta-index の catalog で「この口を実装しているか」を見て、critical なサービスに無ければ drift。
   突き合わせの差も drift（`standby-version-drift` / `schema-drift`）
3. auth-server / gateway にも実装する
4. p52 を cold から warm にして（副作用を切った構成で）、1〜3 を常時回す
5. ここまで緑になってから、**A の比較と計測**。`trust: none`・allowlist に書いた副作用の無いパスだけ
   （`index.unlaxer.org` の画面と `/api/topology` の `refresh` 無しから）
6. `trust: internal` で認証が要る経路まで。一致率を `/topology.html` に出し、`ha-watch` が悪化を通知
7. 一致率が数週間安定してから、`full` 訓練の頻度を下げるかを判断する

## 未解決の問い

（「auth の検証が書き込みを伴うのでは」という懸念は、3 節のとおり実装を読んで解消した）

- **`X-Volta-Shadow: 1` を hub / auth に教えるのはいつか。** 4.1 のとおり、当面は
  「パスの allowlist」と「副作用を切った構成で影を立てる」の二段で守る。バックエンド側の対応は
  影を常設する段（段階 4）までに入れたい
- **どのホストから始めるか。** `index.unlaxer.org`（hub）は GET が多く副作用が少ないので最初の候補。
  `auth.unlaxer.org` は認証そのものなので `trust: internal` が要る
