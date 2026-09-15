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

### 4. どのメソッドを測るか

既定は **GET と HEAD だけ**。

secondary の DB は read-only の replica なので、POST を流せば必ず失敗する。
失敗が正常な状態を比較しても情報が増えない。将来 POST を測るなら
「期待するのは 5xx か 403」という形の設定が要る（今回はやらない）。

```yaml
      compare:
        methods: [GET, HEAD]
```

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

1. **比較と計測**（この設計の範囲）。`trust: none` のまま、公開パスだけで一致率を出す
2. `trust: internal` を足し、auth の要る経路まで測れるようにする
3. volta-index 側で一致率を `/topology.html` に出し、`ha-watch` が悪化を通知する
4. p52 を cold から warm にして、hub / auth / gateway の影を常設する
5. 影の一致率が数週間安定してから、`full` 訓練の頻度を下げるかを判断する

## 未解決の問い

（「auth の検証が書き込みを伴うのでは」という懸念は、3 節のとおり実装を読んで解消した）

- **影の側の書き込みをどう止めるか。** `X-Volta-Shadow: 1` を見て拒否するのはバックエンドの仕事だが、
  いまの hub / auth はこのヘッダを知らない。read-only replica が自然に弾く構図に頼るか、
  バックエンドに明示的な対応を入れるか
- **どのホストから始めるか。** `index.unlaxer.org`（hub）は GET が多く副作用が少ないので最初の候補。
  `auth.unlaxer.org` は認証そのものなので `trust: internal` が要る
