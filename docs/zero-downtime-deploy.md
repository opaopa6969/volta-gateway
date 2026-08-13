# ゼロダウンタイム配信（SO_REUSEPORT ローリング）

`#74` (BT-HA-2) の手順。**バイナリを更新しても `:80` が瞬断しない**ようにする。

## 何が問題だったか

これまでのデプロイは「プロセスを止める → バイナリを差し替える → 起動する」だった。
その間 `:80` を誰も listen していないので、**数秒間すべての `*.unlaxer.org` が
接続拒否**になる。`restart: always` と `drain_timeout_secs` は入っていたが、これは
「落ちたときに戻す」「落とすときに in-flight を守る」ための設定で、**切り替えの
瞬間に穴が開く**ことは解決しない。

## 仕組み

`server.reuse_port: true` にすると SO_REUSEPORT が立ち、**同じ `:80` に複数の
プロセスが同時に bind できる**。カーネルが新規接続を listen 中のプロセスへ分散
するので、次の順で回せば穴が開かない:

```
1. 新バイナリのプロセスを起動        ← この時点で新旧2つが :80 を listen
2. 旧プロセスに SIGTERM              ← drain 開始。in-flight を流し切る
3. 旧プロセスが終了                  ← 以降は新プロセスだけが listen
```

`SO_REUSEADDR` だけでは足りない（TIME_WAIT の再利用はできるが、**同時に listen
はできない**）ので、両方立てている。

## 設定

```yaml
server:
  port: 80
  reuse_port: true          # 既定は false
  drain_timeout_secs: 15    # in-flight を待つ上限
```

**既定を false にしてある**のは、既存のデプロイで勝手に有効になると「古いプロセスが
残っていることに気付かないまま新旧が同時に動く」事故が起きうるため。
「再起動したのに古い挙動のまま」の原因が読めなくなる。手順を整えたうえで opt-in する。

Linux / *BSD / macOS のみ。他プラットフォームでは警告を出して通常の bind に落ちる
（**黙って無効にすると「有効にしたつもりで瞬断する」**ので、必ずログに出す）。

## 手順（systemd を使わない場合）

```bash
# 1. 新バイナリを配置（別名で置く）
scp target/release/volta-gateway prod:/home/opa/volta-gateway/volta-gateway.new

# 2. 旧プロセスの PID を控える
OLD=$(pgrep -f 'volta-gateway volta-gateway.yaml')

# 3. 差し替えて新プロセスを起動
ssh prod 'cd /home/opa/volta-gateway && mv volta-gateway.new volta-gateway && \
          nohup ./volta-gateway volta-gateway.yaml >> gateway.log 2>&1 &'

# 4. 新プロセスが listen したことを確認（2つ見えるはず）
ssh prod 'ss -ltnp | grep :80'

# 5. 旧プロセスを drain
ssh prod "kill -TERM $OLD"

# 6. 旧プロセスが消えたことを確認（listener が1つに戻る）
ssh prod 'ss -ltnp | grep :80'
```

**4 を飛ばさないこと。** 新プロセスが起動に失敗している（設定エラー等）のに旧を
落とすと、そこで初めて全滅する。`--validate` を先に通しておくとなお良い
（終了コードは SPEC §11.8。#95）。

## 実測（2026-08-13）

同一設定の2プロセスを `:18080` に立て、旧プロセスに SIGTERM を送りながら
100ms 間隔で 60 回叩いた結果:

| 応答 | 回数 |
|---|---:|
| 200 | 59 |
| 503 | 1 |
| **接続失敗** | **0** |

**接続拒否は一度も起きなかった** = `:80` は瞬断していない。

503 が1回出たのは、drain 中の旧プロセスの `/healthz` に当たったため。これは
**設計どおり**で、`/healthz` は drain 中に 503 を返して「このインスタンスに新規を
回すな」を上流に伝える。実トラフィック（`/healthz` 以外）は drain 中も処理される。

ただし**外形監視が `/healthz` を叩いていると、ローリング中に一瞬 down と判定され
うる**。cf-health-worker は「2回連続失敗で down 宣言」なので誤報にはならないが、
気になるなら drain 開始時に listener を閉じる（新規接続をカーネルが残りの
プロセスへ回す）ようにすれば 503 も出なくなる。**未実装**。

## BT-HA-1: hang したインスタンスを置き換える

`restart: always` は**プロセスが死んだとき**しか効かない。**応答しないが生きている
（hang）状態は拾えない。** 実際 2026-08-06 に gateway が 10時間 502 を返し続けた間、
コンテナは Running のままだった。

### `--health-check`

```bash
volta-gateway --health-check 80    # 2xx なら exit 0、それ以外は exit 1
```

`http://127.0.0.1:<port>/healthz` を叩く。**curl / wget を使わない**のは、本番
イメージが `debian:bookworm-slim` で**どちらも入っていない**ため。パッケージを
足すとイメージが変わるので、既にマウントされているバイナリ自身で叩く。

Host ヘッダには routing に載っていない値（`127.0.0.1`）を送る。routing にある
Host を送ると backend へ proxy されてしまい、**gateway 自身ではなく backend の
健康を見てしまう**（`dc4b098` で直した挙動そのもの）。

### compose に入れる

```yaml
services:
  gateway:
    # ... 既存の設定 ...
    healthcheck:
      test: ["CMD", "./volta-gateway", "--health-check", "80"]
      interval: 30s
      timeout: 5s
      # drain 中は /healthz が 503 を返す。ローリング更新の最中に殺されないよう
      # retries を積む（30s × 3 = 90s 応答が無ければ unhealthy）。
      retries: 3
      start_period: 10s
```

`restart: always` と組み合わせると、unhealthy になったコンテナを Docker が
再起動する。

### 適用手順（prod）

```bash
# 1. 新バイナリを配置（--health-check を含むもの）
scp target/release/volta-gateway prod:/home/opa/volta-gateway/volta-gateway

# 2. compose に healthcheck を追記

# 3. 反映（この時点では一度落ちる。reuse_port のローリングを使うなら上の手順で）
ssh prod 'cd /home/opa/volta-gateway && docker compose up -d'

# 4. 効いているか確認
ssh prod 'docker inspect --format "{{.State.Health.Status}}" volta-gateway'
```

**3 で一度落ちる**点に注意。compose の設定変更はコンテナの再作成を伴うので、
無停止でやりたければ先に `reuse_port` のローリング（上記）で新プロセスを立てて
おくこと。
