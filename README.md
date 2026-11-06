# TrustAuto

Linux 向けの、常駐しない自動権限昇格ツールです。`sudo` と打たなくても、管理者がポリシーで許可した範囲のコマンドは root で実行されます。未知のコマンドや高リスクのコマンドは管理者の承認を求めます。v1.0.0 からは、機械の事実を読む ML に判断を任せるモードも選べます（プレビュー）。

```console
$ systemctl daemon-reload # ルールで許可 → パスワードなしで root 実行
$ apt search vim          # 権限不要 → そのままユーザー権限で実行
$ apt update              # 外部と通信する → 管理者の承認を要求（network.ask）
$ apt install ./evil.deb  # 型付きルールに合わない → 管理者の承認を要求
$ trustauto run -- mkfs -t ext4 /dev/sda  # 拒否ルール → 実行しない
```

設計の詳細と脅威モデルは [docs/DESIGN.md](docs/DESIGN.md) にあります。

## 現在の状態（v1.0.0-preview.1）

| 項目 | 状態 |
|---|---|
| 判定エンジン、ポリシー、監査ログの形式、シェル連携の生成 | macOS で単体テスト済み |
| ML（機械の事実を使う Transformer） | **組み込み済み（プレビュー）**。Python の学習コードと、4 台・1,534 行で特徴量とスコアが一致することを確認済み |
| ML の精度 | **合格基準に未達**。未見の機械で危険グループの見逃し 8/217（95% 上限 6.6%、基準は 1.8% 未満）、無害の自動許可 71.2%（[実験 5](docs/ML_EXPERIMENT_5.md)） |
| root で動くブローカー、PAM 承認、`trustauto-facts` | 使い捨ての VM（Ubuntu 26.04、arm64）で `scripts/linux_integration.sh` の 178 件すべて合格（2026-11-06） |

既定は「ML＋ルール」（`hybrid`）です。ML が判断するのは、ルールの `allow` と `envelope` に一致したコマンドだけです。ルールのない操作まで ML に任せる「ML のみ」は、管理者が `sudo trustauto mode ml` で選んだときだけ有効になります。外部の監査は受けていません。普段使いのマシンに入れる前に内容を確認してください。

これまでの実験: [1](docs/ML_EXPERIMENT_1.md)、[2](docs/ML_EXPERIMENT_2.md)、[3](docs/ML_EXPERIMENT_3.md)、[4](docs/ML_EXPERIMENT_4.md)、[5](docs/ML_EXPERIMENT_5.md)、[6](docs/ML_EXPERIMENT_6.md)。変更点は [CHANGELOG.md](CHANGELOG.md) にあります。

## 動作モード

| モード | 名前 | `allow` ルール | `envelope` ルール | どのルールにも合わない |
|---|---|---|---|---|
| `rule` | ルールのみ | 昇格 | 承認要求 | 承認要求 |
| `hybrid` | ML＋ルール（既定） | リスクが `ml.high` 未満なら昇格 | リスクがモデルのしきい値未満なら昇格 | 承認要求 |
| `ml` | ML のみ（プレビュー、高リスク） | ML が判断 | ML が判断 | root が必要なら ML が判断、不要なら普段の権限で実行 |

- `deny` はどのモードでも拒否、`ask` は常に承認要求、`user` は権限なしで実行します。優先順位は `deny > ask > allow > envelope > user` で、ファイル内の順序には依存しません。
- `rule` と `hybrid` では、`allow` と `envelope` の外にあるコマンドは、ML がどう判定しても自動昇格しません。
- `ml` では、ルールのないコマンドも ML が低リスクと判断すれば root で実行します。ただし次のものは、どの設定でも承認待ちです。
  - シェル、インタープリター、エディタ、`sudo` などの起動役、リモート接続、ビルドツール
  - カーネル、ディスク、ブートの操作（`mount`、`mkfs`、`modprobe` など）
  - 秘密のファイル（`/etc/shadow` など）を名指しするもの、実行オプションやシェルのメタ文字を含むもの
- `ml` で、学習データで許可された例が 3 行未満のプログラムは、既定では承認待ちです。`sudo trustauto mode ml` を実行すると「MLが学習していないコードも判定して自動で認証しますか？（高リスク）」と聞かれ、`y` と答えたときだけ ML が判断します（`ml.judge_unknown = true`）。
- `ml` で root が必要かどうかは、プログラムの場所（sbin）、変更を目的とする操作か（`systemctl restart`、`apt install` など）、引数のパスを本人の権限で読み書きできるかで決めます。自分のファイルへの `cp` などは普段の権限で実行します。

### 外部との通信

`[network] ask = true`（既定）では、外部と通信しうるコマンドは、どのモードでも、`allow` ルールがあっても承認要求になります。対象は `apt update`、`apt install`、`curl`、`git pull`、URL や `user@host:` を引数に含むものなどです。v0.1.0 では `apt update` がパスワードなしで実行されましたが、v1.0.0 からは既定で承認が必要です。元に戻すには `ask = false` にします。

### ML が読む情報

ML は、コマンドの引数と、その機械の事実を使います。事実とは、パッケージの依存関係、systemd ユニットの状態、実行中のプロセスが使っているファイル、設定ファイルからの参照などです。

`trustauto-facts` が root で事実を集め、`/var/lib/trustauto/facts.json` に保存します。あわせて、判定が読む索引を前もって作り、`/var/lib/trustauto/facts.index.json` に保存します（どちらも `root:trustauto`、`0640`）。インストール時、毎日のタイマー、パッケージの変更後に更新されます。索引がない、または 8 日より古い場合、ML を使う判定はすべて承認要求になります。既定の `hybrid` では `allow` ルールのコマンドも承認要求になるので、事実の収集に失敗したら `sudo trustauto-facts collect`（`/usr/lib/trustauto/trustauto-facts`）を実行するか、`sudo trustauto mode rule` に切り替えてください。

## ビルドとインストール（Linux）

```bash
sudo apt install build-essential libpam0g-dev cargo
```

```bash
cargo build --release
```

```bash
sudo scripts/install.sh
```

その後、次の順に設定します。

1. `/etc/trustauto/policy.toml` を編集し、`approval.approvers` を設定する
2. `trustauto check` で検証する
3. `sudo usermod -aG trustauto ユーザー名` を実行し、ログインし直す
4. `~/.bashrc` または `~/.zshrc` に `eval "$(trustauto shell-init bash)"`（zsh なら `zsh`）を追加する
5. 必要なら `sudo trustauto mode rule`（ルールのみ）または `sudo trustauto mode ml`（ML のみ）でモードを変える。既定は `hybrid`（ML＋ルール）

インストールで `trustauto-facts` の初回収集が走ります。数分かかることがあります。

`trustauto` グループに入れることは、ポリシーの許可範囲をそのユーザーに渡すことと同じです。

## 使い方

```bash
trustauto explain -- apt install htop
```

実行せずに判定と理由だけを表示します。

```bash
trustauto history 20
```

判定履歴を表示します。承認者は全員分、それ以外は自分の分だけ見られます。

| コマンド | 内容 |
|---|---|
| `trustauto on` | 自分の自動昇格をオンにする |
| `trustauto off` | 自分の自動昇格をオフにする。コマンドは普段の権限で動く |
| `trustauto setting` | オンかオフか、モード、モデル、機械の事実の状態を表示する |
| `sudo trustauto mode rule\|hybrid\|ml` | モードを変える。`ml` では高リスクの確認が出る。`--judge-unknown` / `--no-judge-unknown` で確認を省ける |
| `trustauto log` | ログファイルのパスを表示する。読めないユーザーには `trustauto history` を案内する |
| `trustauto help` | コマンドの一覧を表示する |

オンとオフはユーザーごとの設定で、`~/.config/trustauto/off` の有無で決まります。実行のたびに読むので、開いているシェルにもすぐ反映されます。これは本人の好みの設定で、セキュリティの制限ではありません。ブローカーは読まないので、他人の権限を止める目的には使えません。

端末では、キャラクターが判定を顔で伝えます。

| 顔 | 意味 |
|---|---|
| `^ ^` | root で実行 |
| `? ?` | 承認が必要 |
| `> <` | 拒否 |
| `0 0` / `- -` | オン / オフ（`explain` の `user` 判定も `0 0`） |

権限を上げない `user` の判定では、実行時には何も表示しません。顔は権限のない `trustauto` の予測で、最終的に決めるのはブローカーです。パイプやファイルへの出力には出ません。`TRUSTAUTO_FACE=off` で消せて、`NO_COLOR` を設定すると色なしの `[^ ^]` になります。

モードの変更は `sudo trustauto mode` で行います。`/etc/trustauto/policy.toml` の `mode` と `ml.judge_unknown` の行だけを書き換え、コメントやルールはそのまま残します。

ポリシーの書き方は [config/policy.toml](config/policy.toml) を見てください。

## テスト

macOS でも実行できます。

```bash
cargo test
```

```bash
cargo run --release --bin trustauto-bench
```

setuid と PAM の検証は Linux でのみ行えます。setuid バイナリと一時アカウントを作成するので、**使い捨ての VM** で実行してください。

```bash
sudo TRUSTAUTO_TEST_DISPOSABLE=yes scripts/linux_integration.sh
```

## モデルの学習

組み込むモデルは `ml/facts_model.bin` です。実験 5 の round 4 と同じ方法（4 つの乱数の平均、学習側で決めるしきい値）で、開発用の 4 台すべてを学習に使います。NumPy、scikit-learn、PyTorch のある Python で実行します。

```bash
python3 ml/release/export_facts_model.py ml/release/out
```

`ml/release/out/facts_model.bin` を `ml/facts_model.bin` にコピーして再ビルドします。`golden.json` は、Rust の移植が学習コードと同じ値を出すかを確かめる `tests/facts_parity.rs` が使います。

実験 1、2 の文字列モデル（`trustauto-train`）も残していますが、判定には使いません。

## 性能目標

使い捨ての Linux VM（UTM、Ubuntu 26.04、arm64、4 コア、837 パッケージ）で、その機械の事実を集めて `trustauto-bench` を実行した値です（2026-11-06）。

| 項目 | 目標 | 実測（p99） |
|---|---|---|
| Rule Mode の判定 | 100 µs 未満 | 0.18 µs |
| ML の判定（特徴量の計算と 4 つの Transformer） | 10 ms 未満 | 約 7 ms |
| 索引とモデルの読み込み | 目標なし | 約 26 ms（ML を使う判定のときだけ） |
| 事実の収集と索引づくり | 目標なし | 約 10 秒（タイマーとパッケージ変更後に、低い優先度で裏で実行） |
| アイドル時の追加 RAM | 0 MB | 常駐プロセスなし |
| モデルサイズ | 10 MB 未満 | 799 KiB |

判定時間にプロセス起動は含みません。ML を使う判定では、索引の読み込みとモデルの検証が毎回かかります。読み込むのはブローカーだけで、フロントエンドはモデルが要る判定をそのままブローカーに渡します。

## ライセンス

Apache License 2.0 です（[LICENSE](LICENSE)）。第三者のデータとフォントの出典とライセンスは [NOTICE](NOTICE) にあります。

実験の記録のうち、NL2Bash と GTFOBins（GPL-3.0）のコマンドを含むもの（ラボの行、教師 AI への問い合わせ、行ごとのスコア、`ml/release/out/golden.json`）は、このリポジトリに入れていません。`ml/truth/collect_commands.py` が元のデータから集め直します。`golden.json` がないと、`tests/facts_parity.rs` の比較は飛ばされます。
