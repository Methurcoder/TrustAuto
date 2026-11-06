# Round 4 の評価と再現手順

2026-11-06 に Claude の一時作業フォルダの `ext/m7` から保存しました。
元の全10ジョブは学習と交差検証を同時に行い、最後の結果は同日15:47:20（日本時間）に出力されています。

## 保存スコアから再評価する（再学習不要）

Python の標準ライブラリだけで動きます。

```bash
python3 <path>/TrustAuto/ml/truth/experiment_5/round4_evaluation/evaluate.py
```

保存ファイルのハッシュ、予定した全10ジョブの出力、重複行、各ジョブ間のデータ一致、数値の有限性を確認します。
各行のスコアと元のしきい値から、危険・無害・教師ラベル・REVIEW の許可数、危険グループの片側95%上限、AUC、合否を再集計し、元の結果と照合します。
`summary.md` と `summary.json` を出力します。合格基準やしきい値は変えません。

## 学習・交差検証を最初から再実行する

当時のソース4ファイル、4環境の facts/usage、ラベル、外部の学習データも `reproduction/` に保存しました。
追加2環境の `taught_*.jsonl` が空なのは、Flash の教師ラベルが不採用になったためです。

当時の仮想環境（存在確認済み）:

```text
<path>/venv-ml/bin/python
```

この Python は NumPy、scikit-learn、PyTorch を使用します。環境のバージョンは `environment.json` に保存しています。
標準の `python3` には依存パッケージが揃っていません。一時フォルダの仮想環境は削除される可能性があります。

例: 外部データありの4乱数平均 Transformer を、未見の対象で評価します（再学習を伴うため時間がかかります）。

```bash
export TA_ROUND4=<path>/TrustAuto/ml/truth/experiment_5/round4_evaluation
mkdir -p "$TA_ROUND4/rerun/scores"
OMP_NUM_THREADS=2 TA_SEED=1 \
  <path>/venv-ml/bin/python \
  "$TA_ROUND4/reproduction/source/train_actions.py" \
  "$TA_ROUND4/reproduction/data" "$TA_ROUND4/reproduction/labels" \
  known_avg_ext_facts_transformer target deb137 ubu2610 ubu24 deb14 \
  --external "$TA_ROUND4/reproduction/external_rows.jsonl" \
  --out "$TA_ROUND4/rerun/known_avg_ext_facts_transformer_target.json" \
  --scores "$TA_ROUND4/rerun/scores/known_avg_ext_facts_transformer_target.jsonl"
```

全10通りのモデル名と分割方法は `results/jobs.txt` にあります。
モデルの重み自体は元のスクリプトが保存していません。保存スコアでの集計以外に、新しいコマンドを推論するには学習をやり直す必要があります。
危険なコマンドはこの再評価・再学習では実行しません。コーパスを文字列として扱います。
4環境は開発データであり、新環境での独立した最終テストではありません。
