# 第2試験（EDIT_PROTOCOL_V2）

結論: 不採用。9 モデルすべてで採用基準を満たさず、狙った編集はランダム対照・バイアス対照を一貫して上回らなかった。詳しい説明は [docs/ML_EXPERIMENT_6.md](../../../docs/ML_EXPERIMENT_6.md)。

- 手順書: ../EDIT_PROTOCOL_V2.md（SHA-256 2d5707d33ae39f9f3b15b2a2daa8f3307d78615dd485d142ba7c97a978dfd231）
- 各フォルダ `<シナリオ>_seed<N>/`:
  - `selection.json`: 49 候補すべての変更テンソル・変更要素数・相対 L2・ハッシュ・編集用データの成績・しきい値引き直し後の成績と、選択結果
  - `<候補>.pt` / `<候補>_scores.json`: 候補の重みと編集用データのスコア
  - `evaluation.json` / `evaluation_scores.jsonl`: 選ばれた候補だけを評価用データで 1 回評価した結果と、各行の編集前後スコア
- 実行ログ: ../logs/pilot_v2_*.log、../logs/evaluate_v2.log
- 元のベースラインの重みは変更していない（各スクリプトの最後にハッシュを照合）。
