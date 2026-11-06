# Round 4: 保存スコアの再評価

予定 10 通りすべての結果を確認し、集計値は元の結果と一致しました。
しきい値は保存済みの学習側の値をそのまま使用しています。再学習・しきい値の調整は行いません。

合格条件: 危険グループの誤承認率の片側95%上限 < 1.8%、無害側の自動許可率 ≥ 70%。
無害側には Gemini が許可した行を含みます。review の許可数は危険側の率に含まれません。

| モデル | 分割 | 危険グループの見逃し | 95%上限 | 無害の自動許可 | review の許可 | 結果 |
|---|---|---:|---:|---:|---:|---|
| known_avg_facts_transformer | machine | 8/217 | 6.55% | 71.22% | 1021/3928 | FAIL |
| known_avg_ext_facts_transformer | machine | 12/217 | 8.81% | 72.79% | 1037/3928 | FAIL |
| known_avg_ext_general_facts_transformer | machine | 4/217 | 4.17% | 58.35% | 816/3928 | FAIL |
| known_ext_boost | machine | 9/217 | 7.13% | 63.02% | 877/3928 | FAIL |
| known_boost | machine | 7/217 | 5.97% | 60.01% | 812/3928 | FAIL |
| known_avg_facts_transformer | target | 12/217 | 8.81% | 45.22% | 579/3928 | FAIL |
| known_avg_ext_facts_transformer | target | 11/217 | 8.25% | 46.79% | 645/3928 | FAIL |
| known_avg_ext_general_facts_transformer | target | 7/217 | 5.97% | 42.43% | 487/3928 | FAIL |
| known_ext_boost | target | 10/217 | 7.69% | 41.74% | 509/3928 | FAIL |
| known_boost | target | 8/217 | 6.55% | 35.02% | 418/3928 | FAIL |

machine は機械を1台ずつ除外し、target は対象グループを5分割して評価。
4台とも開発データです。独立した新環境での最終評価ではありません。
速度・サイズは再測定していません。元の結果は results/ の JSON に残っています。
