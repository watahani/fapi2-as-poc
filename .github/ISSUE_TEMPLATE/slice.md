---
name: 開発スライス (slice)
about: 1 PR = 1 セッションで完結する独立スライス。自己完結ブリーフとして書く。
title: "[WS-x] <slice title>"
labels: ["type:slice"]
---

<!-- docs/DEVELOPMENT.md の方法論に沿った自己完結ブリーフ。
     フルの会話コンテキストなしで新セッションが着手できる粒度で書く。 -->

## 目的 / スコープ
<!-- このスライスで達成すること（1 PR 分）。範囲外も明記。 -->

## 対象仕様（先に精読）
<!-- FAPI2 SP / 関連 RFC の節番号。例: RFC 8705 §2, FAPI2 SP 5.3.2.x -->

## 触るファイル（所有）
<!-- 主に編集するファイル。hot-file（config.ts / endpoints/index.ts /
     db/repositories/* / CLAUDE.md / README.md）に触るなら ⚠ を付ける。 -->

## 依存
<!-- blocked by #NN（土台 PR 待ち等）。なければ「なし」。 -->

## Definition of Done
- [ ] TDD（テストファースト・カバレッジ 80%）で実装
- [ ] `/code-review` + `/security-review` ループで Critical/High/Medium = 0
- [ ] CI green（typecheck / test / audit / helm / allowlist / build smoke / Layer1 conformance）
- [ ] 必要なら conformance モジュール / variant を追加し確認
- [ ] ドキュメント更新（該当時：CLAUDE.md / HANDOVER.md / docs / TODO の索引）

## 非機能要件（該当のみ）
<!-- CLAUDE.md「FAPI 実装方針」§2 の該当項目（鍵管理・監査ログ・レート制限・性能・管理機能等）。 -->
