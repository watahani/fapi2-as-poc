# TODO — 非機能要件・残タスクの継続的メモ

実装中に気付いた非機能要件（NFR）・残タスクをここに積む（CLAUDE.md「FAPI 実装方針」§2 の NFR 検討の受け皿）。
着手時はフェーズ計画（docs/GOALS.md §8）と突き合わせ、PR で本ファイルからチェックを外していく。

凡例：`[ ]` 未着手 / `[x]` 完了 / （P?）想定フェーズ

## セキュリティ・運用ゲート（本番前必須）

- [ ] **KEYSTORE_KEK の KMS / sealed-secret 管理**（現状 env 直渡し。P1 セキュリティレビュー由来）
- [ ] **SESSION_SECRET / DPOP_NONCE_SECRET のローテーション対応**：現行+旧の二鍵受理（グレース期間）がないと、ローテーション時に全ログインセッション・DPoP nonce が即無効化される
- [ ] **DB 接続 TLS の実運用検証**（`DATABASE_SSL=true` は本番ガードで強制済み。証明書配布手順が未整備）
- [ ] **監査ログの永続化・出力先分離**：現状 pino stdout の `audit:` フィールドのみ。改ざん耐性のある保管先（別ストリーム/収集基盤）と保持期間の設計
- [ ] **pg ストアの定期クリーンアップ Job**：期限切れ PAR / interaction / code / token 行の reaping は読み取り時のみ。k8s CronJob 等での物理削除がないとテーブルが単調増加

## トークン・鍵管理（CLAUDE.md NFR 列挙より）

- [ ] **トークン管理機能**：発行済みトークンの一覧・失効（ユーザー別/クライアント別）を行う管理 API/UI。introspection 連携
- [ ] **署名鍵ローテーションの運用化**：`KeyStore.rotate()` は実装済みだが、トリガー（管理 API / CronJob）と手順書がない。JWKS リタイア猶予（24h）の運用文書化
- [ ] **セッション管理**：ログアウト（cookie 破棄）+ RP-Initiated Logout / セッション一覧・強制失効。現状ログインセッションはステートレス署名 cookie のためサーバー側失効不可（失効要件が出たらサーバー側セッションストアへ）
- [ ] **refresh token の有効期限・アイドルタイムアウト方針**（現状固定 TTL のみ。スライディング/絶対の二段が一般的）

## FAPI プロファイル選択（CLAUDE.md NFR 列挙より）

- [ ] **sender-constraining の切替**：DPoP（実装済み）に加え mTLS（RFC 8705, P5）。クライアント別に許可方式を設定
- [ ] **クライアント認証方式の切替**：private_key_jwt（実装済み）に加え tls_client_auth（P5）。プロファイル（FAPI2 SP / Baseline）選択の設定面
- [ ] **RFC 8707 `resource` パラメータ**：AT の `aud` をリソースサーバー別に絞る（現状 issuer 固定。docs/REQUIREMENTS-P1.md §14 の逸脱項目）

## スケール・性能（P4）

- [ ] **性能目標の計測**：100 RPS / 1vCPU / 800MB、`/token` p95 < 50ms。負荷試験ハーネス + レポート
- [ ] **キャッシュ導入判断**：JWKS / クライアントメタデータ / introspection（ボトルネック計測後、必要なら Redis）
- [ ] **レート制限の分散化**：現状 in-process fixed-window（per-IP）。水平スケール時は Redis 等の共有ストアが必要。クライアント認証後は per-client キーへの切替も検討
- [ ] **DB コネクションプールのサイズ設計**（1vCPU 前提のプール数・タイムアウト）

## クライアント・運用管理

- [ ] **クライアント登録の管理面**：現状 seeder スクリプトのみ。管理 API か RFC 7591 Dynamic Client Registration（FAPI では通常 admin 登録）
- [ ] **k8s マイグレーション Job**：`npm run migrate`（tsx）を initContainer / Job 化（HANDOVER 既知事項）
- [ ] **GHCR conformance イメージの public 化**（packages スコープトークン/UI 操作が必要）

## P2.5（外部 IdP フェデレーション）で発生予定の NFR

- [ ] **上流 IdP 障害時の挙動**：discovery/JWKS/token 取得失敗は fail-closed（ログイン不可）+ 監査ログ。タイムアウトとリトライ方針
- [ ] **上流 IdP の鍵ローテーション追従**：JWKS キャッシュの TTL / kid ミスヒット時の再取得（`src/crypto/jws.ts` の remoteJwksCache を流用）
- [ ] **acr/amr/auth_time のマッピング方針**：上流 ID トークンのクレームを自 AS のセッション・ID トークンへどう透過するか
