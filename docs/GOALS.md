# PoC ゴール定義 — FAPI 2.0 認可サーバー（スクラッチ実装）

> Claude Code を用いて **FAPI 2.0 準拠の認可サーバーをスクラッチ実装できるか**を検証する実証実験。
> 本書は「何を達成すれば成功か」を測定可能な形で定義する。

## 0. 一行ゴール

**OpenID FAPI 2.0 Security Profile Conformance Suite を green で通過し、かつ 1 vCPU / 800MB 環境で 100 RPS を所定のレイテンシ内でさばける認可サーバーを、認証・認可・プロトコルが分離されたアーキテクチャで、既存 OAuth/OIDC ライブラリに依存せず自前実装する。**

## 1. 実装方針（本 PoC の核）

- **スクラッチ実装**：既存 OAuth/OIDC ライブラリ（oidc-provider 等）は使わない。プロトコルロジックは自前。
- **Source of Trust = 仕様**：RFC / FAPI 仕様を一次情報源とする（[SPECS.md](./SPECS.md)）。仕様で一意に決まらない点・仕様に無い非機能要件は人間と相談して決める。
- **許容する外部ライブラリ（インフラ系のみ）**：暗号 = `jose`、Web フレームワーク = `Fastify`、DB ドライバ = `pg`（生 SQL、ORM 不使用）、バリデーション = `zod`、ロガー = `pino`、キャッシュ = `ioredis`（必要時に後付け）。
- **実装・設計・提案・レビューは Claude Code が担う**。

## 2. 対象プロファイルとスコープ

| 区分 | 採用 | 備考 |
|---|---|---|
| FAPI 2.0 Security Profile | ✅ 対象 | ゴールの中核 |
| Sender-constraining | **DPoP (RFC 9449) 先行** | mTLS は後続 |
| Client 認証 | **private_key_jwt (RFC 7523)** | mTLS client auth は後続 |
| PAR / PKCE / Issuer id | ✅ 必須 | RFC 9126 / 7636 / 9207 |
| JAR (RFC 9101) | ⭕ 任意 | conformance 必須ではない |
| FAPI 2.0 Message Signing | ❌ スコープ外 | 後続 |
| Grant types | authorization_code / refresh_token | implicit/ROPC 不採用 |

## 3. 非機能要件（測定可能な目標値）

測定環境：k8s 上で AS Pod に **requests=limits（cpu:1 / memory:800Mi）** を割当（PostgreSQL は別 Pod）。

| 指標 | 目標 |
|---|---|
| 定常スループット | **100 RPS を持続**（PAR→authorize→token 混在） |
| `/token` 自処理レイテンシ p95 | **< 50ms**（外部 IdP/PDP 往復除く） |
| エラー率 | < 0.1% |
| CPU 使用率 | 100 RPS 時に 1 vCPU の 80% 以下 |
| 常駐メモリ RSS | **< 300MB**（負荷ピークでも 500MB 未満、`--max-old-space-size=256`） |
| 起動時間 | < 3s |

- 律速は ES256 署名 / DPoP proof 検証 / private_key_jwt 検証。鍵・JWKS はキャッシュする。

## 4. 永続化とキャッシュ

- **一次ストア = PostgreSQL**：client / authorization_code / token / grant / PAR / session を永続化（本番稼働スペックのため DB は必須）。
- **キャッシュ = Redis（後付け）**：性能計測でボトルネックが見えた箇所（JWKS / クライアント / introspection 等）に P4 で導入。
- アプリはステートレス。状態は DB（必要に応じ Redis）に外出し。

## 5. アーキテクチャ要件（3つの分離）

1. **プロトコル ⇔ 認証**：ユーザー認証は外部 IdP / interaction 境界へ委譲。
2. **プロトコル ⇔ 認可判断**：consent・スコープ可否を **AuthZEN PDP** に委譲（AS は PEP）。
3. **PDP 実装の差し替え可能性**：`src/authz/pdp.ts` のインターフェイス背後に OPA/Topaz/Cedar/mock を隠蔽。

詳細は [ARCHITECTURE.md](./ARCHITECTURE.md)。

## 6. 開発・デプロイ環境

- **開発環境 = Claude Code Docker サンドボックス**：全開発をサンドボックス内で実施。ホスト FS/認証情報アクセス禁止、egress は許可リストのみ（`.devcontainer/`）。
- **デプロイ = k8s ネイティブ**：Helm chart（`deploy/helm/auth-server/`）。ローカルは in-sandbox k3s（DinD なし）。開発 DB も k8s 内。

## 7. 成功の定義（Definition of Done）

以下の **両方** を満たしたとき成功とする：

1. **適合性**：FAPI 2.0 SP Conformance Suite（DPoP + private_key_jwt + PAR）が **すべて green**。CI で再現可能。
2. **性能**：§3 の目標を制約環境で達成し、負荷試験レポートで裏付けられる。

加えて §5 の分離が実装境界として確認でき、PDP モックを別実装へ差し替えても認可フローが成立すること。

## 8. フェーズ計画

| フェーズ | 内容 | 完了条件 |
|---|---|---|
| **P0** | 開発環境（サンドボックス + k8s）+ アプリ骨組み | サンドボックス隔離確認・`helm install` で AS+postgres 起動・`/healthz` green |
| **P1** | コアプロトコル自前実装（PAR/authorize/token/DPoP/private_key_jwt/JWT/Discovery/JWKS/iss） | DPoP 付き authz code フロー成立、仕様準拠をテストで担保 |
| **P2** | 認証委譲（外部 IdP）＋ AuthZEN PDP 統合 | 認証・認可が分離して動作 |
| **P3** | Conformance Suite 通過 | FAPI2 SP テストプラン green |
| **P4** | 性能チューニング・負荷試験（必要に応じ Redis） | §3 達成・レポート |
| **P5（任意）** | mTLS / Message Signing / OTel | — |

## 9. 未決事項

- in-sandbox k8s の privileged 容認（リスク）／ rootless 方式の採否
- 署名鍵のローテーション・保管（KMS の要否）、k8s Secret 運用
- 外部 IdP / AuthZEN PDP の実体（P2）
- マイグレーション運用（自前ランナーで十分か）
