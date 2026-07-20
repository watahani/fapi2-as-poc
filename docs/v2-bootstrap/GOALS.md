# ゴール定義 v2 — FAPI 2.0 認可サーバー（全シナリオ対応・設定注入可能）

> v1 PoC（[watahani/fapi2-as-poc](https://github.com/watahani/fapi2-as-poc)）の後継。v1 は単一バリアント点
> （plain_fapi × openid_connect × private_key_jwt × dpop）で FAPI 2.0 SP conformance overall=PASS を達成した。
> v2 はゴールを「**Conformance Suite の全シナリオでパスできる、設定を外部注入可能な認可サーバー**」に引き上げる。

## 0. 一行ゴール

**OpenID Conformance Suite の FAPI 2.0 Security Profile / FAPI 2.0 Message Signing 両テストプランを、ユーザー選択可能な全バリアント組合せで green にできる認可サーバーを、シナリオごとの設定を管理 API で外部注入できる（将来は設定画面を提供する）データ駆動アーキテクチャとして、既存 OAuth/OIDC ライブラリに依存せず自前実装する。**

## 1. 実装方針（v1 から継続）

- **スクラッチ実装**：既存 OAuth/OIDC ライブラリ（oidc-provider 等）は使わない。プロトコルロジックは自前。
- **Source of Trust = 仕様**：RFC / FAPI 仕様を一次情報源とする（[SPECS.md](./SPECS.md)）。仕様で一意に決まらない点は人間と相談。
- **許容ライブラリ（インフラ系のみ）**：`jose` / `Fastify` / `pg` / `zod` / `pino`（必要時 `ioredis`）。
- **実装・設計・提案・レビューは Claude Code が担う**。
- **v1 実装は参照実装**：プロトコルの葉ロジック（crypto / DPoP / PKCE / PAR / private_key_jwt 検証 / ストレージ原子性契約）は v1 から**移植**し、再導出しない。

## 2. 対象シナリオ（成功判定の分母）

対象は OpenID Conformance Suite の次の 2 プラン × user-selectable バリアントの全組合せ：

| プラン | バリアント軸 | 組合せ |
|---|---|---|
| `fapi2-security-profile-final-test-plan` | client_auth_type {private_key_jwt, mtls} × sender_constrain {dpop, mtls} × openid {openid_connect, plain_oauth}（fapi_profile=plain_fapi 固定） | 8 |
| `fapi2-message-signing-final-test-plan` | 上記 + 署名リクエスト（JAR）/ JARM 軸。正確な user-selectable 軸は着手時に suite から列挙し `deploy/conformance/plans/` にデータ化 | 着手時確定 |

- **地域プロファイル（openbanking_brazil / connectid_au 等）はスコープ外**。
- suite バージョンは pin する（v1 は `release-v5.1.45`）。suite 更新はプラン一覧の再列挙とセットで行う。
- ハーネス制約による想定 non-pass（v1 の `EXPECTED_NONPASS` 相当）はプランごとに理由付きでデータ化し、それ以外の全モジュール PASS を green と定義する。

## 3. 機能スコープ

| 区分 | 採用 | 備考 |
|---|---|---|
| FAPI 2.0 Security Profile | ✅ 中核 | |
| FAPI 2.0 Message Signing（JAR / JARM） | ✅ 対象 | v1 ではスコープ外だった |
| Sender-constraining | **DPoP + mTLS（両対応）** | バリアント行列の半分が mTLS |
| Client 認証 | **private_key_jwt + mTLS（両対応）** | 同上 |
| PAR / PKCE / Issuer id | ✅ 必須 | RFC 9126 / 7636 / 9207 |
| plain OAuth バリアント（openid なし） | ✅ 対象 | openid {openid_connect, plain_oauth} 両方 |
| Grant types | authorization_code / refresh_token | implicit / ROPC 不採用 |
| RAR / DCR / Grant Management | ⭕ 拡張フェーズ | DCR は suite のプラン設定で dynamic_client が選択可能なら前倒し |
| 地域プロファイル / CIBA | ❌ スコープ外 | |

## 4. 設定の外部注入（v2 の新規中核要件）

- **デプロイポリシー（L2）は永続データ**：プロファイル・有効オプション・鍵設定・クライアント登録を DB 上の設定集約として保持し、**管理 API** で CRUD できる。env 変数は bootstrap/dev 用の一設定ソースに格下げする。
- **反映モデルは段階導入**：当面は「設定変更 → 再起動で反映」（conformance はプランごとに API で設定注入 + 再起動）。無停止 hot-reload（鍵・TLS を含む動的再構成）は後続マイルストーンとして分離する。
- **設定画面**：管理 API の上の薄い UI として後置。API 境界が先、UI は後。
- **管理 API は別認証境界**（admin 認証・監査ログ・レート制限必須）。プロファイル床（fapi2-sp 述語）を下回る緩和は API 経由でも受理しない（fail-closed）。

## 5. 非機能要件（v1 から継続、測定可能な目標値）

測定環境：k8s 上で AS Pod に requests=limits（cpu:1 / memory:800Mi）。

| 指標 | 目標 |
|---|---|
| 定常スループット | 100 RPS 持続（PAR→authorize→token 混在） |
| `/token` 自処理レイテンシ p95 | < 50ms（認証コンポーネント / PDP 往復除く） |
| エラー率 | < 0.1% |
| CPU 使用率 | 100 RPS 時に 1 vCPU の 80% 以下 |
| 常駐メモリ RSS | < 300MB（ピーク 500MB 未満） |
| 起動時間 | < 3s（設定集約の解決込み） |

- L2 が DB 駆動になっても、解決済み設定（ResolvedCapabilities）は起動時に不変スナップショットとしてメモリ常駐させ、ホットパスに DB/レジストリ探索を入れない。

## 6. アーキテクチャ要件

1. **能力の 4 層交差モデル**：L1 サーバー能力（feature module の宣言）∩ L2 デプロイポリシー（永続設定 + プロファイル述語）⊇ L3 クライアント登録 ⊇ L4 リクエスト。Discovery metadata は L1∩L2 から自動導出（手書きリテラル禁止）。詳細は [PLAN.md](./PLAN.md) §3。
2. **プロトコル ⇔ 認証の分離**：ユーザー認証は `AuthenticationProvider` 背後（既定 dev ログイン、deployment は社内認証基盤へ委譲）。
3. **プロトコル ⇔ 認可判断の分離**：consent・スコープ可否は AuthZEN PDP へ委譲（AS は PEP）。PDP 実装は差し替え可能。

## 7. 成功の定義（Definition of Done）

以下の**すべて**を満たしたとき成功とする：

1. **適合性**：§2 の全プラン×全バリアントが green（想定 non-pass はデータ化された理由付きリストのみ）。CI で再現可能。
2. **設定注入**：conformance の各シナリオが、コード変更なしに管理 API 経由の設定注入だけで実行できる。
3. **性能**：§5 の目標を制約環境で達成し、負荷試験レポートで裏付けられる。
4. **分離**：§6 の境界が実装として確認でき、PDP / AuthenticationProvider を別実装へ差し替えても認可フローが成立する。

## 8. 開発・デプロイ環境（v1 資産を継承）

- 開発環境 = Claude Code Docker サンドボックス（隔離・egress 許可リスト）。
- デプロイ = k8s ネイティブ（Helm）。ローカルは in-sandbox k3s。
- 移設する資産の一覧と手順は [ASSETS.md](./ASSETS.md)。

## 9. 未決事項

- Message Signing プランの正確なバリアント軸・モジュール数（W3 着手時に suite から列挙して確定）
- mTLS の TLS 終端方式（Ingress で `client_certificate` ヘッダ渡し vs AS 直接終端の別ポート）
- 管理 API の認証方式（静的 admin token / 社内認証基盤連携）
- hot-reload（無停止再構成）の対象範囲と時期
