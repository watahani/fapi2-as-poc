# v2 再実装計画 — ゼロから作り直す拡張可能な FAPI 2.0 認可サーバー

> 状態：**計画（未着手）**。人間の判断（2026-07-20）：「現在のコードを再修正するよりも、初めから計画を立て直しゼロから実装を進める」。
> 本書は旧 `docs/PLAN-EXTENSIBILITY.md`（v1 リファクタ計画）を**置換**する。同計画の実装監査と 4 層能力モデルは v2 の設計原則として本書に吸収した。
> 実行は CLAUDE.md の統治（レビューループ / CI ループ / TDD / 1 スライス = 1 Issue = 1 bookmark）に従う。

## 0. 一行ゴール

**FAPI 2.0 SP conformance（Layer 1: 20/20、Layer 2: overall=PASS）という既に持っている実装非依存の受入資産を安全網に、「機能 = 自己完結モジュール」「オプション = 4 層で交差検証される宣言」を最初から骨格に持つ AS を新規実装し、v1 と同等（parity）到達後に RAR / DCR / JAR / JARM / mTLS を積み増す。**

## 1. なぜ書き直すか（リファクタ案の棄却理由）

v1 実装監査（2026-07-20、§9 に要約）の結論：

1. **単値固定が型システムの芯まで浸透している**。`z.literal("code")` / `z.literal("private_key_jwt")` / `z.literal("ES256")`、`token_type: "DPoP"` リテラル、`ValidatedAuthorizationRequest.responseType: "code"`、DB レコード型の `codeChallengeMethod: "S256"`。リファクタでも結局ほぼ全ファイル・全型・複数 migration に手が入り、「挙動不変の安全な小改修」にはならない。
2. **「保存されるが無視される」クライアント設定**（`require_pushed_authorization_requests`、`dpop_bound_access_tokens: false`）が示す通り、広告・登録・enforcement の一致は後付けの検証では保証しにくい。**能力の宣言と交差を先に作り、その上に機能を載せる**方が構造的に安全。
3. **書き直しのコストを下げる資産が既に揃っている**：
   - Layer 1 conformance（`test/conformance/fapi2-sp.test.ts`、20 ケース）は `buildApp()` への HTTP（inject）黒箱テストで、**実装の内部構造に依存しない受入仕様**として機能する。
   - Layer 2（`deploy/conformance/` + OpenID Conformance Suite + `drive-browser.mjs`）も外部から HTTP で当てるだけで実装非依存。
   - `docs/REQUIREMENTS-P1.md` の要件 ID 網羅、`docs/SPECS.md` のトレーサビリティ、CI / Helm / k3s / サンドボックスのインフラ一式、および v1 で確立した暗号・プロトコルの知見（consent CSP の form-action 問題等）はすべて持ち越せる。

新規性の高い部分（能力モデル・feature module 骨格）に集中でき、正しさは既存の受入資産で担保できるため、再実装のリスクは通常の「フルスクラッチ書き直し」より大幅に低い。

## 2. v1 から持ち越すもの / 捨てるもの

| 区分 | 対象 |
|---|---|
| **持ち越す（無改変が原則）** | `test/conformance/`（Layer 1、受入仕様）・`test/helpers/`、`deploy/conformance/` 一式（Layer 2 ハーネス、`run-conformance.sh` の EXPECTED_NONPASS 含む）、`deploy/helm/`、`.github/workflows/`、`.devcontainer/`、`scripts/`、`docs/`（GOALS / SPECS / REQUIREMENTS-P1 / AGENT_GUIDE / DEVELOPMENT）、`Dockerfile` |
| **設計参照として持ち越す（コードは書き直す）** | PDP port + adapters + `PDP_KIND` 選択パターン、Storage ports の原子性契約（code redeem / request_uri consume / jti register をポート契約に押し込む）、PAR の peek/consume 分離、`AuthenticationProvider` 境界、config の本番 fail-fast ガード、#33 の enforcement-bearing metadata パターン |
| **ほぼ流用可能（監査で唯一固定が薄い層）** | `src/crypto/` の jose ラッパ構造（ただし発行 alg の ES256 固定は解いて移植） |
| **捨てる** | `src/domain/` `src/endpoints/` の実装本体（単値固定の縦穴）、`src/config.ts` の固定リテラル群、migration の literal 前提スキーマ |
| **参照用に残す** | v1 実装そのもの（main ブランチ）。細部挙動（エラー写像、リダイレクト規約、DPoP nonce 発行タイミング等）の照合用リファレンス実装として parity 達成まで保持 |

## 3. 受入契約（parity の定義）— v2 が変えてはならない外形

Layer 1 / Layer 2 資産を無改変で使い続けるため、v2 は以下の**外形契約**を維持する：

1. `src/index.ts` が `buildApp()` をエクスポートし、`STORAGE=memory` で DB 不要起動できる（Layer 1 の import 面。`test/helpers/` が参照する補助エクスポートも同様）。
2. エンドポイントパス・env 変数名（`ISSUER` / `STORAGE` / `PDP_KIND` / TTL 群 / `METADATA_*` / `DEV_*` / `SESSION_SECRET` 等）は v1 互換。変更が必要な場合はテスト側の修正を同一スライスで行い、**アサーション（要件）には触れない**。
3. dev ログイン・consent 画面は `deploy/conformance/drive-browser.mjs` がドライブできるフォーム構造を維持（変更時はハーネス修正を同一スライスで）。consent ページ CSP の `form-action` にクライアント redirect_uri origin を許可する v1 の教訓（CLAUDE.md 記載）を初回実装から織り込む。
4. **parity 判定 = Layer 1 20/20 green ＋ Layer 2 プラン overall=PASS（55 モジュール中 49 PASS / 1 SKIP / 5 想定 non-pass）＋ unit カバレッジ 80%**。

## 4. v2 アーキテクチャ — 能力の 4 層交差モデル × feature module

### 4.1 4 層交差モデル（オプション整合の中核）

```
L1 サーバー能力   ：feature module 群が登録した選択肢の全集合（コードと同居する宣言）
L2 デプロイポリシー：運用者が有効化した部分集合。PROFILE（fapi2-sp 等）の述語と交差し、矛盾は起動失敗
L3 クライアント登録：クライアントが選んだ部分集合。登録時（seed / DCR）に L1∩L2 内であることを検証
L4 リクエスト     ：実行時に L3 内であることを検証
```

- **Discovery metadata は L1∩L2 から自動導出**（手書きリテラルは存在させない）。広告＝能力が構造的に一致する。
- **プロファイルは L2 上の述語**：`fapi2-sp` は「response_type=code のみ / PAR 必須 / PKCE S256 必須 / sender-constraining 必須 / client auth ∈ {private_key_jwt, mTLS} / alg ∈ {PS256, ES256, EdDSA} / RT ローテーションなし / code 寿命 ≤60s / confidential client のみ」等を宣言。将来 `fapi2-ms`（Message Signing）や dev 用 `baseline` は述語の追加であり、コード分岐は増えない。
- 仕様上任意（MAY）の点はオプション化し、**既定は最も厳しい側**。緩和は L2/L3 の明示オプトインのみ。

### 4.2 feature module（機能 = 自己完結モジュール）

1 ディレクトリ = 1 仕様（RFC 単位）。各 feature は kernel のレジストラに対して以下を**寄与**する：

- capability 宣言（L1 への寄与）／ discovery metadata 断片
- クライアントメタデータのスキーマ断片（L3 検証。RFC 7591 スタイルのフィールド別エラー）
- 認可リクエストのパラメータバリデータ（L4。純関数、ctx に client と L1∩L2）
- provider 実装：`ClientAuthenticator` / `SenderConstraintMethod` / `GrantTypeHandler` / `AccessTokenFormat` / `ClaimsProvider` / `ResponseMode` のいずれか（該当する場合）
- ルート（エンドポイント）／ ストレージ集約（port + memory/pg 実装）／ 起動時自己検査

```
src/
  kernel/                 # プロトコル非依存の核
    config/               #   zod config + PROFILE 述語 + L1∩L2 解決（fail-fast）
    registry/             #   feature 登録先（capabilities / validators / providers / routes / metadata）
    http/                 #   Fastify 配線・EndpointDeps・エラー写像（RFC 6749 エラー規約）
    storage/              #   port 基盤 + memory/pg アダプタ枠（集約は feature が寄与）
    crypto/               #   jose ラッパ（v1 移植、発行 alg 可変化）
  features/
    oauth-core/           # RFC 6749: token EP 骨格・authorization_code / refresh_token ハンドラ
    pkce/                 # RFC 7636
    par/                  # RFC 9126（request_uri は peek/consume 分離、保存は構造化 JSON）
    dpop/                 # RFC 9449（SenderConstraintMethod: jkt / nonce）
    private-key-jwt/      # RFC 7521/7523（ClientAuthenticator）
    jwt-access-token/     # RFC 9068（AccessTokenFormat）
    oidc/                 # ID token / userinfo / discovery 寄与 / claims マッピング
    iss-response/         # RFC 9207
    introspection/        # RFC 7662（cnf 出力は SenderConstraintMethod 由来）
    revocation/           # RFC 7009
    interaction/          # ログイン/consent（AuthenticationProvider・PDP 連携・grant 永続化）
    ...                   # 拡張フェーズ: resource / rar / dcr / jar / jarm / mtls / grant-management
  profiles/
    fapi2-sp.ts           # プロファイル述語（必須 feature / 制約）
    baseline.ts           # dev/テスト用の緩和プロファイル（本番ガードで禁止）
```

- **grant / consent モデルは初回から (subject, client) の consent 再利用を前提に設計**（`findActiveBySubjectClient`、grant 失効カスケード、将来の Grant Management `grant_id` を見越した形）。
- **クライアントモデルは DCR 前提のフィールド**（`client_id_issued_at` / registration access token ハッシュ / `software_id` 等、nullable）を初回スキーマに含め、後続 migration を減らす。
- kernel は feature を知らない。feature 間依存は capability 経由（例: `fapi2-sp` 述語が par/dpop/pkce の capability 存在を要求）。

### 4.3 リポジトリ運用

- **同一リポジトリ・単一ソースツリー**。v2 ブランチ（bookmark）上で `src/` を新実装に置き換えていき、parity 達成 PR 群を経て main へ。v1 コードは main の履歴（および parity までの参照タグ）として保持する。
- 別ディレクトリ並走（`src2/`）はしない：受入契約（§3）が `src/` への import を前提にしており、二重維持のコストに見合わない。parity までは v2 ブランチの Layer 1 が段階的に green 化していく（P1 当時と同じ「RED から始めて要件を消化する」運用）。

## 5. フェーズ計画

各フェーズ共通 DoD：typecheck / unit green、対象スライスの Layer 1 ケース green 化、`/code-review`・`/security-review` C/H/M=0、要件 ID をコード・コミットから引用。

### V0 — kernel と歩く骨格（walking skeleton）

- kernel（config/PROFILE 述語/L1∩L2 解決、registry、http、storage 枠、crypto 移植）。
- feature ゼロ個でも起動し、`/healthz` と「能力から自動導出された空に近い discovery」を返す。
- 起動時 fail-fast（プロファイル矛盾・本番ガード）のテスト。**オプション整合テストの骨格**（「広告される値は必ず対応 enforcement テストを持つ」を CI 規約化）をここで導入。
- 完了条件：skeleton が k3s/Helm で起動、CI green（Layer 1 は RED のまま=想定内）。

### V1 — コアフロー（parity への最短路）

依存順に独立スライス化（DEVELOPMENT.md の並行開発方式）：

1. **V1a**: oauth-core + pkce + interaction（dev ログイン + consent + PDP）+ oidc 最小 — `baseline` プロファイルで code フロー成立。
2. **V1b**: private-key-jwt + par + dpop + iss-response + jwt-access-token — `fapi2-sp` プロファイル述語を satisfy。
3. **V1c**: introspection + revocation + userinfo + refresh。
4. **V1d**: pg アダプタ（memory と同一のポート契約テストを両バックエンドで実行）、seed、migration。

- 完了条件（**M-parity**）：§3 の受入契約充足 — Layer 1 20/20、Layer 2 overall=PASS、unit 80%、性能スモーク（1vCPU/800Mi で /token p95 < 50ms 回帰確認）。
- parity 達成 PR で main へ。ARCHITECTURE.md を v2 構成へ全面更新、CLAUDE.md の運用差分（PROFILE 等）を反映。

### V2+ — 拡張機能（parity 後、1 機能 = 1 REQUIREMENTS 文書 = 1 ブランチ）

| 順 | 機能 | 主仕様 | v2 での実装形 |
|---|---|---|---|
| E1 | `resource` + クライアント別オプション実効化 | RFC 8707 | パラメータバリデータ + AT `aud` 絞り込み。4 層モデルの実証（最小差分） |
| E2 | **RAR** | RFC 9396 | `rar/` feature：type 別スキーマ registry、PAR 構造化保存→grant 永続化→AT/introspection 反映→consent 表示、PDP へ details 連携 |
| E3 | **DCR** | RFC 7591/7592 | `dcr/` feature：`/register` + 管理 EP（registration access token）。既定 off（L2 オプトイン）、レート制限・監査ログ必須 |
| E4 | **JAR** | RFC 9101 | `jar/` feature：`request`/`request_uri` バリデータスロット実装、`require_signed_request_object` を L3 に |
| E5 | **JARM** | JARM (OIDF) | `jarm/` feature：ResponseMode provider。`fapi2-ms` 述語の一部 |
| E6 | **mTLS** | RFC 8705 | `mtls/` feature：ClientAuthenticator + SenderConstraintMethod（`x5t#S256`）+ `mtls_endpoint_aliases`。TLS 終端のデプロイ設計含む |
| E7 | Grant Management + トークン管理 | FAPI-GM / RFC 7662 | `grant-management/` feature + 管理 API（admin 認証境界、一覧・失効） |

順序の根拠：E1 で配線を検証 → E2 は「リクエスト表現の拡張」、E3 は「クライアント表現の拡張」で、v2 骨格の 2 大拡張軸を早期に本番検証する。E6 はデプロイ影響が最大のため独立。E4 以降は需要で入替可（着手前に人間と合意）。各機能で Layer 1 変種テストを追加し、可能なものは Layer 2 変種プラン（mTLS 版等）を追加する。

## 6. 非機能要件の割付（CLAUDE.md §2 / docs/TODO.md）

| NFR | 割付 |
|---|---|
| FAPI プロファイル選択（profile / sender-constraining / client auth 切替） | V0（PROFILE 骨格）→ E6 で実質複数化 |
| トークン管理（一覧・失効・introspection 連携） | E7 |
| 鍵管理・ローテーション | V0 crypto（発行 alg 可変・複数鍵種 keystore）+ E7 管理面にローテーション API |
| 監査ログ | V1（発行・失効・consent の監査イベント設計を初回から）→ E3 で登録系を追加。永続化先分離は TODO.md 継続 |
| レート制限 | V1（v1 同等の in-process）→ E3 で `/register` 強化。分散化は P4 系 TODO のまま |
| 性能（100RPS / 1vCPU / 800MB, /token p95<50ms） | M-parity の DoD に回帰計測を含める。レジストリ間接呼び出しのオーバーヘッドをここで検証 |

## 7. リスクと対策

| リスク | 対策 |
|---|---|
| 二度目のシステム症候群（過剰抽象） | provider port は「2 つ目の実装が §5 の表に載っているもの」に限定。それ以外は関数分割まで。V0 レビューで port 一覧を人間と確認 |
| parity 未達のまま長期化 | V1 は Layer 1 の RED→green 消化率で進捗を可視化（P1 と同じ運用）。v1 参照実装との挙動照合を V1 各スライスのレビュー観点に含める |
| 受入資産への「テストを実装に合わせる」改変 | Layer 1 のアサーション変更は要件変更としてレビューで明示ブロック（PR テンプレの確認項目化）。パス・env の互換は §3 契約で固定 |
| 性能退行（registry 間接化） | M-parity で計測。ホットパス（/token）は起動時に解決済みハンドラを直接参照する形にし、リクエスト毎のレジストリ探索をしない |
| v1 との共存混乱 | v2 はブランチで一気に `src/` を置換（並走ディレクトリなし）。main は parity マージまで v1 のまま、緊急修正は v1 に当てて v2 に転記 |

## 8. マイルストーン

1. **M-V0**：kernel + skeleton 起動、整合テスト規約導入、CI green。
2. **M-parity**：Layer 1 20/20 + Layer 2 overall=PASS + unit 80% + 性能回帰なし。main へマージ、ARCHITECTURE.md/CLAUDE.md 更新。**ここまでが本計画のコミットメント**。
3. **M-E1〜E7**：§5 の表の順に、各機能着手前に REQUIREMENTS 文書 + 詳細計画で人間と合意。

## 9. 付録 — v1 実装監査の要点（2026-07-20、v2 設計判断の根拠）

- 単値固定の代表：client-auth 一枚岩（`src/domain/client-auth.ts:53-201`）、DPoP 直書き（`tokens.ts:28,54-56` / `token.ts:54-62` / `userinfo.ts:38-57`）、`validateAuthorizationRequest` 一枚岩 + `request` 明示拒否（`authz-request.ts:66-191,71-74`）、JWT AT 固定 + 固定クレーム（`tokens.ts:37-101`）、PAR params の平坦文字列保存（`types.ts:47`）、discovery/config 残存リテラル（`discovery.ts:34-35,53,55` / `config.ts:298-304`）、consent 再利用なし（毎回新規 grant、`grant.ts:40`）。
- v1 の良い設計（v2 が設計参照として継承）：ポート契約への原子性押し込み、PAR peek/consume 分離、alg の config∩天井交差 + 検証点 enforcement（#33）、PDP/Storage/AuthenticationProvider の「port + adapters + config enum + fail-closed」パターン、本番 fail-fast ガード。
