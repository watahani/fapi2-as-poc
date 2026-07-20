# v2 実装計画 — 拡張可能な FAPI 2.0 認可サーバー（新規実装）

> 状態：**計画（未着手）**。本書は自己完結であり、実装セッションは **本書 + CLAUDE.md + docs/（GOALS / SPECS / REQUIREMENTS-P1 / ARCHITECTURE / AGENT_GUIDE / DEVELOPMENT / TODO）** のみを前提に開始できる。
> 実行は CLAUDE.md の統治（レビューループ / CI ループ / TDD / 1 スライス = 1 Issue = 1 bookmark）に従う。

## 0. 一行ゴール

**FAPI 2.0 SP conformance（Layer 1: 20/20、Layer 2: overall=PASS）という実装非依存の受入資産を安全網に、「機能 = 自己完結モジュール」「オプション = 4 層で交差検証される宣言」を骨格に持つ認可サーバーを `src/` に新規実装し、現行実装と同等（parity）到達後に RAR / DCR / JAR / JARM / mTLS を積み増す。**

方針：現行 `src/`（main、以下「現行実装」）は置き換える。現行実装は FAPI 2.0 SP conformance を達成済みだが、プロトコルオプションが単一の組合せ（code + PAR + DPoP + private_key_jwt + ES256 + JWT AT）に固定された構造であり、v2 はオプションの追加・切替を前提とした骨格で作り直す。

## 1. 現有資産 — v2 が利用するもの

| 区分 | 対象 |
|---|---|
| **受入資産（無改変で流用）** | `test/conformance/`（Layer 1：`buildApp()` への HTTP 黒箱 20 ケース、FAPI2 SP 要件を直接アサート）・`test/helpers/`、`deploy/conformance/` 一式（Layer 2：OpenID Conformance Suite ハーネス、`run-conformance.sh` の EXPECTED_NONPASS、`drive-browser.mjs`） |
| **インフラ（そのまま）** | `.github/workflows/`（CI / conformance）、`deploy/helm/`、`.devcontainer/`、`scripts/`、`Dockerfile` |
| **要件・設計文書（そのまま）** | `docs/REQUIREMENTS-P1.md`（要件 ID はコード・コミットから引用継続）、`docs/SPECS.md`、`docs/GOALS.md`、`docs/TODO.md` |
| **参照実装** | 現行実装（main）。細部挙動（エラー写像、リダイレクト規約、DPoP nonce 発行タイミング等）の照合用として parity 達成まで保持。緊急修正は現行実装に当て、v2 に転記 |
| **移植候補コード** | `src/crypto/` の jose ラッパ構造（ただし発行 alg の単一固定は解いて移植） |

### 継承する設計知見（現行実装で実証済みのパターン）

- **port + adapters + config enum 選択 + fail-closed 既定**：`PolicyDecisionPoint`（`PDP_KIND`）、Storage ports（`STORAGE`）、`AuthenticationProvider` で実証済み。v2 の全拡張点をこの形に統一する。
- **原子性はポート契約に押し込む**：authorization code の redeem、`request_uri` の consume、`jti` replay 登録は「atomic な一回性」をポートのメソッド契約として定義し、memory / pg 両実装に同一のポート契約テストを当てる。
- **PAR の peek / consume 分離**：ページロードでは消費せず、authorization action 時に消費（FAPI2-AUTHZ-15）。
- **enforcement-bearing metadata**：広告する値（discovery）は必ず対応する enforcement を持つ。config 集合 → プロファイル天井と交差 → 検証点で enforcement、の一方向フロー。
- **本番 fail-fast ガード**：dev 用設定（dev ログイン・弱い秘密・非 TLS 等）は `NODE_ENV=production` で起動失敗させる。
- **consent 画面の CSP**：consent フォームの 303 はクライアントの cross-origin redirect_uri へ向かうため、consent ページの CSP `form-action` に当該 redirect_uri origin を許可する（global の `form-action 'self'` のみだと browser がリダイレクトを阻止。CLAUDE.md 記載）。

## 2. 受入契約（parity の定義）— v2 が守る外形

Layer 1 / Layer 2 資産を無改変で使い続けるため、v2 は以下を維持する：

1. `src/index.ts` が `buildApp()` をエクスポートし、`STORAGE=memory` で DB 不要起動できる（`test/helpers/` が参照する補助エクスポートも同様）。
2. エンドポイントパス・env 変数名（`ISSUER` / `STORAGE` / `PDP_KIND` / TTL 群 / `METADATA_*` / `DEV_*` / `SESSION_SECRET` 等）は現行互換。変更が必要な場合はテスト側修正を同一スライスで行い、**アサーション（要件）には触れない**。Layer 1 のアサーション変更は要件変更としてレビューで明示ブロックする。
3. dev ログイン・consent 画面は `drive-browser.mjs` がドライブできるフォーム構造を維持（変更時はハーネス修正を同一スライスで）。
4. **parity 判定 = Layer 1 20/20 green ＋ Layer 2 プラン overall=PASS（55 モジュール中 49 PASS / 1 SKIP / 5 想定 non-pass）＋ unit カバレッジ 80%**。

## 3. アーキテクチャ — 能力の 4 層交差モデル × feature module

### 3.1 4 層交差モデル（オプション整合の中核）

オプションの整合性は都度の if 文ではなく、**宣言された集合の交差**として一元検証する：

```
L1 サーバー能力   ：feature module 群が登録した選択肢の全集合（コードと同居する宣言）
L2 デプロイポリシー：運用者が有効化した部分集合。PROFILE（fapi2-sp 等）の述語と交差し、矛盾は起動失敗
L3 クライアント登録：クライアントが選んだ部分集合。登録時（seed / DCR）に L1∩L2 内であることを検証
L4 リクエスト     ：実行時に L3 内であることを検証
```

- **Discovery metadata は L1∩L2 から自動導出**する。手書きリテラルは存在させない。能力が空のキー（例：JAR 未搭載時の `request_parameter_supported`）は出力しない規約とし、feature 追加で自動的に現れるようにする。
- **プロファイルは L2 上の述語**：`fapi2-sp` は「response_type=code のみ / PAR 必須 / PKCE S256 必須 / sender-constraining 必須 / client auth ∈ {private_key_jwt, mTLS} / alg ∈ {PS256, ES256, EdDSA} / RT ローテーションなし / code 寿命 ≤60s / confidential client のみ」等を宣言。プロファイル追加（`fapi2-ms`、dev 用 `baseline`）は述語の追加であり、コード分岐は増やさない。
- 仕様上任意（MAY）の点はオプション化し、**既定は最も厳しい側**。緩和は L2/L3 の明示オプトインのみ。「クライアント設定として保存されるが実挙動では無視される」フィールドを作らない — 保存する設定は必ず L4 の enforcement に接続するか、受理しない。

### 3.2 feature module（機能 = 自己完結モジュール）

1 ディレクトリ = 1 仕様（RFC 単位）。各 feature は kernel のレジストラに対して以下を**寄与**する：

- capability 宣言（L1 への寄与）／ discovery metadata 断片
- クライアントメタデータのスキーマ断片（L3 検証。RFC 7591 スタイルのフィールド別エラー）
- 認可リクエストのパラメータバリデータ（L4。純関数、ctx に client と L1∩L2）
- provider 実装（該当する場合）：`ClientAuthenticator` / `SenderConstraintMethod` / `GrantTypeHandler` / `AccessTokenFormat` / `ClaimsProvider` / `ResponseMode`
- ルート（エンドポイント）／ ストレージ集約（port + memory/pg 実装）／ 起動時自己検査

```
src/
  kernel/                 # プロトコル非依存の核
    config/               #   zod config + PROFILE 述語 + L1∩L2 解決（fail-fast）
    registry/             #   feature 登録先（capabilities / validators / providers / routes / metadata）
    http/                 #   Fastify 配線・EndpointDeps・エラー写像（RFC 6749 エラー規約）
    storage/              #   port 基盤 + memory/pg アダプタ枠（集約は feature が寄与）
    crypto/               #   jose ラッパ（発行 alg 可変・複数鍵種 keystore）
  features/
    oauth-core/           # RFC 6749: token EP 骨格・authorization_code / refresh_token ハンドラ
    pkce/                 # RFC 7636
    par/                  # RFC 9126（request_uri は peek/consume 分離、パラメータ保存は構造化 JSON）
    dpop/                 # RFC 9449（SenderConstraintMethod: jkt / server nonce）
    private-key-jwt/      # RFC 7521/7523（ClientAuthenticator）
    jwt-access-token/     # RFC 9068（AccessTokenFormat）
    oidc/                 # ID token / userinfo / discovery 寄与 / scope→claims マッピング
    iss-response/         # RFC 9207
    introspection/        # RFC 7662（cnf 出力は SenderConstraintMethod 由来）
    revocation/           # RFC 7009
    interaction/          # ログイン/consent（AuthenticationProvider・AuthZEN PDP・grant 永続化）
    ...                   # 拡張フェーズ: resource / rar / dcr / jar / jarm / mtls / grant-management
  profiles/
    fapi2-sp.ts           # プロファイル述語（必須 feature / 制約）
    baseline.ts           # dev/テスト用の緩和プロファイル（本番ガードで禁止）
```

設計上の先行判断（後続 migration を減らすため初回スキーマに織り込む）：

- **PAR / 認可リクエストのパラメータ保存は構造化 JSON**（平坦な `Record<string,string>` にしない）。RAR の `authorization_details` 配列や `claims` オブジェクトをそのまま保持できる形。
- **grant / consent は (subject, client) の consent 再利用を前提に設計**：`findActiveBySubjectClient` による consent スキップ判定（PDP へは「既存 grant あり」を context で通知）、grant 失効カスケード、将来の Grant Management `grant_id` を見越した形。
- **クライアントモデルは DCR 前提フィールド**（`client_id_issued_at` / registration access token ハッシュ / `software_id` 等、nullable）を初回から持つ。メタデータ検証は seed と DCR で共用できる形（フィールド別 `invalid_client_metadata`）にする。
- kernel は feature を知らない。feature 間依存は capability 経由（例：`fapi2-sp` 述語が par / dpop / pkce の capability 存在を要求）。
- provider port を切るのは「2 つ目の実装が §4 の表に載っているもの」に限定する（抽象化過剰の抑止）。それ以外は関数分割まで。

### 3.3 リポジトリ運用

- **同一リポジトリ・単一ソースツリー**。v2 ブランチ（bookmark）上で `src/` を新実装に置き換え、parity 達成 PR 群を経て main へ。並走ディレクトリ（`src2/` 等）は作らない — 受入契約（§2）が `src/` への import を前提としており、二重維持のコストに見合わない。
- parity までは v2 ブランチの Layer 1 が RED から始まり段階的に green 化していく。進捗は Layer 1 の消化率（n/20）で可視化する。

## 4. フェーズ計画

各フェーズ共通 DoD：typecheck / unit green、対象スライスの Layer 1 ケース green 化、`/code-review`・`/security-review` C/H/M=0、要件 ID をコード・コミットから引用。

### V0 — kernel と歩く骨格（walking skeleton）

- kernel（config / PROFILE 述語 / L1∩L2 解決、registry、http、storage 枠、crypto）。
- feature ゼロ個でも起動し、`/healthz` と「能力から自動導出された（ほぼ空の）discovery」を返す。
- 起動時 fail-fast（プロファイル矛盾・本番ガード）のテスト。**オプション整合テストの規約**（「discovery に広告される値は必ず対応する enforcement テストを持つ」）をここで導入し、以降の feature 追加ごとに行を増やす。
- 完了条件：skeleton が k3s / Helm で起動、CI green（Layer 1 は RED のまま = 想定内）。

### V1 — コアフロー（parity への最短路）

依存順に独立スライス化（docs/DEVELOPMENT.md の並行開発方式で Issue 化）：

1. **V1a**：oauth-core + pkce + interaction（dev ログイン + consent + PDP）+ oidc 最小 — `baseline` プロファイルで code フロー成立。
2. **V1b**：private-key-jwt + par + dpop + iss-response + jwt-access-token — `fapi2-sp` プロファイル述語を satisfy。
3. **V1c**：introspection + revocation + userinfo + refresh。
4. **V1d**：pg アダプタ（memory と同一のポート契約テストを両バックエンドで実行）、seed、migration。

- 完了条件（**M-parity**）：§2 の受入契約充足 ＋ 性能回帰確認（1vCPU / 800Mi で `/token` p95 < 50ms — レジストリ間接化のオーバーヘッド検証。ホットパスは起動時に解決済みハンドラを直接参照させ、リクエスト毎のレジストリ探索をしない）。
- parity 達成で main へマージ。ARCHITECTURE.md を v2 構成へ全面更新、CLAUDE.md の運用差分（PROFILE 等）を反映。**ここまでが本計画のコミットメント**。

### V2+ — 拡張機能（parity 後、1 機能 = 1 REQUIREMENTS 文書 = 1 ブランチ）

着手前に対象仕様＋関連仕様を読み `docs/REQUIREMENTS-<機能>.md` に要件 ID 化（NFR 含む）→ 詳細計画で人間と合意 → TDD 実装 → Layer 1 変種テスト追加 → Layer 2 既存プラン green 維持（可能なら変種プラン追加）、の順で進める（CLAUDE.md「FAPI 実装方針」）。

| 順 | 機能 | 主仕様 | v2 での実装形 |
|---|---|---|---|
| E1 | `resource` + クライアント別オプション実効化 | RFC 8707 | パラメータバリデータ + AT `aud` 絞り込み。4 層モデルの最小実証 |
| E2 | **RAR** | RFC 9396 | `rar/` feature：type 別スキーマ registry、PAR 構造化保存 → grant 永続化 → AT/introspection 反映 → consent 表示、PDP へ details 連携、`authorization_details_types_supported` 自動広告 |
| E3 | **DCR** | RFC 7591/7592 | `dcr/` feature：`/register` + 管理 EP（GET/PUT/DELETE、registration access token）。FAPI 運用では admin 登録が通例のため**既定 off**（L2 オプトイン）。レート制限・監査ログ必須 |
| E4 | **JAR** | RFC 9101 | `jar/` feature：`request` / `request_uri` バリデータ実装（クライアント鍵で検証）、`require_signed_request_object` を L3 に。PAR + JAR の組合せ整合（RFC 9126 §3）に注意 |
| E5 | **JARM** | JARM (OIDF) | `jarm/` feature：ResponseMode provider。`fapi2-ms`（Message Signing）述語の一部として |
| E6 | **mTLS** | RFC 8705 | `mtls/` feature：ClientAuthenticator（`tls_client_auth` / `self_signed_tls_client_auth`）+ SenderConstraintMethod（`x5t#S256`）+ `mtls_endpoint_aliases`。TLS 終端（Ingress / 別ポート）のデプロイ設計含む |
| E7 | Grant Management + トークン管理 | FAPI-GM / RFC 7662 | `grant-management/` feature（`grant_id` / `grant_management_action`）+ 管理 API（admin 認証境界で一覧・失効：ユーザー別 / クライアント別） |

順序の根拠：E1 は最小差分で 4 層モデルの配線を検証する。E2 は「リクエスト表現の拡張」、E3 は「クライアント表現の拡張」で、v2 骨格の 2 大拡張軸を早期に本番検証する。E6 はコードよりデプロイ設計が重いため独立。E4 以降は需要で入替可（着手前に人間と合意）。

## 5. 非機能要件の割付（CLAUDE.md §2 / docs/TODO.md）

| NFR | 割付 |
|---|---|
| FAPI プロファイル選択（profile / sender-constraining / client auth 切替） | V0（PROFILE 骨格）→ E6 で実質複数化 |
| トークン管理（一覧・失効・introspection 連携） | E7 |
| 鍵管理・ローテーション | V0 crypto（発行 alg 可変・複数鍵種 keystore・ローテーション API 足場）+ E7 管理面 |
| 監査ログ | V1（発行・失効・consent の監査イベント設計を初回から）→ E3 で登録系を追加。永続化先分離は TODO.md 継続 |
| レート制限 | V1（in-process fixed-window）→ E3 で `/register` 強化。分散化は TODO.md（P4 系）継続 |
| 性能（100RPS / 1vCPU / 800MB、`/token` p95 < 50ms） | M-parity の DoD に回帰計測を含め、以降の各 E フェーズ DoD にも含める |

## 6. リスクと対策

| リスク | 対策 |
|---|---|
| 抽象化過剰（使わない port の維持コスト） | port は「2 つ目の実装が §4 の表に載っているもの」に限定。V0 レビューで port 一覧を人間と確認 |
| parity 未達のまま長期化 | Layer 1 の RED→green 消化率（n/20）で進捗を可視化。現行実装（main）との挙動照合を V1 各スライスのレビュー観点に含める |
| 受入資産への「テストを実装に合わせる」改変 | Layer 1 アサーション変更は要件変更としてレビューで明示ブロック（PR の確認項目化）。パス・env 互換は §2 契約で固定 |
| 性能退行（registry 間接化） | M-parity で計測。ホットパスは起動時解決（§4 V1 完了条件） |
| 広告と挙動の乖離の再発 | discovery は L1∩L2 からの自動導出のみ（手書き禁止）。オプション整合テスト規約（V0）で CI が乖離を検出。「保存されるが無視される」クライアント設定を作らない（§3.1） |

## 7. マイルストーン

1. **M-V0**：kernel + skeleton 起動、整合テスト規約導入、CI green。
2. **M-parity**：Layer 1 20/20 + Layer 2 overall=PASS + unit 80% + 性能回帰なし。main へマージ、ARCHITECTURE.md / CLAUDE.md 更新。
3. **M-E1〜E7**：§4 の表の順に、各機能着手前に REQUIREMENTS 文書 + 詳細計画で人間と合意。

## 8. セッションの始め方（実装者向け）

1. 本書と CLAUDE.md、docs/GOALS.md / SPECS.md / REQUIREMENTS-P1.md / AGENT_GUIDE.md / DEVELOPMENT.md を読む。
2. 現在のマイルストーン（§7）を確認し、対応する GitHub Issue（自己完結ブリーフ、`.github/ISSUE_TEMPLATE/slice.md`）を取る。なければ本書 §4 のスライス定義から Issue を起こす。
3. 1 セッション = 1 jj workspace = 1 bookmark。実装は TDD、完了前にレビューループ（`/code-review` → `/security-review`、C/H/M=0）と該当 Layer 1 ケースの green 化を確認する。
