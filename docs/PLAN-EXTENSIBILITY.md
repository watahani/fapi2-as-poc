# 拡張性再設計計画 — 「テストを通す実装」から「オプションを矛盾なく実装できる AS」へ

> 状態：**計画（未着手）**。P3 完了（Layer 2 conformance overall=PASS）後の再設計フェーズの統治ドキュメント。
> 前提資料：[ARCHITECTURE.md](./ARCHITECTURE.md) / [REQUIREMENTS-P1.md](./REQUIREMENTS-P1.md) / [TODO.md](./TODO.md) / [DEVELOPMENT.md](./DEVELOPMENT.md)。
> 本計画の実行は CLAUDE.md の統治（レビューループ / CI ループ / TDD / 1 スライス = 1 Issue = 1 bookmark）に従う。

## 0. 一行ゴール

**単一プロファイル（FAPI2 SP + DPoP + private_key_jwt + PAR 固定）の縦穴実装を、「サーバー能力 → デプロイ設定 → クライアント登録 → リクエスト」の 4 層で能力を交差検証するメタデータ駆動アーキテクチャに再編し、RAR / DCR / JAR / JARM / mTLS 等を conformance green を維持したまま追加可能にする。**

## 1. 背景 — 何が「テストを通すだけ」なのか

P1–P3 で FAPI 2.0 SP conformance（Layer 1: 20/20、Layer 2: overall=PASS）は達成した。しかし実装監査（2026-07-20、本計画の付録 A に全文相当の要約）の結論は次の通り：

- **レイヤ構造は健全**：endpoints（薄い）→ domain（プロトコル）→ db ports の分離、PAR の peek/consume 分離、原子性をポート契約に押し込んだストレージ設計は再利用に足る。
- **しかしプロトコルオプションはほぼ全て単値固定**：`z.literal("code")`、`z.literal("private_key_jwt")`、`z.literal("ES256")`、`token_type: "DPoP"` リテラル、`switch (grantType)`、`request` パラメータの明示的拒否…。「選択肢が 1 つしかないので矛盾も起きない」状態であり、選択肢を増やした瞬間に整合性を保つ仕組みがない。
- **discovery だけ config 化しても挙動は変わらない**：#33 で `METADATA_*` 環境変数 → FAPI2 天井との交差 → 検証時 enforcement という **enforcement-bearing パターン**が確立されたが、適用されたのはクライアント認証 alg と DPoP alg の 2 系統のみ。`response_types_supported` / `grant_types_supported` / `require_pushed_authorization_requests` 等は依然ビルダー内リテラル。
- **クライアント別設定は「保存されるが無視される」**：`require_pushed_authorization_requests` は保存されるが PAR はグローバル強制。`dpop_bound_access_tokens: false` は登録できるが実行時に拒否される。**広告（metadata）・登録（client）・挙動（enforcement）の三者一致が構造的に保証されていない**。

このままの構造で RAR / DCR / mTLS を「もう一本の縦穴」として掘ると、オプションの組合せごとに整合性バグ（広告と挙動の乖離、プロファイル違反の組合せ受理）が積み上がる。**機能追加の前に、オプションを表現・交差・検証する基盤を作る**のが本計画である。

## 2. 現状評価（監査サマリ）

凡例：**[RIGID]** 単値固定・拡張阻害 / **[PARTIAL]** 構造はあるが不完全 / **[GOOD]** 既に拡張可能。

| # | 領域 | 評価 | 根拠（file:line） |
|---|---|---|---|
| 1 | response_type | RIGID | `src/domain/authz-request.ts:26,89-91`・`src/domain/clients.ts:33`・`src/endpoints/discovery.ts:34` すべて `"code"` リテラル |
| 2 | grant type ディスパッチ | PARTIAL | `src/endpoints/token.ts:69-80` の閉じた `switch`。ハンドラレジストリなし |
| 3 | クライアント認証 | RIGID | `src/domain/client-auth.ts:53-201` が private_key_jwt 一枚岩。`token_endpoint_auth_method` によるディスパッチなし。`config.ts:301` 固定 |
| 4 | sender-constraining | RIGID | DPoP が発行（`tokens.ts:28,54-56`）・token EP（`token.ts:54-62`）・RS（`userinfo.ts:38-57`）に直書き。mTLS/`x5t#S256` は不在 |
| 5 | 署名 alg | 検証 PARTIAL / 発行 RIGID | 検証は config∩FAPI2 天井（`crypto/jws.ts:16,77-81`）で良好。発行は ES256 固定（`crypto/keys.ts:177,234-238`、`types.ts:14`） |
| 6 | scope / claims | PARTIAL | `METADATA_SCOPES/CLAIMS_SUPPORTED` はあるが、scope→claim マッピングなし・`claims_supported` は飾り（ID token/UserInfo は固定クレームのみ `tokens.ts:89-101`、`userinfo.ts:78`） |
| 7 | response_mode / JARM | RIGID（不在） | `response_mode` 未パース。query リダイレクトのみ（`endpoints/redirect.ts`） |
| 8 | クライアントモデル | PARTIAL | `clients.ts:16-45` はフィールドの意図は正しいが中身が literal。DCR 用フィールド（registration_access_token 等）・`Client` 形状（`clients.ts:67-71`）・DB 列が不足 |
| 9 | DCR | RIGID（不在） | `/register` なし（`endpoints/index.ts:46-114`）。seed スクリプトのみ |
| 10 | 認可リクエスト検証 | PARTIAL | `validateAuthorizationRequest`（`authz-request.ts:66-191`）約 125 行の一枚岩。ただし PAR/authorize/interaction で正しく共有され、`passthrough`（`:38,43-52`）は拡張の継ぎ目になる |
| 11 | RAR | RIGID（不在） | `authorization_details` はどこにもない |
| 12 | JAR | RIGID（明示拒否） | `authz-request.ts:71-74` で `request` パラメータを拒否 |
| 13 | AT フォーマット | RIGID | JWT (RFC 9068) 固定（`tokens.ts:37-73`）。introspection/revocation も JWT 前提（`token-lookup.ts:28-46`） |
| 14 | grant / consent | PARTIAL | `GrantRecord` は認可単位で永続化・失効カスケードあり（良い土台）。しかし (subject, client) の consent 再利用・一覧・Grant Management なし。毎回 consent 画面 |
| 15 | discovery | PARTIAL | #33 パターンは正しいが 2 系統のみ。`config.ts:298-304` の固定リテラルと `discovery.ts:34-35,53,55` の直書きが残存 |
| 16 | プロファイル選択 | RIGID（不在） | `PROFILE` に相当する設定なし。プロファイルはコード全体に暗黙に散在 |
| 17 | 既存の拡張点 | GOOD | `PolicyDecisionPoint`＋adapters＋`PDP_KIND`、`Storage` ports＋`STORAGE`、`AuthenticationProvider`。**これが複製すべき参照パターン** |

## 3. 設計原則

### 3.1 参照パターンの全域展開

既存の 3 つの成功例（PDP / Storage / AuthenticationProvider）に共通する形を、新設するすべての拡張点に適用する：

> **狭い TS インターフェイス（port） → `adapters/` に具象実装 → `config.ts` の zod enum で選択 → `EndpointDeps` 経由で注入 → fail-closed 既定**

### 3.2 能力の 4 層交差モデル（本計画の中核）

オプションの整合性は「都度 if 文」ではなく、**宣言された集合の交差**として一元的に検証する：

```
L1 サーバー能力   ：コードが実装している選択肢の全集合（実装と同居する capability レジストリで宣言）
L2 デプロイポリシー：運用者が有効化した部分集合。プロファイル（FAPI2 SP 等）が課す制約と交差し、起動時に矛盾を fail-fast
L3 クライアント登録：クライアントが選んだ部分集合。登録時（seed / DCR）に L1∩L2 の範囲内であることを検証
L4 リクエスト     ：実行時に L3 の範囲内であることを検証
```

- **Discovery metadata は L1∩L2 から自動導出**する（手書きリテラル全廃）。広告＝能力が構造的に一致する。
- **プロファイルは L2 上の述語**として実装する：`FAPI2-SP` プロファイルは「response_type は code のみ / PAR 必須 / sender-constraining 必須 / client auth は private_key_jwt か mTLS / alg は PS256·ES256·EdDSA / RT ローテーションなし / code 寿命 ≤60s …」を宣言し、起動時に L2 全体へ課す。将来 `FAPI2-MS`（Message Signing）や非 FAPI の `BASELINE` を追加してもコード分岐は増えず、述語が増えるだけ。
- これは #33 の enforcement-bearing パターン（config 集合 → 天井と交差 → 検証点で enforcement）の一般化である。

### 3.3 その他の原則

- **挙動を変えるリファクタと機能追加を同一 PR に混ぜない**。基盤再編（フェーズ R）は外形挙動不変で、Layer 1 conformance 20/20 と unit green を維持したまま行う。
- **Source of Trust = 仕様**（CLAUDE.md）。各機能フェーズは着手前に対象 RFC の要件を `docs/REQUIREMENTS-<機能>.md` に ID 化し、テスト・コードから引用する（REQUIREMENTS-P1.md と同じ運用）。
- **仕様上任意（MAY/OPTIONAL）の点はオプション化し、既定は FAPI2 SP の最も厳しい側に倒す**。緩和は L2/L3 での明示的なオプトインのみ。
- **conformance は「変種プラン」で守る**：オプションを増やすたびに、(a) Layer 1 に当該オプション有効時のテストを追加し、(b) Layer 2 は既存プラン green 維持 + 可能なら変種プラン（例: mTLS 版 FAPI2 SP プラン）を追加する。

## 4. フェーズ R — 基盤再設計（機能追加の前提・挙動不変）

各項目は独立スライスとして Issue 化し並行可能（依存は明記）。**完了条件は共通**：typecheck / unit / Layer 1 conformance 20/20 green、`/code-review`・`/security-review` で C/H/M = 0。

### R1. Capability レジストリとプロファイルポリシー（最優先・他の受け皿）

- `src/capabilities.ts`（新設）：サーバー能力（L1）を単一の型付きオブジェクトで宣言 — `responseTypes`, `grantTypes`, `clientAuthMethods`, `senderConstraints`, `signingAlgs(issuance/verification 別)`, `responseModes`, `requestObjectSupport`, `authorizationDetailTypes`, `codeChallengeMethods`, `subjectTypes` など。
- `src/profile.ts`（新設）：`Profile` インターフェイス（L2 への制約述語 + 既定値）。第一弾は `fapi2-sp` のみ。`config.ts` に `PROFILE`（zod enum、既定 `fapi2-sp`）を追加し、`loadConfig` 内で L1∩L2∩profile を解決・矛盾は起動失敗（既存の本番ガード `config.ts:170-206` と同じ fail-fast 慣性）。
- `config.ts:298-304` の固定リテラル（`subjectTypesSupported` / `idTokenSigningAlgs` / `clientAuthMethods` / `codeChallengeMethods`）を解決済み L2 へ置換。
- 解決結果（`ResolvedCapabilities`）を `EndpointDeps` に載せ、以降の R2–R7 の enforcement の単一ソースにする。

### R2. Discovery の自動導出（R1 依存）

- `buildMetadata`（`discovery.ts:20-59`）を `ResolvedCapabilities` からの純関数に書き換え。直書きリテラル（`response_types_supported`、`grant_types_supported`、`require_pushed_authorization_requests`、`authorization_response_iss_parameter_supported`）を撤去。
- 将来キー（`response_modes_supported` / `authorization_details_types_supported` / `request_parameter_supported` / `mtls_endpoint_aliases` 等）は能力が空なら出力しない規約にし、機能フェーズで能力を足すと自動で現れるようにする。
- テスト：**「discovery に広告される値はすべて対応する enforcement テストを持つ」**ことを Layer 1 に反映（広告と挙動の一致をテストで固定）。

### R3. クライアント認証のストラテジ化

- `src/domain/client-auth/`：`ClientAuthenticator` port（`method` 識別子 + `authenticate(req, client) → AuthenticatedClient`）に分割し、`token_endpoint_auth_method` でディスパッチ。第一弾アダプタは既存ロジックを移植した `private-key-jwt.ts` のみ（挙動不変）。
- `clients.ts:22` の `z.literal("private_key_jwt")` を「L1∩L2 に含まれる方式の enum」検証へ。`jwks/jwks_uri` 必須制約（`clients.ts:61-63`）は「JWT 系認証方式を選んだ場合のみ必須」に条件化（mTLS 受け入れ準備）。
- PAR・token・revoke・introspect の認証呼び出しを port 経由に統一。

### R4. Sender-constraining のポート化

- `SenderConstraintMethod` port（`dpop` / 将来 `mtls`）：proof/証明書の検証、`cnf` クレームの生成（`jkt` / `x5t#S256`）、RS 側（userinfo）の所持証明検証、introspection の `cnf` 出力までを 1 つの責務境界に。
- `TokenIssuanceInput.cnfJkt`（`tokens.ts:16-18`）を `cnf: SenderConstraintBinding` に一般化。`token_type` リテラル（`tokens.ts:28`）を method 由来に。
- `dpop_bound_access_tokens` 等のクライアント設定を L3 として尊重（ただし L2 が FAPI2-SP の間は「非拘束トークン」は選べない＝プロファイル述語が拒否。ここで 4 層モデルの整合性が初めて実挙動になる）。

### R5. 認可リクエスト検証のパイプライン化

- `validateAuthorizationRequest`（`authz-request.ts:66-191`）を **パラメータバリデータのレジストリ + 順次適用**に再編。各バリデータは `(raw, ctx) → 検証済み値 | エラー` の純関数で、`ctx` に client（L3）と capabilities（L1∩L2）を持つ。
- `ValidatedAuthorizationRequest` を拡張可能な形（コア必須項目 + 型付き拡張スロット）にし、`ParRequestRecord.params: Record<string,string>`（`types.ts:47`）を **構造化 JSON 値**を保持できるよう migration（RAR の `authorization_details` 配列や `claims` オブジェクトの ad-hoc 文字列詰めを回避）。
- `request` パラメータ拒否（`authz-request.ts:71-74`）は「capability に JAR がなければ拒否」に置換（挙動不変、E4 の差し込み口）。

### R6. トークン発行の分解

- `GrantTypeHandler` port + レジストリで `token.ts:69-80` の `switch` を置換（`authorization_code` / `refresh_token` を移植、挙動不変）。
- `AccessTokenFormat` port（第一弾 `jwt` (RFC 9068) のみ）。`token-lookup.ts` の JWT 前提をフォーマット port 経由に。将来の opaque AT / introspection 専用 RS 構成の受け皿。
- `ClaimsProvider` port：AT / ID token / UserInfo のクレーム組み立てを分離し、scope→claims マッピング（`profile` scope → 標準クレーム等）を定義可能に。`claims_supported` を「飾り」から実効に。RT ローテーション有無もプロファイル述語化（FAPI2-SP は「ローテーションなし」を宣言、`FAPI2-GEN-9`）。

### R7. クライアントモデルと grant モデルの拡張（DB migration を伴う）

- `Client` 形状（`clients.ts:67-71`）に DCR 前提フィールドを追加：`clientIdIssuedAt` / `registrationAccessTokenHash` / `registrationClientUri` / `softwareId` 等（nullable、seed 経路では未使用）。`clients` テーブルへ列追加 migration。
- `parseClientMetadata` を **RFC 7591 スタイルのフィールド別エラー**（`invalid_client_metadata` + どのフィールドか）を返す形に再編（seed と将来の DCR で共用）。
- `GrantRepository` に `findActiveBySubjectClient` / `list` を追加し、consent の再利用判定（同一 subject×client×scope ⊆ 既存 grant なら consent スキップ可、PDP へは「既存 grant あり」を context で通知）を interaction に実装。Grant Management API（FAPI-GM）の土台。

**フェーズ R の完了定義**：全 R マージ後、外形挙動が変わっていないこと（Layer 1 20/20・unit green・Layer 2 プラン overall=PASS を再実行して確認）。差分は「オプションが 1 つずつしかない capability レジストリが存在する」ことのみ。

## 5. フェーズ E — 機能拡張ロードマップ（フェーズ R 完了後）

各フェーズの共通手順（CLAUDE.md「FAPI 実装方針」準拠）：
1. 対象仕様 + 関連仕様を読み、`docs/REQUIREMENTS-<機能>.md` に要件 ID 化（NFR 含む）。
2. brainstorming → writing-plans で詳細計画 → 人間と合意。
3. TDD で実装（capability 追加 → discovery 自動反映 → enforcement テスト → Layer 1 変種テスト）。
4. レビュー ループ（C/H/M=0）→ Layer 2 回帰（既存プラン green 維持）。

| フェーズ | 内容 | 主仕様 | 主な touch 点（R 後） | 備考 |
|---|---|---|---|---|
| **E1** | クライアント別オプションの実効化 + `resource` | RFC 8707 | R4/R5 の L3 尊重、`resource` バリデータ、AT `aud` 絞り込み | TODO.md 既載の逸脱解消。最小で 4 層モデルを実証 |
| **E2** | **RAR** `authorization_details` | RFC 9396 | R5 バリデータ登録（type 別スキーマ registry）、PAR 構造化保存、grant への永続化、AT/introspection への反映、consent 画面表示、`authorization_details_types_supported` 自動広告 | FAPI2 SP との併用が本命。type 定義はプラガブルに（AuthZEN PDP へ details を渡し認可判断） |
| **E3** | **DCR** | RFC 7591 / 7592 | `/register`（POST）+ 管理（GET/PUT/DELETE, registration access token）、R7 のメタデータ検証・フィールドを利用、initial access token / open registration は L2 ポリシーで選択 | FAPI 現場では admin 登録が通例のため、**既定 off**（L2 で有効化）。レート制限・監査ログ必須 |
| **E4** | **JAR**（signed request object） | RFC 9101 | R5 の `request`/`request_uri` スロット実装、クライアント鍵で検証（`crypto/jws.ts` 再利用）、`require_signed_request_object` を L3 に | PAR + JAR の組合せ整合（RFC 9126 §3）に注意 |
| **E5** | **JARM** | JARM (OIDF) | 新 `ResponseMode` port（R2 で `response_modes_supported` 自動広告）、`authorization_signing_alg_values_supported` | FAPI2 Message Signing プロファイル（`FAPI2-MS` 述語追加）の一部として |
| **E6** | **mTLS** | RFC 8705 | R3 に `tls_client_auth` / `self_signed_tls_client_auth` アダプタ、R4 に `x5t#S256` binding、`mtls_endpoint_aliases`、TLS 終端（k8s Ingress/エンドポイント別ポート）設計 | インフラ影響が最大のため後置。conformance の mTLS 変種プランで検証 |
| **E7** | Grant Management + トークン管理 | FAPI Grant Management / RFC 7662 連携 | R7 の grant 基盤に `grant_id` / `grant_management_action`、管理 API（一覧・失効：ユーザー別/クライアント別）、TODO.md「トークン管理機能」 | NFR（CLAUDE.md §2）の本丸。管理 API は別認証境界（admin）で |

順序の根拠：E1 は最小差分で 4 層モデルの配線を検証する肩慣らし。E2（RAR）は R5 の設計が正しいかを最初に本気で試す機能で、DCR より先に置くことで「リクエスト表現の拡張」と「クライアント表現の拡張」を分離して検証できる。E6（mTLS)はコードよりデプロイ設計が重いので独立させる。E3 以降は相互依存が薄く、需要に応じて入れ替え可能。

## 6. 整合性を継続的に守る仕組み

- **オプション整合マトリクスのテスト化**：`test/conformance/` に「L2 で有効な全オプション組合せについて、discovery 広告 ⇔ 実挙動 ⇔ 拒否挙動」を確認するプロパティ的テスト群を追加（R2 で導入、以降フェーズごとに行を追加）。矛盾は CI で落ちる。
- **プロファイル述語のテスト**：`fapi2-sp` 選択時に非適合オプション（例: 非拘束トークン、RT ローテーション、`response_type=token`）が **設定・登録・実行のどの層でも**通らないことを層別にテスト。
- **REQUIREMENTS ドキュメントの分冊運用**：`REQUIREMENTS-P1.md` の形式を機能ごとに複製（`REQUIREMENTS-RAR.md` 等）。コード・コミットからは要件 ID を引用（既存運用の継続）。
- **conformance 変種プラン**：Layer 2 の実行対象プランを `deploy/conformance/` にデータとして列挙し、機能追加時に変種（例: JARM 付き、mTLS 版）を追記できる構造にする（現状の単一プラン前提を解く）。
- **CLAUDE.md / ARCHITECTURE.md の追従**：R1 完了時に 4 層モデルと capability レジストリを ARCHITECTURE.md へ、運用手順の変化（PROFILE 設定等）を CLAUDE.md へ反映。

## 7. 非機能要件との対応（CLAUDE.md §2 の列挙に対する割付）

| NFR | 対応フェーズ |
|---|---|
| FAPI プロファイル選択機能（プロファイル / sender-constraining / client auth 切替） | R1（選択の骨格）+ E6（mTLS で実質 2 択化） |
| トークン管理機能（一覧・失効・introspection 連携） | E7 |
| トークンローテーション UI / 管理機能 | E7（RT/grant 失効）+ TODO.md の鍵ローテーション運用化（管理 API トリガーを E7 の管理面に同居） |
| 鍵管理・ローテーション | R6（発行 alg の複数鍵種対応で keystore を単一 ES256 前提から解く）+ 既存 TODO |
| 監査ログ | E3（DCR は登録操作の監査必須）から段階導入、TODO.md の永続化設計と接続 |
| レート制限 | E3 で `/register` に per-client/per-IP 強化（既存 in-process 制限の拡張、分散化は P4 系 TODO のまま） |
| 性能目標（1vCPU/800MB/100RPS） | フェーズ R 完了時に回帰計測（ポート化のオーバーヘッドが p95 < 50ms を壊していないか）。以降は各 E フェーズの DoD に含める |

## 8. リスクと対策

| リスク | 対策 |
|---|---|
| 基盤リファクタで conformance を壊す | フェーズ R は挙動不変が DoD。R の各スライス完了ごとに Layer 1 実行、R 全体完了時に Layer 2 再実行 |
| 抽象化過剰（使わない port の維持コスト） | port は「2 つ目の実装が計画に載っているもの」に限定（本計画の E フェーズが根拠）。それ以外は関数分割まで |
| 4 層モデルの検証漏れ（層をバイパスする直接参照） | enforcement の入力を `ResolvedCapabilities` / `Client` に限定し、`config.metadata` への直接参照を lint（簡易 grep チェックを CI に追加）で禁止 |
| DB migration の非互換 | R5（PAR params 構造化）・R7（clients 列追加）は後方互換 migration（新列 nullable / JSON 値は旧形式を読める）とし、ロールバック手順を PR に明記 |
| スコープ膨張 | E フェーズは 1 機能 = 1 REQUIREMENTS 文書 = 独立ブランチ。E2 以降は着手前に人間と優先順位を再確認 |

## 9. マイルストーン

1. **M-R（基盤完了）**：R1–R7 マージ、外形挙動不変を Layer 1/2 で確認、ARCHITECTURE.md 更新。
2. **M-E1**：`resource` + クライアント別オプション実効化。4 層モデルが実挙動として機能。
3. **M-E2（RAR）**：FAPI2 SP + RAR で Layer 1 変種 green。
4. **M-E3（DCR）**：`/register` 一式 + 監査ログ + レート制限。
5. **M-E4/E5/E6/E7**：需要順（着手前に人間と合意）。

---

## 付録 A. 監査の要点（2026-07-20 実施、詳細は §2 の表）

- 複製すべき参照パターン：`src/authz/pdp.ts`（PDP port + adapters + `PDP_KIND`）、`src/db/repositories/types.ts`（Storage ports + `STORAGE`）、`src/domain/interaction.ts:30-32`（`AuthenticationProvider`）。
- 最高レバレッジの固定点：①`client-auth.ts` 一枚岩 → R3、②DPoP 直書き（発行/token EP/RS 横断） → R4、③`validateAuthorizationRequest` 一枚岩 + `request` 拒否 + PAR params 平坦文字列 → R5、④JWT 固定 + 固定クレーム → R6、⑤consent 再利用なし → R7、⑥discovery/config 残存リテラル → R1/R2。
- 既に良い点：PAR の peek/consume 分離、原子性のポート契約化、alg 検証の config∩天井パターン、grant 失効カスケード、本番 fail-fast ガード。
