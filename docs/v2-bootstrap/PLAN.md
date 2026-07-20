# v2 実装計画 — 全シナリオ対応・設定注入可能な FAPI 2.0 認可サーバー（新リポジトリ）

> 状態：**計画（ドラフト）**。本書は自己完結であり、実装セッションは **本書 + CLAUDE.md + GOALS.md + ASSETS.md +
> 移設 docs（SPECS / AGENT_GUIDE / DEVELOPMENT / REQUIREMENTS-P1）** のみを前提に開始できる。
> 本計画は v1 リポジトリの `docs/PLAN-V2.md`（fapi2-extensibility-plan-e5kpza ブランチ）を置き換える。

## 0. 一行ゴール

**[GOALS.md](./GOALS.md) §2 の全プラン×全バリアントを green にできる認可サーバーを、「機能 = 自己完結 feature module」「オプション = 4 層で交差検証される宣言」「デプロイポリシー = 管理 API で注入される永続データ」を骨格として新リポジトリに実装する。プロトコルの葉ロジックは v1 参照実装から移植し、conformance green の信号は Layer 1 ラチェットで初日から絶やさない。**

## 1. 経緯と設計判断（v1 との関係）

v1（[watahani/fapi2-as-poc](https://github.com/watahani/fapi2-as-poc)）は単一バリアント点で FAPI 2.0 SP
conformance overall=PASS を達成したが、次の理由で**骨格の新規実装**を選択する：

1. **設定の背骨が契約ごと変わる**：v1 の「env 変数 + 起動時 fail-fast」は、全シナリオ対応（プランごとの設定注入・将来の設定画面）が要求する「永続化された可変な L2 + 管理 API」と両立しない。config は全 enforcement 点を貫くため、リテラル置換で救える差分ではない。
2. **最終資産に占める v1 実装の比率が小さい**：全バリアント対応後の系に対し、v1 の縦穴（約 5,100 行）はオーケストレーション部分がほぼ全て置き換わる。生き残る価値は葉のプロトコルロジックに集中している。
3. **エージェント開発の文脈汚染を避ける**：v1 の git log / PR / 旧計画が新アーキテクチャの前提と混在すると、セッション開始時のコンテキストが汚れる。新リポジトリで履歴をゼロから作る。

ただし次の 2 点は**書き直しの失敗様式**として明示的に回避する：

- **葉は移植、再導出しない**：DPoP proof 検証・private_key_jwt 検証・PKCE・PAR の peek/consume・ストレージ原子性契約・crypto ラッパは欠陥密度が最も高い部分であり、v1 の実装とユニットテストをペアで移植する（§3.4）。v1 参照は**コミット固定**（ASSETS.md 記載）。
- **green 信号の空白を作らない**：受入資産（Layer 1 / Layer 2）は初日から新リポジトリに入れ、**ラチェット CI**（§2.1）で「通っているものが減らない」ことを常時ゲートする。v1 リポジトリへの緊急修正・二重保守は行わない（v1 は archive、参照専用）。

## 2. 受入資産と受入契約

### 2.1 Layer 1（in-repo・Docker 不要）— ラチェット方式

- v1 の `test/conformance/`（20 ケース、`buildApp()` への HTTP 黒箱）+ `test/helpers/` を無改変で移設。バリアント追加のたびにケース群を拡張する（例：mTLS 変種、plain_oauth 変種、JARM 変種）。
- **ラチェット**：`test/conformance/passing.json` にパス済みケース ID を列挙し、CI は
  (a) 列挙済みケースの fail、(b) 未列挙ケースの pass（昇格漏れ）の両方で落ちる。
  これにより実装ゼロの初日から CI は green で、進捗 = passing.json の単調増加としてレビュー可能になる。
- アサーション（要件）の変更は要件変更としてレビューで明示ブロック（v1 運用の継続）。要件 ID は `REQUIREMENTS-P1.md` を引用継続し、新機能は `REQUIREMENTS-<機能>.md` を追加。

### 2.2 Layer 2（external・OpenID Conformance Suite）— プランのデータ化

- v1 の `deploy/conformance/` 一式（run-conformance.sh / run-local.sh / drive-browser.mjs / compose / k8s）を移設。
- **単一プラン前提を解く**：`deploy/conformance/plans/<plan>-<variant>.json` に GOALS §2 の全組合せを列挙し、各ファイルが variant・クライアント設定・`EXPECTED_NONPASS`（理由付き）・status（active / pending）を持つ。`run-conformance.sh` は plan ファイルを引数に取る。
- **AS 側の設定注入**：各 plan ファイルは対応する **AS 設定（L2 スナップショット + クライアント登録）** を含み、ハーネスが管理 API 経由で注入 → AS 再起動 → プラン実行、を 1 サイクルとして自動化する（W2 で最初の 1 プラン、W3 で行列化）。
- suite イメージは v1 の `conformance-image.yml` 方式（pin 済みビルド → GHCR → pull/import のみ）を継承。**GHCR パッケージが v1 リポジトリに紐付いている点は移設時の要対応事項**（ASSETS.md）。

### 2.3 受入契約（外形）

1. `src/index.ts` が `buildApp()` をエクスポートし、`STORAGE=memory` + インライン設定で DB 不要起動できる（Layer 1 / test helpers の前提）。env 変数名は v1 互換を初期値とし、変更する場合はテスト側修正を同一スライスで行う（アサーションには触れない）。
2. dev ログイン・consent 画面は `drive-browser.mjs` がドライブできるフォーム構造を維持（変更時はハーネス修正を同一スライスで）。consent ページ CSP の `form-action` に redirect_uri origin を許可する v1 の知見を継承。
3. **マイルストーン判定はバリアント行列の消化数**（§7）。単一の parity 点ではなく「green 化済み plan ファイル数 / 全 plan ファイル数」を進捗 KPI とする。

## 3. アーキテクチャ

### 3.1 能力の 4 層交差モデル

```
L1 サーバー能力   ：feature module 群が登録した選択肢の全集合（コードと同居する宣言）
L2 デプロイポリシー：永続化された設定集約（DB）。管理 API で CRUD。PROFILE 述語と交差し、矛盾は起動失敗
L3 クライアント登録：クライアントが選んだ部分集合。登録時（管理 API / 将来 DCR）に L1∩L2 内であることを検証
L4 リクエスト     ：実行時に L3 内であることを検証
```

- **Discovery metadata は L1∩L2 から自動導出**。手書きリテラル禁止。能力が空のキーは出力しない。
- **プロファイルは L2 上の述語**：`fapi2-sp`（PAR 必須 / PKCE S256 / sender-constraining 必須 / client auth ∈ {private_key_jwt, mtls} / alg ∈ {PS256, ES256, EdDSA} / code 寿命 ≤60s / confidential のみ 等）、`fapi2-ms`（+ 署名リクエスト/レスポンス要件）、dev 用 `baseline`（本番ガードで禁止）。
- 仕様上任意（MAY）の点はオプション化し、**既定は最も厳しい側**。緩和は L2/L3 の明示オプトインのみ。「保存されるが無視される」設定を作らない — 保存する設定は L4 の enforcement に接続するか、受理しない。
- **広告 ⇔ enforcement の対テスト規約**：discovery に広告される値は必ず対応する enforcement テストを持つ（W0 で規約導入、feature 追加ごとに行を増やす）。`config` 直接参照の迂回は CI の grep lint で禁止。

### 3.2 L2 = 永続設定集約 + 管理 API（v2 の新規中核）

- **設定ソースは 2 系統を同一の集約に解決**：env / インライン（bootstrap・dev・Layer 1 テスト用）と DB（deployment・conformance 用）。起動時に L1∩L2∩profile を解決し、**不変スナップショット（ResolvedCapabilities）** としてメモリ常駐。ホットパスは解決済みハンドラを直接参照し、リクエスト毎のレジストリ・DB 探索をしない。
- **反映モデル**：当面「変更 → 検証 → 保存 → 再起動で反映」。管理 API は保存時に L1∩profile との交差検証を行い、矛盾する設定は保存自体を拒否（fail-closed）。無停止 hot-reload は M4 以降の独立マイルストーン（鍵・TLS の動的再構成を含むため、kernel の設定購読インターフェイスだけ先に切っておき、実装は後置）。
- **管理 API は別認証境界**：admin 認証（初期は静的トークン、将来社内認証基盤）・監査ログ・レート制限を W1 から必須。クライアント登録 CRUD も管理 API に含める（DCR はその外部公開形として後続）。
- **設定画面**は管理 API の上の薄い UI（M4）。API 契約が先。

### 3.3 feature module と kernel

1 ディレクトリ = 1 仕様（RFC 単位）。各 feature は kernel のレジストラへ capability 宣言 / discovery 断片 / クライアントメタデータスキーマ断片 / リクエストバリデータ / provider 実装 / ルート / ストレージ集約 / 起動時自己検査を**寄与**する。

```
src/
  kernel/
    config/        # 設定集約（env/DB ソース → L1∩L2∩profile 解決 → ResolvedCapabilities）
    admin/         # 管理 API（設定・クライアント CRUD、admin 認証境界、監査）
    registry/      # feature 登録先（capabilities / validators / providers / routes / metadata）
    http/          # Fastify 配線・エラー写像（RFC 6749 エラー規約）
    interaction/   # ログイン・consent・セッション（AuthenticationProvider / AuthZEN PDP / grant 永続化）
    storage/       # port 基盤 + memory/pg アダプタ枠（集約は feature が寄与）
    crypto/        # jose ラッパ（発行 alg 可変・複数鍵種 keystore・ローテーション足場）— v1 から移植・単一 alg 固定を解く
  features/
    oauth-core/ pkce/ par/ dpop/ private-key-jwt/ mtls/ jwt-access-token/
    oidc/ iss-response/ introspection/ revocation/ jar/ jarm/
    ...            # 拡張: resource / rar / dcr / grant-management
  profiles/
    fapi2-sp.ts fapi2-ms.ts baseline.ts
```

- **interaction は feature ではなく kernel サービス**とする（RFC 単位でなく、最大の非プロトコル塊。feature 扱いにすると kernel→feature 依存が滲む）。
- kernel は feature を知らない。feature 間依存は capability 経由（例：`fapi2-sp` 述語が par / pkce の capability 存在と sender-constraining ≥1 を要求）。
- provider port（`ClientAuthenticator` / `SenderConstraintMethod` / `GrantTypeHandler` / `AccessTokenFormat` / `ClaimsProvider` / `ResponseMode`）を切るのは 2 つ目の実装が本計画に載っているものに限る。mTLS・JARM が W3 で早期に 2 実装目を提供するため、v1 計画より port の検証時期が早い。W3 での port シグネチャ改訂は想定内とし、それまで磨き込まない。

### 3.4 合成契約（kernel が型で固定する規約）— 設計の最難所

プラグイン型 AS が壊れるのはバリデータ・provider の合成点である。以下を W1 で kernel の仕様として文書化・型化する：

1. **バリデータの適用順序**：登録順依存は禁止。明示的な優先度（フェーズ：構文 → クライアント解決 → 認証 → プロトコル制約 → プロファイル制約）で決定的に順序付ける。
2. **エラー優先順位**：複数バリデータが同時に失敗した場合にどの `error` / HTTP ステータスを返すかの規則（conformance suite は特定のエラーコードをアサートする）。redirect 可能エラーと不可エラー（client/redirect_uri 未検証時）の区別を kernel が持つ。
3. **feature 間の拒否権**：PAR×JAR の整合（RFC 9126 §3）、`fapi2-sp` 時の未知パラメータ・非対応パラメータの扱いを capability ベースで解決する（明示拒否のハードコードを残さない）。
4. **token エンドポイントのオーケストレーション順序**：grant 検証 → sender-constraint binding（cnf 決定） → claims 組み立て → フォーマット直列化・署名 → レスポンス組立（`token_type` は SenderConstraintMethod 由来）。この順序と各段の入出力型を kernel が固定し、feature は段に寄与する。

### 3.5 v1 からの移植資産（葉）

| 移植対象 | v1 位置 | 移植時の変更 |
|---|---|---|
| jose ラッパ・keystore | `src/crypto/` | 発行 alg の ES256 固定を解く（複数鍵種） |
| DPoP proof 検証・nonce | `src/domain/dpop.ts` | `SenderConstraintMethod` provider 化 |
| private_key_jwt 検証 | `src/domain/client-auth.ts` | `ClientAuthenticator` provider 化 |
| PKCE | `src/domain/pkce.ts` | ほぼ無改変 |
| PAR peek/consume・原子性契約 | `src/domain/par.ts`・`src/db/repositories/` | パラメータ保存を構造化 JSON 化（RAR 前提） |
| grant 失効カスケード | `src/domain/grant.ts` | (subject, client) consent 再利用を初回から設計 |
| エラー写像・本番 fail-fast ガード | `src/domain/errors.ts`・`src/config.ts` | kernel/http・kernel/config へ |
| 対応ユニットテスト | `test/` | 挙動アサーションを維持したまま移植（構造依存部のみ書換） |

クライアントモデルは DCR 前提フィールド（`client_id_issued_at` / registration access token ハッシュ / `software_id` 等、nullable）を初回スキーマから持ち、メタデータ検証は管理 API と将来の DCR で共用（RFC 7591 スタイルのフィールド別エラー）。

## 4. フェーズ計画

共通 DoD：typecheck / unit green、Layer 1 ラチェット更新（passing.json 単調増加）、`/code-review`・`/security-review` C/H/M=0、要件 ID をコード・コミットから引用。統治（TDD / 1 スライス = 1 Issue = 1 bookmark / hot files 先行マージ）は CLAUDE.md に従う。

### W0 — リポジトリ bootstrap + 受入資産移設

- ASSETS.md の手順で新リポジトリ作成、サンドボックス・CI・k3s・conformance ハーネス・skills を移設。
- Layer 1 ラチェット機構（passing.json、全ケース RED 登録 = CI green）と広告⇔enforcement 対テスト規約を導入。
- `deploy/conformance/plans/` に FAPI2 SP 8 バリアントの plan ファイル雛形（status=pending）を列挙。
- 完了条件（**M0**）：CI green、`run-local.sh` が suite を k3s で起動できる（AS なしでプラン作成失敗まで到達）。

### W1 — kernel（歩く骨格 + 設定集約 + 管理 API）

- kernel 一式（config / admin / registry / http / interaction 枠 / storage 枠 / crypto 移植）。§3.4 の合成契約を型と文書で固定。
- feature ゼロで起動し、`/healthz` と L1∩L2 導出の（ほぼ空の）discovery を返す。管理 API で L2 設定・クライアントを CRUD でき、矛盾設定は保存拒否・起動失敗（fail-fast）。
- 完了条件（**M1**）：skeleton が k3s / Helm で起動、管理 API 経由の設定注入 → 再起動 → discovery 反映が end-to-end で動く、CI green。

### W2 — 最初のバリアント点（v1 同等点の回復）

依存順に独立スライス化（DEVELOPMENT.md の並行開発方式で Issue 化）：

1. **W2a**：oauth-core + pkce + interaction 実装（dev ログイン + consent + PDP）+ oidc 最小 — `baseline` で code フロー成立。
2. **W2b**：private-key-jwt + par + dpop + iss-response + jwt-access-token — `fapi2-sp` 述語 satisfy。
3. **W2c**：introspection + revocation + userinfo + refresh。
4. **W2d**：pg アダプタ（memory と同一ポート契約テスト）、migration baseline、シード（管理 API 経由）。

- 完了条件（**M2**）：Layer 1 20/20（passing.json 完走）＋ plan `fapi2-sp × private_key_jwt × dpop × openid_connect` が設定注入込みの自動サイクルで overall=PASS ＋ unit 80% ＋ 性能回帰確認（`/token` p95 < 50ms — レジストリ間接化の検証）。

### W3 — バリアント行列の消化

行列の残り（優先順は影響範囲の大きい軸から）。各バリアントで Layer 1 変種ケース追加 → 実装 → plan ファイル active 化 → Layer 2 green、を 1 サイクルとする：

1. **W3a：mTLS**（RFC 8705）— `ClientAuthenticator`（tls_client_auth / self_signed）+ `SenderConstraintMethod`（`x5t#S256`）+ `mtls_endpoint_aliases` + TLS 終端デプロイ設計（k3s / Helm / suite 側 gen-certs 連携）。行列 8 点中 6 点がこれで開く。
2. **W3b：plain_oauth バリアント**（openid なし）— oidc 依存の分離検証。
3. **W3c：Message Signing プラン**— suite からバリアント軸を列挙して plans/ を確定 → JAR（RFC 9101、PAR×JAR 整合）→ JARM（`ResponseMode` provider、`fapi2-ms` 述語）。
4. **W3d**：suite が dynamic_client を要求する場合は DCR（RFC 7591/7592）をここで前倒し（既定 off・L2 オプトイン・レート制限・監査必須）。

- 完了条件（**M3**）：GOALS §2 の全 plan ファイルが active かつ green（想定 non-pass は理由付きデータのみ）。**ここまでが本計画のコミットメント**。

### W4+ — 拡張（1 機能 = 1 REQUIREMENTS 文書 = 1 ブランチ、着手前に人間と合意）

| 順 | 機能 | 主仕様 | 備考 |
|---|---|---|---|
| E1 | 設定画面（管理 API の薄い UI） | — | GOALS §4 の理想形。API は W1 で確立済み |
| E2 | hot-reload（無停止再構成） | — | 鍵・TLS 含む。kernel の設定購読 IF（W1）に実装を差す |
| E3 | resource indicator | RFC 8707 | 4 層モデルの最小拡張実証 |
| E4 | RAR | RFC 9396 | PAR 構造化保存（W2 で仕込み済み）→ grant → AT/introspection → consent 表示 |
| E5 | DCR（W3d で未実施の場合） | RFC 7591/7592 | |
| E6 | Grant Management + トークン管理 | FAPI-GM | 管理 API に一覧・失効（ユーザー別 / クライアント別） |
| E7 | 性能チューニング・負荷試験レポート | — | GOALS §5 の最終裏付け（必要なら Redis） |

## 5. 非機能要件の割付

| NFR | 割付 |
|---|---|
| FAPI プロファイル選択・オプション切替 | W1（L2 骨格）→ W3 で実質複数化 |
| 設定の外部注入・管理 API | W1（中核）。UI は E1、hot-reload は E2 |
| トークン管理（一覧・失効・introspection 連携） | E6 |
| 鍵管理・ローテーション | W1 crypto（複数鍵種・ローテーション足場）+ E6 管理面 |
| 監査ログ | W1（管理 API 操作 + 発行・失効・consent イベントを初回から） |
| レート制限 | W1（管理 API）+ W2（プロトコル EP、in-process fixed-window） |
| 性能（100RPS / 1vCPU / 800MB） | M2 の DoD に回帰計測、以降の各マイルストーン DoD にも含め、E7 で最終レポート |

## 6. リスクと対策

| リスク | 対策 |
|---|---|
| 葉の移植漏れ・劣化 | §3.5 の表を W2 各スライスのレビュー観点に固定。ユニットテストをペアで移植 |
| ラチェットの形骸化（passing.json の手抜き昇格） | 昇格 PR は当該ケースの green ログ添付を必須化（レビュー項目） |
| 合成契約の後決め（バリデータ順序・エラー優先） | W1 の DoD に §3.4 の文書 + 型 + テストを含める。W2 以降の変更は要 ADR |
| mTLS のデプロイ設計が重い | W3a を独立スライス群に分割（TLS 終端 → client auth → sender constrain → aliases）。suite 側は gen-certs.sh 資産を流用 |
| MS プランのバリアント軸が想定と違う | W3c 冒頭で suite API から列挙して plans/ を確定してから実装（先に確定、後に実装） |
| 管理 API 起点の設定破壊 | 保存時交差検証で矛盾拒否（fail-closed）・プロファイル床以下の緩和不可・監査ログ・admin 認証境界 |
| GHCR パッケージ権限（v1 リポジトリ紐付き） | ASSETS.md の移設手順で先に解決（W0 ブロッカー） |
| 抽象化過剰 | port は 2 実装目が本計画に載るものに限定。W1 レビューで port 一覧を人間と確認 |

## 7. マイルストーン

| M | 内容 | KPI |
|---|---|---|
| M0 | bootstrap 完了・受入資産移設・CI green | plans/ 列挙完了 |
| M1 | kernel + 管理 API 経由の設定注入が end-to-end | — |
| M2 | 最初のバリアント点 green（v1 同等点の回復） | Layer 1 20/20・plan 1/8+ |
| M3 | **全プラン×全バリアント green（コミットメント境界）** | plan 消化率 100% |
| M4+ | 設定画面 / hot-reload / RAR / GM / 性能レポート | 着手前に個別合意 |

## 8. セッションの始め方（実装者向け）

1. 本書と CLAUDE.md / GOALS.md / SPECS.md / REQUIREMENTS-P1.md / AGENT_GUIDE.md / DEVELOPMENT.md を読む。
2. 現在のマイルストーン（§7）と `deploy/conformance/plans/` の消化状況を確認し、対応する GitHub Issue（自己完結ブリーフ）を取る。なければ本書 §4 のスライス定義から Issue を起こす。
3. 1 セッション = 1 jj workspace = 1 bookmark。TDD、完了前にレビューループ（C/H/M=0）と Layer 1 ラチェット更新を確認。
4. v1 参照実装を見る場合は ASSETS.md 記載の**固定コミット**を参照する（v1 の計画文書・git log は参照しない）。
