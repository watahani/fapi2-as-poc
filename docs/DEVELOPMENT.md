# DEVELOPMENT.md — 分散・並行開発の進め方

**目的**：1 セッション（1 会話）で直列に開発を続けるのをやめ、**独立したスライスを複数のセッション/エージェントが並行**して進められるようにする。コンテキストは会話ではなく **Issue とドキュメント**に置き、各作業を自己完結させる。

このドキュメントは「仕組み」なので、変更したら CLAUDE.md の保守ルールに従い追従更新する。関連：[HANDOVER.md](../HANDOVER.md) / [AGENT_GUIDE.md](AGENT_GUIDE.md) / [GOALS.md](GOALS.md) / [TODO.md](TODO.md)。

---

## 0. なぜこのリポジトリは並行開発に向くか

- **明確なモジュール境界**（`src/{endpoints,domain,crypto,authz,db}`）— ファイル所有が分かれ、別スライスが同じ行を触りにくい。
- **差し替え可能インターフェイス**（`AuthenticationProvider` / `PolicyDecisionPoint` / `Storage` ポート）— 新機能の多くは**アダプタ追加**で完結し、既存コードをほぼ触らない。
- **独立した品質ゲート**（`bookmark → PR → squash`、CI: typecheck/test/audit/helm/allowlist/Layer1 conformance）— 各 PR が単独で正しさを担保するので、統合前提の密結合が要らない。

## 1. 作業の分解（独立スライス化）

作業は**モジュール境界とインターフェイスの継ぎ目に沿って**スライスする。1 スライス = 1 PR = 1 セッションで完結する粒度（数百行・レビュー可能）。判断基準：

- **触るファイル集合が他スライスと重ならないか**（重なる場合は §4 の hot-file 規律）。
- **既存インターフェイス背後のアダプタ追加**で閉じられるか（理想形）。
- **DoD が単独で検証可能**か（unit + 必要なら conformance モジュール）。

### 現バックログの分解（例）

| WS | 内容 | 主に触るファイル（所有） | 依存 | hot-file 接触 |
|----|------|------------------------|------|--------------|
| **WS-A** 社内認証アダプタ | `AuthenticationProvider` の実アダプタ + 注入切替 | `src/domain/interaction.ts`（新アダプタ）, `src/index.ts`(選択) | なし | `config.ts`(小) |
| **WS-B** FAPI mTLS プロファイル | mTLS sender-constraining(RFC8705)+`tls_client_auth`, conformance mtls variant | `src/domain/client-auth.ts`, `src/domain/dpop.ts`(分岐), `deploy/conformance/*` | なし | `config.ts`, `endpoints/{token,par}.ts` |
| **WS-C** トークン/鍵管理 | 発行済みトークン一覧/失効 API・UI、鍵ローテ運用化、logout | `src/endpoints/admin.ts`(新), `src/domain/token-lookup.ts`, `src/endpoints/views.ts` | Storage 拡張 | `endpoints/index.ts`, `db/repositories/*` |
| **WS-D** 本番前運用ゲート | KEYSTORE_KEK の KMS 化、secret ローテ猶予（二鍵）、監査ログ永続化、pg reaping Job | `src/crypto/keys.ts`, `deploy/helm/*`, `deploy/*` | なし | `config.ts` |
| **WS-E** RFC 8707 resource | AT `aud` をリソース別に絞る | `src/domain/{authz-request,tokens}.ts` | なし | 小 |

> 依存のあるスライス（例：WS-C は `Storage` に列を足す）は、**先に土台 PR**（ポート拡張 + migration）を小さく出してマージ → その上で機能 PR を並行、と段階化する。

## 2. 隔離（並行作業を物理的に分ける）

**1 セッション = 1 jj workspace = 1 bookmark**。同じ working copy を複数セッションで共有しない。

```bash
# 追加ワークスペースを作る（同一リポジトリ・別 working copy）
jj workspace add ../ws-authadapter        # WS-A 用
cd ../ws-authadapter
jj new main                               # main から作業コミットを開始
# …作業… → describe → bookmark create → jj git push → PR
jj workspace list                         # 稼働中ワークスペース一覧
jj workspace forget ../ws-authadapter     # 片付け（マージ後）
```

- **Claude Code エージェントで並行**：`Agent` ツールの `isolation: "worktree"`（各サブエージェントが独立 worktree で編集し衝突しない）、または人が複数セッションを別ワークスペースで開く。
- **`main` は常にリリース可能**を維持。各 WS は短命ブランチ、こまめに `jj rebase -d main` で追従。

## 3. 調整基盤（誰が何を進めているか）

**GitHub Issues を single source of truth に**する（会話ログに依存しない）。

- **Epic Issue**（方向 = WS 単位）＋ **子 Issue**（スライス = PR 単位）。
- **ラベル**：`area:auth` / `area:fapi` / `area:admin` / `area:ops` / `area:conformance` / `type:slice` / `type:epic`。
- **依存**：子 Issue 本文に `blocked by #NN`（土台 PR 待ち等）を明記。
- **着手時**：Issue を self-assign し、**draft PR を早期に開く**（進行中を可視化＝衝突の早期検知）。
- `docs/TODO.md` は**バックログ索引**として残し、各項目に Issue 番号を紐付ける（Issue = 実行、TODO = 台帳）。

## 4. hot files（衝突しやすい共有ファイル）の規律

以下は**横断的に触られる**ため、複数スライスが同時に編集すると衝突する：

- `src/config.ts`（新 env） / `src/endpoints/index.ts`（endpoint 登録・DI） / `src/db/repositories/{types,memory,pg}.ts`（ポート） / `docs/TODO.md` / `CLAUDE.md` / `README.md`

規律：

1. hot file への変更は**最小限**に切り出し、**小さな PR で最初にマージ**（他スライスが即 rebase して取り込む）。
2. 可能なら hot file を触らない設計にする（アダプタ追加・新規ファイルで閉じる）。
3. 同時に config を足す複数スライスがある場合は、**env キーの追加だけ**の土台 PR を先行させる。

## 5. マージ規律（コンフリクト最小化）

- **小さく・頻繁に**：1 PR = 1 スライス。長寿命ブランチを避ける。
- **rebase order**：hot file を触る PR ・土台 PR を先にマージ。機能 PR はその上で rebase。
- **`jj git fetch` → `jj rebase -d main`** を作業中こまめに。
- 各 PR は squash マージ・**main 直 push 禁止**（bookmark → PR）。

## 6. セッション自己完結ブリーフ（コンテキストを Issue に置く）

各 Issue（= スライス）は、**フルの会話コンテキストなしで新セッションが着手できる**だけの情報を持つ。テンプレは `.github/ISSUE_TEMPLATE/slice.md`：

- **対象仕様**：FAPI2 SP / 関連 RFC の**節番号**（CLAUDE.md「FAPI 実装方針」に従い先に精読）。
- **触るファイル**（所有）と **hot-file 接触**の有無。
- **DoD**：追加/変更する unit（TDD・80%）、必要な conformance モジュール、レビューループ（Critical/High/Medium=0）。
- **非機能要件**：CLAUDE.md §2 の該当項目。

新セッションの立ち上げ手順（定型）：
1. Issue を読む → self-assign。
2. `jj workspace add ../ws-<slug>` → `jj new main`。
3. 対象仕様の節を精読（`docs/SPECS.md`）→ 必要なら EnterPlanMode で合意。
4. TDD で実装 → `/code-review` + `/security-review` ループ → CI green。
5. `bookmark → PR`（Issue を close する `Closes #NN`）→ squash マージ。

## 7. 品質ゲート（分散でも品質を落とさない）

- **各 PR**：CI（typecheck/test/audit/helm/allowlist/build smoke）+ Layer 1 conformance が green。レビューループ必須。
- **conformance Layer 2** は重い（外部 suite）ので、機能マージ後に `conformance.yml`（dispatch）で回帰確認。プロファイル追加（WS-B）時は該当 variant を追加。
- **統合の健全性**：週次（または節目）で `main` に対し全 conformance を回し overall=PASS を確認。

---

## 付録：クイックリファレンス

```bash
jj workspace add ../ws-foo && cd ../ws-foo && jj new main   # 並行作業開始
jj describe -m "feat(WS-x): ..." && jj bookmark create feature/ws-x -r @ && jj git push --bookmark feature/ws-x
gh pr create --base main --head feature/ws-x --title "..." --body "Closes #NN"
jj git fetch && jj rebase -d main                            # 追従
jj workspace forget ../ws-foo                                # 片付け
```
