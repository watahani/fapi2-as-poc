# CLAUDE.md — FAPI 2.0 認可サーバー v2

このリポジトリで作業する際の統治ドキュメント。仕組み（jj / レビューループ / CI ループ / conformance）の構築・変更に追従して**継続的に更新する**こと。

プロジェクト概要・設計は [docs/GOALS.md](docs/GOALS.md) / [docs/PLAN.md](docs/PLAN.md) / [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) / [docs/SPECS.md](docs/SPECS.md) を参照。要約：**OpenID Conformance Suite の FAPI 2.0 SP / Message Signing 両プランを全バリアントで green にできる、設定を管理 API で外部注入可能な認可サーバーをスクラッチ実装**（既存 OAuth/OIDC ライブラリ不使用、許容は jose/Fastify/pg/zod/pino）。

## v1 参照実装

- 前身は [watahani/fapi2-as-poc](https://github.com/watahani/fapi2-as-poc)（archive・参照専用）。プロトコルの葉ロジックと細部挙動の照合には **docs/ASSETS.md 記載の固定コミット**を参照する。
- **v1 の計画文書・git log・PR 履歴は参照しない**（本リポジトリの docs が正）。v1 への修正・push は行わない。

## バージョン管理: jj (Jujutsu)

- **git ではなく jj を使う**（`.git` とコロケート運用。手順は docs/AGENT_GUIDE.md）。
- Conventional Commits（`feat:` / `fix:` / `chore:` / `docs:` / `test:` / `refactor:`）を `jj describe -m` で付与。
- **main への直接 push 禁止**。bookmark（=ブランチ）を切って `jj git push` → PR 経由でマージ。
- jj は git の `commit.gpgsign` を読まず既定で無署名（pinentry ハング回避）。

## 開発環境

- 全作業は **Claude Code Docker サンドボックス内**（ホスト FS/認証情報は非マウント、egress は許可リストのみ）。
- **egress ドメインを追加する時は `.devcontainer/init-firewall.sh`（権威）と `.devcontainer/managed-settings.json` の両方を更新**し、`scripts/check-allowlist-sync.sh`（CI でも検査）を通す。
- ローカル k8s は in-sandbox k3s（単体・DinD なし・privileged、**`--snapshotter=fuse-overlayfs` 必須**）。イメージは nerdctl ビルド → `ctr import`。起動中 k3s は再起動不可（sudo 制約）なので誤起動時はコンテナ rebuild。
- インストール済みスキル：`backend-patterns` / `coding-standards` / `tdd-workflow` / `security-review`（`.claude/skills/`）＋ superpowers 全14スキル（lock は `skills-lock.json`、更新は `npx skills update`）。
  - **設計フロー**：実装前に `brainstorming` → `writing-plans` → `executing-plans` / `subagent-driven-development` → `verification-before-completion`。
  - superpowers と既存レビューループが矛盾する場合は本 CLAUDE.md のレビューループが優先。
- **コンテナ内作業の実務ガイド：[docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md)** を必ず参照。
- **分散・並行開発：[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)**。1 セッション = 1 jj workspace = 1 bookmark。コンテキストは GitHub Issue（自己完結ブリーフ、`.github/ISSUE_TEMPLATE/slice.md`）に置く。hot files（kernel/config・kernel/registry・`CLAUDE.md`・`README.md`）は小さく先にマージ。
- **認証の永続化**：`~/.claude` と `~/.config/gh` は名前付きボリュームで rebuild 越しに保持。

### GitHub 認証（基本 PAT 不要）

- **git / jj push = SSH エージェント転送**（VS Code が `SSH_AUTH_SOCK` を自動転送）。リモートは SSH URL。
- **gh CLI / PR API**：`gh auth login`（device flow）を 1 回、`~/.config/gh` 永続化で保持。
- **GHCR（conformance suite prebuilt イメージ）**：パッケージの pull 権限を本リポジトリに付与済みであること（docs/ASSETS.md の移設手順参照）。

## FAPI 実装方針（最重要）

**Source of Trust = 仕様**（[docs/SPECS.md](docs/SPECS.md)）。FAPI 機能を実装する前に、必ず次を順守する：

1. **対象仕様と関連仕様をすべて読む**。
2. **要件をすべて列挙する**（当該仕様 + 関連仕様 + 非機能要件）。要件は `docs/REQUIREMENTS-<機能>.md` に ID 化し、テスト・コード・コミットから引用する。
3. **プランを作成**（EnterPlanMode で合意）→ 承認後に実装。仕様で一意に決まらない点は人間と相談。
4. プロトコルは自前実装。コード/コミットに**該当 RFC のセクションを引用**して根拠を追跡可能にする。
5. **4 層交差モデルを迂回しない**（docs/PLAN.md §3）：discovery は L1∩L2 から自動導出（手書きリテラル禁止、CI の grep lint で検査）。広告する値は必ず対応する enforcement テストを持つ。「保存されるが無視される」設定を作らない。バリデータ・provider の合成は kernel の合成契約（PLAN §3.4）に従う。

## レビュー ループ（コード変更ごとに必須）

変更を記録（`jj describe`/commit）する前に、以下を**反復**する：

1. `/code-review`（code-reviewer）で品質・バグをレビュー → 指摘を修正。
2. `/security-review`（security-reviewer）でセキュリティをレビュー → 修正。
3. **Critical / High / Medium が 0 になるまで再レビュー**（Low は許容、ただし安価なら潰す）。
4. 新機能・バグ修正は `tdd-workflow`（テストファースト・カバレッジ 80%）で進める。

## CI ループ

- すべての push / PR で **`.github/workflows/ci.yml`**：typecheck / test / **Layer 1 conformance ラチェット** / 本番依存 audit ゲート / SBOM / helm lint・template / allowlist 同期 / アプリイメージ build smoke。
- **FAPI conformance は 2 レイヤ**：
  - **Layer 1（in-repo・常時実行・Docker 不要）**：`npm run test:conformance`。AS を `buildApp()`（`STORAGE=memory`）で起動し HTTP で叩く黒箱テスト。**ラチェット方式**：`test/conformance/passing.json` に列挙済みのケースが fail しても、未列挙のケースが pass しても CI が落ちる（昇格は green ログ添付の PR で行う）。アサーションの変更は要件変更としてレビューで明示ブロック。
  - **Layer 2（external・`workflow_dispatch` で gated）**：OpenID Conformance Suite を外部から当てる。**対象プラン×バリアントは `deploy/conformance/plans/*.json` にデータ化**（variant・AS 側 L2 設定・クライアント・`EXPECTED_NONPASS` 理由付き・status）。実行サイクルは「管理 API で設定注入 → AS 再起動 → プラン実行」。CI = `conformance.yml`（compose）、サンドボックス = `deploy/conformance/run-local.sh`（k3s、artifact を `ctr import`）。
  - **Suite は毎回ビルドしない**：`conformance-image.yml` が pin 版をビルドし GHCR へ push → pull/import のみ。
  - consent フォームの 303 は cross-origin redirect_uri へ向かうため、consent ページの CSP `form-action` に当該 origin を許可する（v1 で実証済みの落とし穴）。
- **CI が赤なら緑になるまで修正を反復**。進捗はラチェット（passing.json）と plans/ 消化率で可視化する。

## このファイルの保守

jj / レビューループ / CI / conformance / 管理 API の仕組みを変更したら、**本 CLAUDE.md を必ず更新**すること（仕組みと記述の乖離を作らない）。
