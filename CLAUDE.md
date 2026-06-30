# CLAUDE.md — FAPI 2.0 認可サーバー PoC

このリポジトリで作業する際の統治ドキュメント。仕組み（jj / レビューループ / CI ループ / conformance）の構築・変更に追従して**継続的に更新する**こと。

プロジェクト概要・設計は [docs/GOALS.md](docs/GOALS.md) / [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) / [docs/SPECS.md](docs/SPECS.md) / [HANDOVER.md](HANDOVER.md) を参照。要約：**FAPI 2.0 Security Profile 準拠の認可サーバーをスクラッチ実装**（既存 OAuth/OIDC ライブラリ不使用、許容は jose/Fastify/pg/zod/pino）。

## バージョン管理: jj (Jujutsu)

- **git ではなく jj を使う**（`.git` とコロケート運用。手順は HANDOVER §4）。
- Conventional Commits（`feat:` / `fix:` / `chore:` / `docs:` / `test:` / `refactor:`）を `jj describe -m` で付与。
- **main への直接 push 禁止**。bookmark（=ブランチ）を切って `jj git push` → PR 経由でマージ。
- jj は git の `commit.gpgsign` を読まず既定で無署名（過去の pinentry ハングを回避）。

## 開発環境

- 全作業は **Claude Code Docker サンドボックス内**（ホスト FS/認証情報は非マウント、egress は許可リストのみ）。
- **egress ドメインを追加する時は `.devcontainer/init-firewall.sh`（権威）と `.devcontainer/managed-settings.json` の両方を更新**し、`scripts/check-allowlist-sync.sh`（CI でも検査）を通す。
- ローカル k8s は in-sandbox k3s（単体・DinD なし・privileged）。イメージは nerdctl ビルド → `ctr import`。
- インストール済みスキル：`backend-patterns` / `coding-standards` / `tdd-workflow` / `security-review`（`.claude/skills/`）。
- **認証の永続化**：`~/.claude`（Claude）と `~/.config/gh`（gh）は名前付きボリュームで rebuild 越しに保持（Dockerfile で node 所有を担保）。

### GitHub 認証（基本 PAT 不要）

- **git / jj push = SSH エージェント転送**（VS Code が `SSH_AUTH_SOCK` をコンテナへ自動転送）。ホスト秘密鍵はコンテナに入らない。リモートは SSH URL（`git@github.com:...`）。github の host key はイメージに事前信頼済み。
- **gh CLI / PR API**：`gh auth login`（device flow）を1回。`~/.config/gh` 永続化で保持。
- **GHCR（conformance prebuilt）**：イメージは **public** 前提で pull 認証不要。
- PAT は HTTPS git / device login 回避 / GHCR private pull が必要な時のみ（fine-grained PAT を `GH_TOKEN`、コミット禁止）。

## FAPI 実装方針（最重要）

**Source of Trust = 仕様**（[docs/SPECS.md](docs/SPECS.md)）。FAPI 機能を実装する前に、必ず次を順守する：

1. **対象仕様と関連仕様をすべて読む**（FAPI 2.0 SP / Attacker Model、RFC 6749/6750/7636/9126/9449/7521/7523/7515-7519/9068/9207/8414/7662/7009/9101、OIDC Core/Discovery、AuthZEN）。
2. **要件をすべて列挙する**：当該仕様の要件 + 関連仕様の要件 + **非機能要件**。非機能要件には少なくとも以下を検討する：
   - トークンの**ローテーションを行う UI**／管理機能
   - **FAPI Security Profile の選択機能**（プロファイル / sender-constraining(DPoP·mTLS) / クライアント認証方式の切替）
   - **トークン管理機能**（発行済みトークンの一覧・失効・introspection 連携）
   - 鍵管理・ローテーション、監査ログ、レート制限、性能目標（1vCPU/800MB/100RPS）
3. **プランを作成**（EnterPlanMode で合意）→ 承認後に実装。仕様で一意に決まらない点・設計判断は人間と相談。
4. プロトコルは自前実装（外部 OAuth ライブラリ不使用）。コード/コミットに**該当 RFC のセクションを引用**して根拠を追跡可能にする。

## レビュー ループ（コード変更ごとに必須）

変更を記録（`jj describe`/commit）する前に、以下を**反復**する：

1. `/code-review`（code-reviewer）で品質・バグをレビュー → 指摘を修正。
2. `/security-review`（security-reviewer）でセキュリティをレビュー → 修正。
3. **Critical / High / Medium が 0 になるまで再レビュー**（Low は許容、ただし安価なら潰す）。
4. 新機能・バグ修正は `tdd-workflow`（テストファースト・カバレッジ 80%）で進める。

## CI ループ

- すべての push / PR で **`.github/workflows/ci.yml`**：typecheck / test / 本番依存 audit ゲート / SBOM / helm lint・template / allowlist 同期 / アプリイメージ build smoke。
- **FAPI conformance は 2 レイヤ**（ハーネス `deploy/conformance/`、ワークフロー `conformance.yml`、いずれも `workflow_dispatch` で gated）：
  - **Layer 1（in-repo・常時実行可・Docker 不要）**：`npm run test:conformance`（`vitest.conformance.config.ts` / `test/conformance/`）。AS を `buildApp()` で起動し HTTP で叩いて FAPI2 SP 要件を直接アサート。仕様要件を実行可能テストに落とした高速層で、**P1 エンドポイント未実装の間は red**（TDD ベースライン）。default の `npm test` からは除外（緑ゲートを赤にしない）。
  - **Layer 2（external・P3 で本有効化）**：**AS をサービス起動 → OpenID Conformance Suite を外部から当てる**（参考は [eudiplo](https://github.com/openwallet-foundation/eudiplo) の e2e/conformance CI 構成のみ）。FAPI 2.0 SP + DPoP + private_key_jwt のプランを回す。
    - **Suite は毎回ビルドしない**：`conformance-image.yml`（たまに実行）で一度ビルドし GHCR(public) に publish → **CI もローカルも pull だけ**。
    - 実行：**ローカル（サンドボックスは Docker 無し）= `deploy/conformance/run-local.sh`（k3s に apply）**、**CI = `conformance.yml`（compose で pull&up）**。
    - sandbox 実走は (a) docker 無し / (b) suite イメージ GHCR 未publish / (c) ビルド元 gitlab.com が egress 許可リスト外、により **P3（イメージ publish 後）まで保留**。
- **CI が赤なら緑になるまで修正を反復**（CI ループ）。conformance green を P0 一行ゴールの達成条件とする。

## このファイルの保守

jj / レビューループ / CI / conformance の仕組みを変更したら、**本 CLAUDE.md を必ず更新**すること（仕組みと記述の乖離を作らない）。
