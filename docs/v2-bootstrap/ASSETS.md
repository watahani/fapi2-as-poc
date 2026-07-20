# ASSETS.md — v1 → v2 移設資産の一覧と bootstrap 手順

> v1 参照実装の**固定コミット**：`watahani/fapi2-as-poc@14ffa59f481a094e7e6270f9683e477c0a8d6881`（main, 2026-07-20 時点）。
> 以降 v1 を参照する場合は必ずこのコミットを指す（v1 は archive し、以後更新しない）。

## 1. 無改変で移設（実行環境・受入資産）

| 資産 | パス | 備考 |
|---|---|---|
| サンドボックス定義 | `.devcontainer/`（Dockerfile / devcontainer.json / init-firewall.sh / k3s-cgroup-init.sh / managed-settings.json） | egress 許可リストは init-firewall.sh が権威、managed-settings.json と同期必須 |
| 許可リスト同期検査 | `scripts/check-allowlist-sync.sh` | CI でも実行 |
| in-sandbox k3s | `scripts/dev-cluster.sh` | `--snapshotter=fuse-overlayfs` 修正済み版 |
| Layer 2 ハーネス | `deploy/conformance/`（run-conformance.sh / run-local.sh / drive-browser.mjs / docker-compose.yml / gen-certs.sh / k8s/ / conformance-client.json） | `test-config.json` は単一プラン前提 → `plans/*.json` へ再編（PLAN §2.2、W0） |
| Suite イメージビルド | `.github/workflows/conformance-image.yml` | upstream `release-v5.1.45` pin |
| Layer 1 conformance | `test/conformance/` + `test/helpers/` | 移設後にラチェット機構（passing.json）を追加。アサーションは無改変 |
| スキル | `.claude/skills/` / `.agents/skills/` / `skills-lock.json` | symlink 構造ごとコピー |
| 仕様・運用 docs | `docs/SPECS.md` / `docs/AGENT_GUIDE.md` / `docs/DEVELOPMENT.md` / `docs/REQUIREMENTS-P1.md` | 要件 ID は v2 でも引用継続 |
| Issue テンプレート | `.github/ISSUE_TEMPLATE/slice.md` | |

## 2. 改変して移設

| 資産 | 改変内容 |
|---|---|
| `docs/v2-bootstrap/{GOALS,PLAN,CLAUDE}.md`（本ドラフト） | 新リポジトリの `docs/GOALS.md` / `docs/PLAN.md` / ルート `CLAUDE.md` として配置 |
| `.github/workflows/ci.yml` | Layer 1 ステップをラチェット方式に変更（passing.json 照合）。他ステップ（typecheck / audit / SBOM / helm lint / allowlist / build smoke）は流用 |
| `.github/workflows/conformance.yml` | plan ファイル（`deploy/conformance/plans/*.json`）をパラメータ化。設定注入 → 再起動 → 実行のサイクル化（W2） |
| `Dockerfile` / `package.json` / `tsconfig` / vitest configs | 依存とビルドは流用、`src/` 構成（kernel/features/profiles）に合わせて調整 |
| `deploy/helm/auth-server/` | 骨格は流用。W3a で mTLS 終端（Ingress または別ポート）を追加 |
| `docs/TODO.md` | v2 スコープで棚卸し（済項目・v1 固有項目を落とす） |

## 3. 移設しない（参照専用）

| 資産 | 扱い |
|---|---|
| `src/`（v1 実装） | PLAN §3.5 の表に従い**葉ロジックのみ移植**（crypto / dpop / pkce / par / client-auth / grant / errors / 本番ガード）。固定コミットから引用 |
| `test/`（unit） | 移植する葉とペアで、挙動アサーションを維持して移植 |
| `docs/ARCHITECTURE.md`（v1） | v2 では W1 完了時に新規作成（4 層モデル + kernel/features 構成） |
| `docs/GOALS.md`（v1）/ PLAN 系ブランチ | 歴史資料。参照しない（CLAUDE.md に明記） |

## 4. Bootstrap 手順（W0）

```sh
# 1) 新リポジトリ作成（メモリ方針に従い private）
gh repo create watahani/fapi2-as --private --description "FAPI 2.0 authorization server — full conformance matrix, injectable configuration"

# 2) v1 固定コミットから移設資産を展開（§1/§2 のパスのみ）
git -C /workspace archive 14ffa59f -- \
  .devcontainer scripts deploy/conformance .github/workflows/conformance-image.yml \
  test/conformance test/helpers .claude .agents skills-lock.json \
  docs/SPECS.md docs/AGENT_GUIDE.md docs/DEVELOPMENT.md docs/REQUIREMENTS-P1.md \
  .github/ISSUE_TEMPLATE | tar -x -C <新リポジトリ作業ディレクトリ>

# 3) 本ドラフトを配置（docs/v2-bootstrap/ → CLAUDE.md はルート、他は docs/）
# 4) jj コロケート初期化・初期コミット・push（SSH リモート）
jj git init --colocate && jj describe -m "chore: bootstrap v2 from fapi2-as-poc@14ffa59f" && jj git push --allow-new
# 5) main の branch protection を設定（直接 push 禁止）
```

### 移設時の要対応事項（gotchas）

1. **GHCR パッケージ権限（W0 ブロッカー）**：`ghcr.io/watahani/conformance-suite-{server,httpd}` は private かつ v1 リポジトリに紐付いており、新リポジトリの `GITHUB_TOKEN` では pull できない。**対応：新リポジトリで `conformance-image.yml` を一度実行して自リポジトリ紐付きのパッケージを作り直す**（自己完結・推奨）。または既存パッケージの Actions access に新リポジトリを追加（UI 操作）。
2. **devcontainer 認証ボリュームは引き継がれない**：ボリューム名が `*-${devcontainerId}` のため、新リポジトリのコンテナでは `claude` / `gh auth login`（device flow）を各 1 回やり直す。SSH エージェント転送は設定不要。
3. **リポジトリ secrets は不要**：CI は `GITHUB_TOKEN` のみ使用（SESSION_SECRET はジョブ内生成）。
4. **`test-config.json` の再編**：単一プラン設定を `plans/fapi2-sp_pkjwt_dpop_oidc.json`（v1 実績バリアント、初期 status=active 候補）+ 残り 7 バリアント（status=pending）に分割。`EXPECTED_NONPASS` の 5 モジュールと理由は v1 の `run-conformance.sh` から転記。
5. **Layer 1 は移設直後 20 ケース全 RED**：ラチェット（passing.json = 空配列）を先に入れてから CI を有効化する（= CI は green で開始）。
6. **新リポジトリは private**：GHCR public 前提の記述（v1 CLAUDE.md）は引き継がない。conformance pull は `GITHUB_TOKEN` で行う。
