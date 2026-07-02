# AGENT GUIDE — コンテナ内エージェント運用マニュアル

devcontainer 内で作業する Claude Code エージェント向けの実務ガイド。**環境固有の落とし穴**と**正しい手順**を集約（これまでの試行錯誤の結晶）。設計は [GOALS](GOALS.md)/[ARCHITECTURE](ARCHITECTURE.md)/[SPECS](SPECS.md)、統治は [CLAUDE.md](../CLAUDE.md)。

## まず知るべき環境前提

- ここは **Claude Code の Docker サンドボックス**。ホスト FS/認証情報は非マウント。**egress は許可リストのみ**（許可外への通信は失敗する）。
- **`sudo` は制限付き**：`k3s` / `nerdctl` / `ctr` / `init-firewall.sh` のみ NOPASSWD。**`sudo apt` 等の一般 sudo は不可**（パスワード要求で失敗）。ツール追加は Dockerfile を直して rebuild。
- **永続化されるもの**：`~/.claude`（Claude 認証）・`~/.config/gh`（gh 認証）は名前付きボリューム。`~/.claude.json`（アカウント紐付け `oauthAccount`/`userID`）はホーム直下＝ボリューム外なので、**postStart で `~/.claude/claude.json` への symlink** にして永続化している（これが無いと token が残っても未ログイン扱いになる）。

## バージョン管理：jj（git ではない）

- **`jj` を使う**（`.git` とコロケート）。git 直コマンドで履歴を作らない。
- git は **2.41+ 必須**（jj 要件。ベースは `node:24-trixie`。古いと `jj git fetch` が `porcelain` で落ちる）。
- push は **SSH エージェント転送**（リモートは `git@github.com:...`）。**main 直 push 禁止** → bookmark 作成 → `jj git push` → PR。
- 例：`jj st` / `jj describe -m "feat: ..."` / `jj new` / `jj bookmark create <name> -r @` / `jj git push --bookmark <name>`。
- jj は gpgsign を読まず無署名（pinentry ハング回避）。

## Docker は無い → k3s + nerdctl

- **`docker` デーモンは無い**（DinD 不採用）。`docker` コマンドを叩かない。
- イメージビルドは **`nerdctl build`**（buildkit）。k3s へは **`sudo k3s ctr images import`**（`scripts/dev-cluster.sh import <img>` が `nerdctl save | ctr import` を実行）。
- ローカル k8s は **k3s 単体**：`bash scripts/dev-cluster.sh up`。起動に必要な sandbox 固有の回避策は dev-cluster.sh に集約済み：
  - **`--snapshotter=fuse-overlayfs` 必須**（overlayfs-on-overlayfs 不可。素の k3s ではノード未登録）。
  - **cgroup v2 回避（2段階・両方必須）**：
    - kubelet 側：`--kubelet-arg=cgroups-per-qos=false --kubelet-arg=enforce-node-allocatable=`（無いとノード未登録＝`cannot enter cgroupv2 "/sys/fs/cgroup/kubepods" ...`）。`dev-cluster.sh` 反映済み。
    - runc/containerd 側：ルート cgroup にプロセスが居て `memory`/`io` 未 delegate だと Pod sandbox 作成が `cannot enter cgroupv2 "/sys/fs/cgroup/k8s.io" -- invalid state` で失敗。**root で起動時に cgroup nesting**（全プロセスを `init` leaf へ退避→全 controller を delegate）が必要。`.devcontainer/k3s-cgroup-init.sh` を postStart で **k3s 起動前**に `sudo` 実行（`node` では root 所有プロセスを移動できず不可）。
  - **k3s システムイメージは airgap で焼き込み済み**（Dockerfile が `/var/lib/rancher/k3s/agent/images/` に投入）。これが無いと Pod sandbox 作成時に docker.io から pull できず `FailedCreatePodSandBox`。
  - **docker.io 由来イメージ（postgres/mongo 等）の blob** は CloudFront（`production.cloudfront.docker.com`）配信＝許可リストに追加済み。ただし CloudFront は IP 変動が大きく不安定なので、頻発するなら ctr import（airgap）に寄せる。
  - **起動中の k3s は再起動できない**（root 所有・`sudo pkill` 不可）。**誤った起動をしたら諦めてコンテナ rebuild**。なお走行中 k3s がある状態で `init-firewall.sh` を再適用すると iptables を flush して pod 通信を壊すので不可。
  - kubeconfig は dev-cluster.sh が書き出す。手で見るなら `sudo k3s kubectl ...`（`sudo cat /etc/rancher/k3s/k3s.yaml` はパスワード要求で不可）。

## GitHub / レジストリ

- **gh**：`gh auth login`（device flow）。`~/.config/gh` 永続化済み。
- **GHCR の conformance イメージは現状 private**（gh トークンに packages スコープ無し）。ローカル k3s では **pull せず、CI の artifact を import**：`gh run download <run-id> -n conformance-suite-images` → `sudo k3s ctr images import`（`deploy/conformance/k8s/suite.yaml` 参照）。CI は `GITHUB_TOKEN` で pull 可。

## egress 許可リストの変更手順

許可ドメインを足すときは **3点セット**：
1. `.devcontainer/init-firewall.sh` の `ALLOWED_DOMAINS`（権威）。必須なら `REQUIRED_DOMAINS` にも。
2. `.devcontainer/managed-settings.json` の `allowedDomains`（同期必須）。
3. `bash scripts/check-allowlist-sync.sh` で一致確認（CI でも検査）。
- firewall は postStart で root 適用。**セッション中の再適用は sudo 制約で困難** → 反映は rebuild。

## アプリ（FAPI2 AS）

- コマンド：`npm run typecheck` / `npm test`（health スモーク）/ `npm run dev` / `npm run migrate`（tsx・`migrations/*.sql`）。
- `/health`=liveness（DB 不要）、`/healthz`=readiness（DB ping）。
- **本番ガード注意**：本番イメージは `NODE_ENV=production`。この時 `PDP_KIND=mock` / localhost issuer / dev `DATABASE_URL` は **起動時に拒否**される（`src/config.ts`）。本番モードで起動/スモークするときは有効な設定を渡す。
- スクラッチ実装：許容ライブラリは jose/Fastify/pg/zod/pino のみ。OAuth/OIDC/FAPI ロジックは自前（`src/domain` `src/crypto` `src/endpoints`）。**仕様を読んでから実装**（[SPECS.md](SPECS.md)、CLAUDE.md「FAPI 実装方針」）。

## Conformance テスト

- **ローカル**：`bash deploy/conformance/run-local.sh`（k3s に suite を apply → port-forward → プラン実行）。
- **CI**：`conformance.yml`（compose で prebuilt 起動）。Suite は `conformance-image.yml` がたまにビルドして GHCR/artifact 化。
- **現状 red が正**（P1 のエンドポイント未実装のため）。green 化が P1 のゴール。

## レビュー / CI ループ（変更時）

- 記録（`jj describe`）前に **`/code-review` → 修正 → `/security-review` → 修正** を Critical/High/Medium=0 まで反復。新機能は `tdd-workflow`（テストファースト）。
- push 後 CI（`ci.yml`）が赤なら**緑になるまで反復**。

## 困ったときの第一手

- jj fetch が porcelain で落ちる → 古い git。`jj config set --repo git.subprocess false` で一時回避、恒久は trixie ベースで rebuild。
- k3s が Ready にならない → snapshotter（fuse-overlayfs）か、誤起動 → **rebuild**。
- 通信が失敗する → egress 許可リスト未登録を疑う（上記3点セット）。
- リビルドで Claude 認証が消える → `~/.claude.json` がボリューム外（symlink が外れている）か、ボリューム所有権が root か。`~/.claude.json -> ~/.claude/claude.json` の symlink と node 所有を確認。gh は `~/.config/gh` 配下が全部ボリュームなので `gh auth login` し直せば永続。
- `claude update` が権限エラー → claude は **node 所有の `/home/node/.npm-global`**（`NPM_CONFIG_PREFIX`）にインストールされる（Dockerfile）。`/usr/local` への root install だと node が更新できず EACCES。**リビルドしても新版にならない**のは `npm i -g …@latest` レイヤの Docker キャッシュ由来 → 「Rebuild Without Cache」でベイク更新、または起動後に `claude update`（現在は動く）。`/home/node/.npm-global` はボリュームではないので、runtime 更新はリビルドでベイク版へ戻る（永続したい場合は当該ディレクトリをボリューム化）。
