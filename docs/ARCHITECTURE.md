# アーキテクチャ

## 全体像（スクラッチ・プロトコルエンジン）

```
Fastify (HTTP 層・ルーティングのみ)              src/index.ts (buildApp)
   └─ src/endpoints/   OAuth/OIDC/FAPI エンドポイント（薄いハンドラ）
        └─ src/domain/   プロトコルロジック（自前 / Source of Trust = 仕様）
             │             grant, pkce, par, dpop, client-auth, token, fapi2 制約
             ├─ src/crypto/  jose ラッパ（JWS 署名/検証, JWK 管理, JWT 構築）
             ├─ src/authz/   AuthZEN PDP 境界（PEP→PDP, 差し替え可能 / mock）
             └─ src/db/      リポジトリ（生 SQL + pg）, 自前マイグレーションランナー
   └─ 認証委譲境界          認証コンポーネント interaction（P2）
PostgreSQL（一次ストア） / Redis（後付けキャッシュ, P4）
```

既存 OAuth/OIDC ライブラリは使わない。`jose` は JWS/JWK の署名・検証のみを担い、claim 検証・リプレイ・状態遷移などプロトコル上の判断は `src/domain` で自前実装する。

## 3つの分離

### 1. プロトコル ⇔ 認証
`/authorize` 処理中に認証が必要になったら認証コンポーネント（対話 interaction。deployment では `AuthenticationProvider` アダプタ経由で社内の別認証基盤）へ委譲。AS は認証結果（account id, acr, amr）のみ受領しトークン発行に専念。境界: 認証委譲（P2）。外部 IdP フェデレーションは対象外。

### 2. プロトコル ⇔ 認可判断
consent 可否・スコープ/claim 付与・リソースアクセス可否を **AuthZEN Authorization API (PDP)** に問い合わせる。AS は PEP。境界: `src/authz/pdp.ts`（`PolicyDecisionPoint`）。

### 3. PDP 実装の差し替え
`PolicyDecisionPoint` の背後に HTTP 実装（OPA/Topaz/Cedar）と in-process mock を差し替え可能に。設定 `PDP_KIND` で選択。

## ストレージ
- 短命状態（PAR request, authorization code, token, session, DPoP nonce）と client は **PostgreSQL** に保存。
- `src/db`：`pg` 接続プール（`pool.ts`）＋ 自前マイグレーションランナー（`migrate.ts`, `migrations/*.sql`）。ORM 不使用。
- TTL は期限列 + インデックスで自前管理。Redis は P4 で必要時に前段キャッシュとして導入。

## 開発環境 = Claude Code Docker サンドボックス

```
[ホスト] devcontainer 起動（workspace のみ bind, ホスト FS/creds 非マウント）
   └─ Claude Code サンドボックス（信頼境界）
        ├─ (B) init-firewall.sh : iptables + ipset で OUTPUT 既定 DROP → 許可IP/CIDR のみ ACCEPT
        ├─ (A) managed-settings.json : 組込み sandbox（FS で機微パス拒否, allowedDomains）＝多層防御
        └─ in-sandbox k3s（単体バイナリ + 内蔵 containerd, DinD なし, privileged）
              ├─ PostgreSQL（Helm: dev のみ）
              └─ AS（Helm chart, requests=limits cpu:1/memory:800Mi）
```

- 一次防御は **(B) の IP レベル egress 許可リスト**（ドメインフロンティング耐性）。許可ドメインは `.devcontainer/init-firewall.sh` 参照。
- ホスト Docker ソケット共有は「ホストリソースアクセス禁止」に反するため不採用。k8s はサンドボックス内に閉じる。
- イメージは `nerdctl`(buildkit) でビルドし `ctr images import` で k3s に取り込む（Docker デーモン不使用）。

## デプロイ = k8s ネイティブ
- `deploy/helm/auth-server/`：Deployment / Service / ConfigMap / Secret /（dev）PostgreSQL / NetworkPolicy 雛形。
- リソースは `values.yaml` で 1 vCPU / 800Mi（requests=limits）。NetworkPolicy は認証/認可分離の egress 制御の足場（P0 は無効）。
- ローカル検証は in-sandbox k3s（`scripts/dev-cluster.sh`）。

## 技術スタック
Node.js 24 / TypeScript / ESM ・ Fastify ・ jose ・ pg(生SQL) ・ zod ・ pino ・ vitest ・（Redis: 後付け）。
