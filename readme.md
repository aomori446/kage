# Kage (影)

Kage は、Go言語で記述された軽量かつ高性能な Shadowsocks 実装です。シンプルで効率的、そして既存のプロジェクトに統合しやすいように設計されています。

## 特徴 (Features)

- **プロトコルサポート**: Shadowsocks プロトコルと最新の暗号化方式を実装しています。
- **暗号化方式**: `2022-blake3-aes-256-gcm` などの標準的な暗号化方式をサポートしています。
- **モード**: TCP のトラフィック転送をサポートしています。
- **Fast Open**: レイテンシを削減するための TCP Fast Open (TFO) をサポートしています。
- **トンネリング**: 柔軟なネットワーク構成のためにトンネルモードで動作可能です。
- **軽量**: 依存関係を最小限に抑え、パフォーマンスのために最適化されています。
- **CLI サポート**: JSON 設定ファイルを使用したコマンドラインツールとして利用可能です。

## インストール (Installation)

Go 1.25 以上がインストールされている必要があります。

### CLI ツールとしてインストール

```bash
go install github.com/aomori446/kage/cmd/kage@latest
```

### ライブラリとしてインストール

```bash
go get github.com/aomori446/kage
```

## 使い方 (Usage)

### CLI (コマンドライン) として使用

設定ファイル (`config.json`) を作成します：

```json
{
  "server": "example.com",
  "server_port": 8388,
  "local_address": "127.0.0.1",
  "local_port": 1080,
  "password": "your-password",
  "method": "2022-blake3-aes-256-gcm",
  "mode": "tcp_only",
  "protocol": "socks",
  "fast_open": true
}
```

作成した設定ファイルを指定して実行します：

```bash
kage -c config.json
```

### ライブラリとして使用

Kage を独自の Go アプリケーションに簡単に組み込むことができます。

```go
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	
	"github.com/aomori446/kage"
	"github.com/aomori446/kage/config"
)

func main() {
	// 設定構造体の作成
	cfg := &config.Config{
		LocalAddr:  "127.0.0.1",
		LocalPort:  1080,
		Server:     "example.com",
		ServerPort: 8388,
		Password:   "your-password",
		Method:     config.CipherMethod2022blake3aes256gcm,
		Mode:       config.ModeTCPOnly,
		Protocol:   config.ProtocolSocks,
	}

	// ロガーの設定
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// クライアントの作成
	client, err := kage.NewClient(cfg, logger)
	if err != nil {
		log.Fatal(err)
	}

	// クライアントの実行
	if err := client.Serve(context.Background()); err != nil {
		log.Fatal(err)
	}
}
```

### 設定 (Configuration)

`config.json` や `config.Config` 構造体で以下の項目を設定できます：

- `local_address` / `LocalAddr`: リッスンするローカルアドレス。
- `local_port` / `LocalPort`: リッスンするローカルポート。
- `server` / `Server`: リモートの Shadowsocks サーバーアドレス。
- `server_port` / `ServerPort`: リモートの Shadowsocks サーバーポート。
- `password` / `Password`: Shadowsocks のパスワード/キー。
- `method` / `Method`: 暗号化方式 (例: `2022-blake3-aes-256-gcm`)。
- `mode` / `Mode`: 動作モード。
  - `tcp_only` (TCPのみ)
- `protocol` / `Protocol`: プロトコルタイプ。
  - `socks` (SOCKS5 プロキシ)
  - `tunnel` (ポートフォワーディング/トンネル)
- `forward_address` / `ForwardAddr`: (トンネルモード用) 転送先のアドレス。
- `forward_port` / `ForwardPort`: (トンネルモード用) 転送先のポート。
- `fast_open` / `FastOpen`: TCP Fast Open を有効にするかどうか。

## 開発 (Development)

### 前提条件

- Go 1.25 以上

### テストの実行

```bash
go test ./...
```

## TODO (今後の予定)

- [ ] サーバー側の実装
- [ ] プラグインサポート (SIPs)
- [ ] 複数サーバーのサポート (ロードバランシング / フェイルオーバー)
- [ ] ACL / ルーティングのサポート
- [ ] テストカバレッジの向上

## ライセンス (License)

[MIT License](LICENSE)
