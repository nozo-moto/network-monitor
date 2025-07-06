# Network Monitor

TUIベースのネットワークモニタリングツール

## インストール

```bash
go mod download
go build -o netmon cmd/netmon/main.go
```

## 使用方法

```bash
./netmon
```

終了: `q` または `ESC`

## 機能

- システムメトリクス表示 (CPU、メモリ、接続数、Goroutine数)
- ネットワーク統計 (送受信バイト数、パケット数、エラー、ドロップ)
- アクティブな接続一覧表示