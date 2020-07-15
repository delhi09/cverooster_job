# cverooster_job

## 概要
<a href="https://github.com/kamatimaru/cverooster">cverooster</a>のアプリで使用するデータを作成するバッチ・daemon。

## 使用したライブラリ
- Python3系
- Requests
- Beautiful Soup4
- SQLAlchemy

## ローカル環境での実行手順
### ・前提
以下がインストールされていること
- Python3系
- Docker
- mysqlコマンド

### ・リポジトリをクローン
```shell
git clone https://github.com/kamatimaru/cverooster_job.git
```

### ・仮想環境構築
```shell
cd cverooster_job
python3 -m venv .venv
source .venv/bin/activate
```

### ・必要なパッケージのインストール
```shell
pip3 install -r requirements.txt
```

※ Macでmysqlclientのインストール時にエラーが発生する場合は以下の記事参照
<a href="https://kamatimaru.hatenablog.com/entry/2020/04/30/123939" target="_blank">https://kamatimaru.hatenablog.com/entry/2020/04/30/123939</a>

### ・Dockerコンテナ起動
```shell
docker-compose up -d
```

### PYTHONPATHを宣言
```shell
export PYTHONPATH=$(pwd)
```

### 1.CVE公式からCSVデータをダウンロードしてraw_cveテーブルにimportする。
```shell
python3 cverooster/entrypoint/import_cve_all_items_batch.py
```

### 2.NVD公式からJSONデータをダウンロードしてraw_nvdテーブルにimportする。
```shell
python3 cverooster/entrypoint/import_raw_nvd.py
```

### 3.1,2を元にcveテーブルにデータを作成する。
```shell
python3 cverooster/entrypoint/cve_create_daemon.py
```