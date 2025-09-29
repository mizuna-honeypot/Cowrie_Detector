# Cowrie Detector 🕵️‍♂️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

Cowrieハニーポットを検出するための、シンプルかつ強力なPythonスクリプトです。

---
## 概要

`cowrie_detector.py`は、指定されたSSHサーバーが人気のハニーポット「Cowrie」であるかどうかを、複数の指標に基づいて分析・特定するツールです。ハニーポットの研究者や、ペネトレーションテストの初期調査などで、ターゲットが本物のシステムか、あるいは巧妙に仕掛けられた罠かを見分ける手助けをします。

## 実行結果のスクリーンショット

![Cowrie Detector Screenshot](screenshot.png) 
*注: 上記画像を表示するには、`screenshot.png`という名前で実行結果のスクリーンショットをリポジトリにアップロードしてください。*

---
## 主な機能

* **多層的な分析**: SSHバナー、認証情報、システムの振る舞い、環境情報を組み合わせ、総合的にハニーポットを判断します。
* **軽量＆ポータブル**: Python3と`paramiko`ライブラリのみで動作し、複雑なセットアップは不要です。
* **信頼度スコアリング**: 検出された指標に基づき、ターゲットがCowrieである可能性をパーセンテージで表示します。

---
## 仕組み (How It Works)

このツールは、以下の4段階の分析を通じてCowrieを特定します。

1.  **バナー分析**: ターゲットサーバーのSSHバナーを取得し、Cowrieがよく使用する既知のバージョン文字列と比較します。
2.  **認証プローブ**: `root:root`のような一般的なデフォルト認証情報や、Cowrie特有の`phil:phil`でのログインを試みます。
3.  **行動分析**: 認証成功後、基本的なコマンド(`whoami`など)を実行します。Cowrieは、特定の状況下で即座にチャネルを切断する不自然な挙動を示すことがあり、これを検出します。
4.  **環境フィンガープリント**: `uname -a`や`cat /etc/passwd`を実行し、返却されるカーネルバージョンやユーザーリストがCowrieのデフォルト環境と一致しないか確認します。

---
## 必要なもの

* Python 3.x
* `paramiko` ライブラリ

---
## インストール

1.  **リポジトリをクローンします。**
    ```bash
    git clone [https://github.com/あなたのユーザー名/cowrie_detector.git](https://github.com/あなたのユーザー名/cowrie_detector.git)
    cd cowrie_detector
    ```

2.  **必要なライブラリをインストールします。**
    ```bash
    pip install paramiko
    ```
---
## 使い方

ターミナルから以下のように実行します。

```bash
python3 cowrie_detector.py <ターゲットのIPアドレス> [ポート番号]
