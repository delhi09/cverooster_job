class BatchAbnormalTerminationError(Exception):
    def __init__(self, batch_name):
        message = f"「{batch_name}」が異常終了しました。詳細はスタックトレースを見てください。"
        super().__init__(message)


class DaemonAbnormalTerminationError(Exception):
    def __init__(self, daemon_name):
        message = f"「{daemon_name}」が異常終了しました。詳細はスタックトレースを見てください。"
        super().__init__(message)


class DownloadFileFailedError(Exception):
    def __init__(self, url, request_count):
        message = (
            f"{request_count}回トライしましたが、「{url}」からのファイルのダウンロードに失敗しました。詳細はスタックトレースを見てください。"
        )
        super().__init__(message)


class UnzippedFileNotExistsError(Exception):
    def __init__(self, file_name):
        message = f"{file_name}が存在しません。"
        super().__init__(message)


class CsvValidationError(Exception):
    def __init__(self, error_message, file_name, line=None):
        if line is None:
            message = f"{error_message} at {file_name}:L{line}"
        else:
            message = f"{error_message} at {file_name}"
        super().__init__(message)


class ConnectionNotExistsError(Exception):
    def __init__(self):
        super().__init__("DBコネクションが存在しません。")


class TransactionNotExistsError(Exception):
    def __init__(self):
        super().__init__("DBトランザクションが存在しません。")


class IllegalStateError(Exception):
    def __init__(self, message):
        super().__init__(message)


class CveIDInvalidFormattError(Exception):
    def __init__(self, cve_id):
        message = f"CVE_IDのフォーマットが不正です。CVE_ID: {cve_id}"
        super().__init__(message)


class AccessControlConfiguredError(Exception):
    def __init__(self, robotstxt_url):
        message = f"robots.txtにアクセスコントロールが設定されました。クロール頻度がrobots.txtの設定に違反していないか、robots.txtを確認してください。robots.txtのurl: {robotstxt_url}"
        super().__init__(message)


class CrawlForbiddenError(Exception):
    def __init__(self, url, robotstxt_url):
        message = f"[{url}]はrobotx.txtの設定によりクロールを禁止されています。robots.txtの設定を確認してください。robots.txtのurl: {robotstxt_url}"
        super().__init__(message)
