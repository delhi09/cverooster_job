import json
import os
import subprocess
from datetime import datetime

from cverooster.common.data import RawNvdRecord
from cverooster.common.model import RawNvd
from cverooster.common.util import parse_cve_id

#
# raw_nvdにnvdデータをimportするバッチ
# NVD公式が、以下のURLにてNVDのJSONデータを提供してくれているので、
# ダウンロードしてテーブルにimportする。
# https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz
# ※ ファイルは年単位
#
# 元々は
#     -nvd_crawling_daemon
#     -nvd_scraping_daemon
# を使用することを想定していたが、実際にクローラーを実行してみたところ、
# NVDの公式サイトのパフォーマンスがあまり良くなく、しばしば500系エラーを返したり
# レスポンスタイムが10秒以上かかったりすることがあった。
#
# クローリングが現実的ではないので、他の手段を探したところ、NVD公式がJSONデータを
# 提供していることが分かったので、こちらを使用することにした。
#
# 従って、想定外の作業だったため突貫で作ったので最低限の処理しか書いていない。
#

if os.path.exists("nvdcve-1.1-2020.json.gz"):
    os.remove("nvdcve-1.1-2020.json.gz")

if os.path.exists("nvdcve-1.1-2020.json"):
    os.remove("nvdcve-1.1-2020.json")

cmd = "curl -O -f 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz'"
subprocess.run(cmd, shell=True, check=True)

cmd = "gunzip nvdcve-1.1-2020.json.gz"
subprocess.run(cmd, shell=True, check=True)

with open("nvdcve-1.1-2020.json", mode="r", encoding="utf-8") as f:
    json_data = json.load(f)
cve_items = json_data["CVE_Items"]

total_count = len(cve_items)
raw_nvd_model = RawNvd()
raw_nvd_model.connect()
raw_nvd_model.begin_transaction()
for count, item in enumerate(cve_items, start=1):
    print(f"進捗: {count}/{total_count}")
    cve_id = item["cve"]["CVE_data_meta"]["ID"]
    try:
        cve_year, cve_number = parse_cve_id(cve_id)
        description = item["cve"]["description"]["description_data"][0]["value"]
        cvss3_score = None
        cvss3_severity = None
        cvss3_vector = None
        if "baseMetricV3" in item["impact"]:
            cvss3_score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            cvss3_severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
            cvss3_vector = item["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
        cvss2_score = None
        cvss2_severity = None
        cvss2_vector = None
        if "baseMetricV2" in item["impact"]:
            cvss2_score = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            cvss2_severity = item["impact"]["baseMetricV2"]["severity"]
            cvss2_vector = item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
        published_date = datetime.strptime(item["publishedDate"], "%Y-%m-%dT%H:%MZ")
        last_modified_date = datetime.strptime(
            item["lastModifiedDate"], "%Y-%m-%dT%H:%MZ"
        )
        current_timestamp = datetime.now()
        raw_nvd_record = RawNvdRecord(
            cve_id=cve_id,
            cve_year=cve_year,
            cve_number=cve_number,
            nvd_url="https://nvd.nist.gov/vuln/detail/{cve_id}".format(cve_id=cve_id),
            current_description=description,
            analysis_description=description,
            cvss3_score=cvss3_score,
            cvss3_severity=cvss3_severity,
            cvss3_vector=cvss3_vector,
            cvss2_score=cvss2_score,
            cvss2_severity=cvss2_severity,
            cvss2_vector=cvss2_vector,
            nvd_published_date=published_date,
            nvd_last_modified=last_modified_date,
            last_fetched_date=current_timestamp,
            last_scraped_date=current_timestamp,
            created_by="import_raw_nvd",
            created_at=current_timestamp,
            updated_by="import_raw_nvd",
            updated_at=current_timestamp,
        )
        raw_nvd_model.save_raw_nvd(raw_nvd_record)
    except Exception as e:
        raise Exception(cve_id) from e
raw_nvd_model.commit()
raw_nvd_model.close_connection()
