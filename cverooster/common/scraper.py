import logging
import logging.config
import os
import re
from datetime import datetime

from bs4 import BeautifulSoup

from cverooster.common.data import NvdScrapeResult

logging.config.fileConfig(
    "{}/cverooster/conf/logging.conf".format(os.environ["PYTHONPATH"])
)
logger = logging.getLogger("cveroosterBatchLogger")


class NvdScraper:
    def __init__(self, nvd_url, html):
        self.nvd_url = nvd_url
        self.html = html
        self.soup = BeautifulSoup(self.html, "html.parser")

    def scrape(self):
        current_description = self._scrape_current_description()
        analysis_description = self._scrape_analysis_description()
        cvss3_score, cvss3_severity = self._scrape_cvss_version3()
        cvss3_vector = self._scrape_cvss_version3_vector()
        cvss2_score, cvss2_severity = self._scrape_cvss_version2()
        cvss2_vector = self._scrape_cvss_version2_vector()
        nvd_published_date = self._scrape_nvd_published_date()
        nvd_last_modified = self._scrape_nvd_last_modified()

        return NvdScrapeResult(
            current_description=current_description,
            analysis_description=analysis_description,
            cvss3_score=cvss3_score,
            cvss3_severity=cvss3_severity,
            cvss3_vector=cvss3_vector,
            cvss2_score=cvss2_score,
            cvss2_severity=cvss2_severity,
            cvss2_vector=cvss2_vector,
            nvd_published_date=nvd_published_date,
            nvd_last_modified=nvd_last_modified,
            last_scraped_date=datetime.now(),
        )

    def _scrape_current_description(self):
        selector = "p[data-testid='vuln-description']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [current_description], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None
        current_description = tags[0].getText()
        if not current_description:
            logger.warning(
                "[current_description]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
                self.nvd_url,
            )
        return current_description

    def _scrape_analysis_description(self):
        selector = "p[data-testid='vuln-analysis-description']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [analysis_description], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None
        analysis_description = tags[0].getText()
        if not analysis_description:
            logger.warning(
                "[analysis_description]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None
        return analysis_description

    def _scrape_cvss_version3(self):
        selector = "a[data-testid='vuln-cvss3-panel-score']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [cvss_version3], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None, None
        value = tags[0].getText()
        if not value:
            logger.warning(
                "[cvss_version3]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None, None
        pattern = r"([\d\.\d]+)\s+([A-Z]+)"
        matched = re.search(pattern, value)
        if not matched:
            logger.warning(
                "正規表現にマッチしませんでした。取得対象: [cvss_version3], 値: [%s], 正規表現: %s, url: [%s]",
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        count_matched = len(matched.groups())
        if count_matched != 2:
            logger.warning(
                "正規表現のマッチ数が%s件でした。期待値は2件です。取得対象: [cvss_version3], 値: [%s], 正規表現: %s, url: [%s]",
                count_matched,
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        cvss3_score_str = matched.group(1)
        if not cvss3_score_str:
            logger.warning(
                "[cvss3_score]の取得結果がemptyでした。値: [%s], 正規表現: %s, url: [%s]",
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        if not re.match(r"^\d+\.\d+$", cvss3_score_str):
            logger.warning(
                "[cvss3_score]の値が数値ではありませんでした。cvss3_score: [%s], url: [%s]",
                cvss3_score_str,
                self.nvd_url,
            )
            return None, None
        cvss3_score = float(cvss3_score_str)
        cvss3_severity = matched.group(2)
        if not cvss3_severity:
            logger.warning(
                "[cvss3_severity]の取得結果がemptyでした。値: [%s], 正規表現: %s, url: [%s]",
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        return cvss3_score, cvss3_severity

    def _scrape_cvss_version3_vector(self):
        selector = "span[data-testid='vuln-cvss3-nist-vector']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [cvss_version3_vector], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None
        cvss_version3_vector = tags[0].getText()
        if not cvss_version3_vector:
            logger.warning(
                "[cvss_version3_vector]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None
        return cvss_version3_vector

    def _scrape_cvss_version2(self):
        selector = "div[data-testid='vuln-cvss2-panel'] .label"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [cvss_version2], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None, None
        value = tags[0].getText()
        if not value:
            logger.warning(
                "[cvss_version2]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None, None
        pattern = r"([\d\.\d]+)\s+([A-Z]+)"
        matched = re.search(pattern, value)
        if not matched:
            logger.warning(
                "正規表現にマッチしませんでした。取得対象: [cvss_version2], 値: [%s], 正規表現: %s, url: [%s]",
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        count_matched = len(matched.groups())
        if count_matched != 2:
            logger.warning(
                "正規表現のマッチ数が%s件でした。期待値は2件です。取得対象: [cvss_version2], 値: [%s], 正規表現: %s, url: [%s]",
                count_matched,
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        cvss2_score_str = matched.group(1)
        if not cvss2_score_str:
            logger.warning(
                "[cvss2_score]の取得結果がemptyでした。値: [%s], 正規表現: %s, url: [%s]",
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        if not re.match(r"^\d+\.\d+$", cvss2_score_str):
            logger.warning(
                "[cvss2_score]の値が数値ではありませんでした。cvss2_score: [%s], url: [%s]",
                cvss2_score_str,
                self.nvd_url,
            )
            return None, None
        cvss2_score = float(cvss2_score_str)
        cvss2_severity = matched.group(2)
        if not cvss2_severity:
            logger.warning(
                "[cvss2_severity]の取得結果がemptyでした。値: [%s], 正規表現: %s, url: [%s]",
                value,
                pattern,
                self.nvd_url,
            )
            return None, None
        return cvss2_score, cvss2_severity

    def _scrape_cvss_version2_vector(self):
        selector = "span[data-testid='vuln-cvss2-panel-vector']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [cvss_version2_vector], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None
        cvss_version2_vector = tags[0].getText()
        if not cvss_version2_vector:
            logger.warning(
                "[cvss_version2_vector]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None
        return cvss_version2_vector

    def _scrape_nvd_published_date(self):
        selector = "span[data-testid='vuln-published-on']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [nvd_published_date], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None
        nvd_published_date_str = tags[0].getText()
        if not nvd_published_date_str:
            logger.warning(
                "[nvd_published_date]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None
        pattern = r"^\d{2}/\d{2}/\d{4}$"
        if not re.match(pattern, nvd_published_date_str):
            logger.warning(
                "正規表現にマッチしませんでした。取得対象: [nvd_published_date], 値: [%s], 正規表現: %s, url: [%s]",
                nvd_published_date_str,
                pattern,
                self.nvd_url,
            )
        return datetime.strptime(nvd_published_date_str, "%m/%d/%Y")

    def _scrape_nvd_last_modified(self):
        selector = "span[data-testid='vuln-last-modified-on']"
        tags = self.soup.select(selector)
        count_tags = len(tags)
        if count_tags != 1:
            logger.warning(
                "セレクターのヒット数が%s件でした。期待値は1件です。取得対象: [nvd_last_modified], セレクター: [%s], url: [%s]",
                count_tags,
                selector,
                self.nvd_url,
            )
            return None
        nvd_last_modified_str = tags[0].getText()
        if not nvd_last_modified_str:
            logger.warning(
                "[nvd_last_modified]の取得結果がemptyでした。セレクター: [%s], url: [%s]",
                selector,
                self.nvd_url,
            )
            return None
        pattern = r"^\d{2}/\d{2}/\d{4}$"
        if not re.match(pattern, nvd_last_modified_str):
            logger.warning(
                "正規表現にマッチしませんでした。取得対象: [nvd_last_modified], 値: [%s], 正規表現: %s, url: [%s]",
                nvd_last_modified_str,
                pattern,
                self.nvd_url,
            )
        return datetime.strptime(nvd_last_modified_str, "%m/%d/%Y")
