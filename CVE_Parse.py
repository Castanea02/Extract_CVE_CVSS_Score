import time  # time 모듈 임포트
import tkinter as tk
from tkinter import filedialog, messagebox
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
import csv

class CveScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CVE Scraper")

        # 키워드 입력
        tk.Label(root, text="Enter a keyword to search:").grid(row=0, column=0)
        self.keyword_entry = tk.Entry(root, width=50)
        self.keyword_entry.grid(row=0, column=1, padx=10, pady=5)

        # 파일명 설정
        tk.Label(root, text="Output file name:").grid(row=1, column=0)
        self.filename_entry = tk.Entry(root, width=50)
        self.filename_entry.grid(row=1, column=1, padx=10, pady=5)
        self.filename_entry.insert(0, "cve_data.csv")

        # 행동 상태 표시
        self.status_text = tk.StringVar()
        self.status_text.set("Idle...")
        tk.Label(root, textvariable=self.status_text, anchor='w').grid(row=2, column=0, columnspan=2, padx=10, pady=5)

        # 크롤링 버튼
        self.crawl_button = tk.Button(root, text="Start Crawling", command=self.start_crawling)
        self.crawl_button.grid(row=3, column=0, columnspan=2, pady=10)

    def start_crawling(self):
        keyword = self.keyword_entry.get()
        filename = self.filename_entry.get()

        if not keyword:
            messagebox.showerror("Input Error", "Please enter a keyword.")
            return

        self.status_text.set(f"Crawling data for keyword: {keyword}")
        self.root.update_idletasks()

        # 크롤링 로직
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("--log-level=3")

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

        url = f'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}'
        driver.get(url)

        # 0.5초 대기
        time.sleep(0.5)

        data_list = []
        rows = driver.execute_script("return document.querySelectorAll('#TableWithRules table tbody tr');")

        for row in rows:
            try:
                link_element = driver.execute_script("return arguments[0].querySelector('td:nth-child(1) a');", row)
                link_text = link_element.text
                link_href = link_element.get_attribute('href')
                
                description_element = driver.execute_script("return arguments[0].querySelector('td:nth-child(2)');", row)
                description_text = description_element.text
                
                data_list.append((link_text, link_href, description_text))

            except StaleElementReferenceException:
                continue

        for i, (link_text, link_href, description_text) in enumerate(data_list):
            self.status_text.set(f"Processing CVE: {link_text}")
            self.root.update_idletasks()

            nvd_url = f'https://nvd.nist.gov/vuln/detail/{link_text}'
            driver.get(nvd_url)

            # 0.5초 대기
            time.sleep(0.5)

            cvss_jspaths = [
                "return document.querySelector('#Cvss4CnaCalculatorAnchor');",
                "return document.querySelector('#Cvss3CnaCalculatorAnchor');",
                "return document.querySelector('#Cvss2CnaCalculatorAnchor');",
                "return document.querySelector('#Cvss1CnaCalculatorAnchor');",
                "return document.querySelector('#Cvss4NistCalculatorAnchor');",
                "return document.querySelector('#Cvss3NistCalculatorAnchor');",
                "return document.querySelector('#Cvss2NistCalculatorAnchor');",
                "return document.querySelector('#Cvss1NistCalculatorAnchor');",
                "return document.querySelector('#Cvss4CnaCalculatorAnchorNA');",
                "return document.querySelector('#Cvss3CnaCalculatorAnchorNA');",
                "return document.querySelector('#Cvss2CnaCalculatorAnchorNA');",
                "return document.querySelector('#Cvss1CnaCalculatorAnchorNA');",
                "return document.querySelector('#Cvss4NistCalculatorAnchorNA');",
                "return document.querySelector('#Cvss3NistCalculatorAnchorNA');",
                "return document.querySelector('#Cvss2NistCalculatorAnchorNA');",
                "return document.querySelector('#Cvss1NistCalculatorAnchorNA');"
            ]

            cvss_score = 'Data not found'

            for jspath in cvss_jspaths:
                try:
                    cvss_element = driver.execute_script(jspath)
                    if cvss_element:
                        cvss_score = cvss_element.text
                        if "AnchorNA" in jspath or not cvss_score.strip():
                            cvss_score = 'N/A'
                        break
                except NoSuchElementException:
                    continue
                except StaleElementReferenceException:
                    continue

            data_list[i] = (link_text, link_href, description_text, cvss_score)

        driver.quit()

        # CSV 파일로 저장
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['CVE Code', 'Link URL', 'Description', 'CVSS Score'])
            writer.writerows(data_list)

        self.status_text.set(f"Data saved to {filename}")
        messagebox.showinfo("Success", f"Data successfully saved to {filename}!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CveScraperApp(root)
    root.mainloop()
