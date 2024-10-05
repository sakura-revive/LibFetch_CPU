import requests
from bs4 import BeautifulSoup as bs
import re
import datetime
import pytz
import tldextract

DOMAIN = "https://lib.cpu.edu.cn"
ID = {
    # 'https://lib.cpu.edu.cn/1171/list.htm', # 中文数据库
    "1171": "中文数据库",
    "1172": "外文数据库",
    "1173": "试用数据库",
}

HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "DNT": "1",
    "Referer": "https://lib.cpu.edu.cn/main.htm",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.62",
}

INTRANET_RULESET = """\
  # 校园网段
  - DOMAIN-SUFFIX,cpu.edu.cn # 学校主域名
  - IP-CIDR,202.119.176.0/20 # 学校外网网段
  - IP-CIDR,192.168.0.0/16 # 校园网登录及校内DNS服务器网段
  - IP-CIDR,10.0.0.0/8 # 校园大内网网段
  - IP-CIDR,172.16.0.0/12 # 校园宽带登录及其它内网网段
"""


def get_articles(session: requests.Session, id, page=1):
    menu_url = f"{DOMAIN}/{id}/list{page}.htm"
    resp = session.get(menu_url, headers=HEADERS)
    resp.encoding = "utf-8"
    html_doc = resp.text
    soup = bs(html_doc, "html.parser")
    article_container = soup.find(class_="wp_article_list")
    articles = article_container.find_all(class_="Article_Title")
    dataset = []
    for article in articles:
        article_info = {}
        article_a_tag = article.find("a")
        article_info["name"] = article_a_tag.get_text()
        article_info["menu_url"] = f"{DOMAIN}{article_a_tag.get('href')}"
        dataset.append(article_info)
    return dataset


def build_library(session: requests.Session):
    library = []
    for id in ID.keys():
        menu_url = f"{DOMAIN}/{id}/list.htm"
        dataset = {
            "name": ID[id],
        }
        resp = session.get(menu_url, headers=HEADERS)
        dataset["data"] = []
        resp.encoding = "utf-8"
        html_doc = resp.text
        soup = bs(html_doc, "html.parser")
        max_page = int(soup.find(class_="all_pages").get_text())

        for page in range(1, max_page + 1):
            dataset["data"] += get_articles(session=session, id=id, page=page)
        library.append(dataset)
    return library


def analyze_urls(urls):
    rules = []
    for url in urls:
        match = re.search(r"https?://([A-Za-z0-9.-]+)", str(url))
        if match is None:
            continue
        domain = match.group(1)
        if "cpu.edu.cn" in domain or "weixin.qq.com" in domain:
            continue
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", str(domain)):  # ip address
            rules.append(f"IP-CIDR,{domain}/32")
            continue

        extracted = tldextract.extract(url)
        rule = f'DOMAIN-SUFFIX,{f"{extracted.subdomain}." if "edu" in extracted.suffix else ""}{extracted.domain}.{extracted.suffix}'
        rule = rule.replace("www.", "")
        if rule not in rules:
            rules.append(rule)
    return rules


def fetch_url(session: requests.Session, library_raw):
    library = []
    for database_raw in library_raw:
        database = {"name": database_raw["name"], "data": []}
        for data_raw in database_raw["data"]:
            data = {"name": data_raw["name"], "menu_url": data_raw["menu_url"]}
            resp = session.get(data_raw["menu_url"], headers=HEADERS)
            resp.encoding = "utf-8"
            html_doc = resp.text
            soup = bs(html_doc, "html.parser")
            article_content = soup.find(class_="article")
            if article_content is None:
                data["rule_list"] = [
                    f"# Error: Access denied",
                ]
                database["data"].append(data)
                continue
            a_tag_list = article_content.find_all("a")

            urls = [a_tag.get_text() for a_tag in a_tag_list]
            rules = analyze_urls(urls)

            data["rule_list"] = list(set(rules))
            database["data"].append(data)
        library.append(database)
    return library


def generate_ruleset(library):
    current_time_utc = datetime.datetime.now(pytz.utc)
    expected_timezone = pytz.timezone("Asia/Shanghai")
    current_time_expected = current_time_utc.astimezone(expected_timezone)
    formatted_datetime = current_time_expected.strftime(
        "%Y-%m-%d %H:%M:%S UTC+08:00 Asia/Shanghai"
    )

    ruleset = f"# LAST UPDATED: {formatted_datetime}\npayload:\n"
    for database in library:
        ruleset += f"  # {database['name']}\n"
        for data in database["data"]:
            for rule in data["rule_list"]:
                if f"  - {rule}" in ruleset:
                    new_line = f"  # - "
                else:
                    new_line = f"  - "
                if data["name"] not in ruleset:
                    new_line += f'{rule} # {data["name"]} ({data["menu_url"]})\n'
                else:
                    new_line += f'{rule} # {data["name"]}\n'
                if new_line not in ruleset:
                    ruleset += new_line
        ruleset += "\n"
    ruleset += INTRANET_RULESET
    return ruleset


def main():
    session = requests.Session()
    session.verify = True
    library_raw = build_library(session=session)
    library = fetch_url(session=session, library_raw=library_raw)
    rule_text = generate_ruleset(library=library)
    with open("cpu_lib.yaml", "w", encoding="utf-8") as f:
        f.write(rule_text)


if __name__ == "__main__":
    main()
