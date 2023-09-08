import requests
from bs4 import BeautifulSoup as bs
import re
import datetime


DOMAIN = 'http://lib.cpu.edu.cn'
ID = {
    # 'http://lib.cpu.edu.cn/1171/list.htm', # 中文数据库
    '1171': '中文数据库',
    '1172': '外文数据库',
    '1173': '试用数据库',
}

HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Referer': 'http://lib.cpu.edu.cn/main.htm',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.62',
}

INTRANET_RULE = """  # 校园内网
  - DOMAIN-SUFFIX,cpu.edu.cn # 学校主域名
  - IP-CIDR,202.119.176.0/20 # 学校外网网段
  - IP-CIDR,192.168.199.0/24 # 校园网登录及校内DNS服务器网段
  - IP-CIDR,10.0.0.0/8 # 校园大内网网段
"""

def get_articles(id, page=1):
    menu_url = "%s/%s/list%d.htm" %(DOMAIN, id, page)
    resp = requests.get(menu_url, headers=HEADERS, verify=False)
    resp.encoding='utf-8'
    html_doc = resp.text
    soup = bs(html_doc, 'html.parser')
    article_container = soup.find(class_="wp_article_list")
    articles = article_container.find_all(class_="Article_Title")
    dataset = []
    for article in articles:
        article_info = {}
        article_a_tag = article.find('a')
        article_info['name'] = article_a_tag.get_text()
        article_info['menu_url'] = "%s%s" %(DOMAIN, article_a_tag.get('href'))
        dataset.append(article_info)
    return dataset

def build_library():
    library = []
    for id in ID.keys():
        menu_url = "%s/%s/list.htm" %(DOMAIN, id)
        dataset = {
            'name': ID[id],
        }
        resp = requests.get(menu_url, headers=HEADERS, verify=False)
        dataset['data'] = []
        resp.encoding='utf-8'
        html_doc = resp.text
        soup = bs(html_doc, 'html.parser')
        max_page = int(soup.find(class_="all_pages").get_text())

        for page in range(1, max_page+1):
            dataset['data'] += get_articles(id=id, page=page)
        library.append(dataset)
    return library

def get_domain_suffix(url):
    match = re.search(r'https?://([A-Za-z0-9.-]+)', str(url))
    if match is None:
        return None
    domain = match.group(1)
    if "cpu.edu.cn" in domain:
        return None

    domain_parts = domain.split('.')
    parts = len(domain_parts)
    if parts<=2:
        domain_suffix = '.'.join(domain_parts[:])
    elif parts>=4:
        domain_suffix = '.'.join(domain_parts[1:])
    elif parts==3:
        if len(domain_parts[-2])>=7:
            domain_suffix = '.'.join(domain_parts[-2:])
        else:
            if domain_parts[0] == 'www':
                domain_suffix = '.'.join(domain_parts[1:])
            else:
                domain_suffix = '.'.join(domain_parts[:])
    return domain_suffix

def merge(domain_suffix_list):
    res = []
    domain_suffix_list_no_redundancy = list(set(domain_suffix_list))
    for domain_suffix in domain_suffix_list_no_redundancy:
        if domain_suffix != 'cpu.edu.cn' and domain_suffix != 'weixin.qq.com':
            res.append(domain_suffix)
    return res

def fetch_url(library_raw):
    library = []
    for database_raw in library_raw:
        database = {
            'name': database_raw['name'],
            'data': []
        }
        for data_raw in database_raw['data']:
            data = {
                'name': data_raw['name']
            }
            resp = requests.get(data_raw['menu_url'], headers=HEADERS, verify=False)
            resp.encoding='utf-8'
            html_doc = resp.text
            soup = bs(html_doc, 'html.parser')
            article_content = soup.find(class_='article')
            a_tag_list = article_content.find_all('a')

            domain_suffix_list = []
            for a_tag in a_tag_list:
                # url = a_tag.get('href')
                url = a_tag.get_text()
                domain_suffix = get_domain_suffix(url=url)
                if domain_suffix is None:
                    continue
                domain_suffix_list.append(domain_suffix)
            data['url_list'] = merge(domain_suffix_list)
            database['data'].append(data)
        library.append(database)
    return library

def generate_rules(library):
    current_datetime = datetime.datetime.now()
    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    rules = "# LAST UPDATED: %s\npayload:\n" %(formatted_datetime)
    for database in library:
        rules += "  # %s\n" %(database['name'])
        for data in database['data']:
            for url in data['url_list']:
                rules += "  - DOMAIN-SUFFIX,%s # %s\n" %(url, data['name'])
        rules += '\n'
    rules += INTRANET_RULE
    return rules

def main():
    library_raw = build_library()
    library = fetch_url(library_raw=library_raw)
    rule_text = generate_rules(library=library)
    with open("cpu_lib.yaml", 'w', encoding='utf-8') as f:
        f.write(rule_text)

if __name__ == "__main__":
    main()
    pass
