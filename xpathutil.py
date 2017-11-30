#!/usr/bin/env python
# -*- coding:utf8 -*-
#
#!/usr/bin/env python
# -*- coding:utf8 -*-
#
# created by chenpengfei@ipin.com 2017/11/30
#

from lxml import html
from lxml import etree
import re


def get_node_by_text(dom, tag='*', text='', origin=True):
    xpath_string = './/{tag}[contains(text(), {value})]'
    if origin:
        return dom.xpath(xpath_string.format(tag=tag, value=text))
    node = dom.xpath(xpath_string.format(tag=tag, value=''.join(text.split())))
    if is_valid_list_res(node):
        return node[0]
    else:
        return None


def get_value_by_tag_attr(dom, tag='*', attr='class', value='', item='text'):
    """
    根据tag 和 tag属性找到node 并提取node中的标签的值
    :param dom: lxml树
    :param tag: tag
    :param attr: 属性
    :param value: 属性值
    :param item: 目标属性
    :return: 目标值或None
    """
    xpath_string = './/{tag}[@{attr}="{value}"]/{item}'
    if item == 'text':
        item = 'text()'
    else:
        item = '' + '@' + item
    result = dom.xpath(xpath_string.format(tag=tag, attr=attr, value=value, item=item))
    if is_valid_list_res(result):
        return result[0]
    else:
        return None

def get_node_by_tag_attr(dom, tag='*', attr='class', value=''):
    """
    根据tag和属性、属性值找节点
    :param dom: lxml
    :param tag: tag
    :param attr: 属性
    :param value: 属性值
    :return: 节点或None
    """
    xpath_string = './/{tag}[@{attr}="{value}"]'.format(tag=tag, attr=attr, value=value)
    node = dom.xpath(xpath_string)
    if is_valid_list_res(node):
        return node[0]
    else:
        return None


def table_content(table, sep=',', rowsep='\r\n'):
    trs = table.xpath('tr')
    if len(trs) == 0:
        trs = table.xpath('tbody/tr')
    texts = []
    for tr in trs:
        tds = tr.xpath('td')
        row_text = []
        for td in tds:
            row_text.append(re.sub('[\r\t\n]+', '', td.text_content()))
        texts.append(sep.join(row_text))
    return rowsep.join(texts)


def is_valid_list_res(item, size=1):
    return item is not None and isinstance(item, list) and len(item) >= size


def get_text_content(dom, xpath):
    ele = dom.xpath(xpath)
    if is_valid_list_res(ele):
        return ele[0].text_content()
    else:
        return ""


def html_content(html_src):
    dorm = html.fromstring(html_src)
    return dorm.text_content()


def get_text_or_none_str(dom, xpath):
    ele = dom.xpath(xpath)
    txt = ''
    if is_valid_list_res(ele):
        if isinstance(ele[0], (str, unicode)):
            txt = ele[0]
        elif hasattr(ele[0], "text_content"):
            txt = ele[0].text_content()
        elif hasattr(ele[0], "text"):
            txt = ele[0].text
        else:
            txt = 'None'
    if txt == '':
        txt = "None"
    return txt


def get_text_or_empty_str(dom, xpath=None):
    ele = dom.xpath(xpath) if xpath is not None else [dom]
    txt = ''
    if is_valid_list_res(ele):
        if isinstance(ele[0], (str, unicode)):
            txt = ele[0]
        elif hasattr(ele[0], "text_content"):
            txt = ele[0].text_content()
        elif hasattr(ele[0], "text"):
            txt = ele[0].text
        else:
            txt = ''
    if txt == '':
        txt = ""
    return txt


def get_node_text(node):
    if isinstance(node, list) and len(node) > 0:
        node = node[0]
    if node is not None:
        if hasattr(node, 'text'):
            return node.text
        else:
            return ""
    else:
        return ""


def get_attribute(node, attr_name):
    attr = node.xpath('@{attr}'.format(attr=attr_name))
    if is_valid_list_res(attr):
        return attr[0]
    return ''


