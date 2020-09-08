# -*- coding:utf-8 -*-
"""
@author: XiangNan
@desc: 
"""
import re
import time
from datetime import datetime, timedelta
import hashlib
import requests
from base64 import b64encode


class CoolapkSpider:
    def __init__(self):
        self.session = requests.Session()
        self.token = {'value': '', 'time': datetime.now()}
        self.device = {'value': '', 'time': datetime.now()}
        self.headers = {
            # 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 8.1.0; Pixel Build/OPM4.171019.021.P1) (#Build; google; Pixel; OPM4.171019.021.P1; 8.1.0) +CoolMarket/9.2.2-1905301',
            'X-Requested-With': 'XMLHttpRequest',
            'X-App-Id': 'com.coolapk.market',
            'X-App-Token': self.__get_token(),
        }

    def __get_token(self, device_id="b1685500-01c5-3c88-a05d-4b99fed7f421"):
        if self.token['value'] == '' or datetime.now() - self.token['time'] > timedelta(seconds=30):
            timestamp = int(time.time())
            v62 = f"token://com.coolapk.market/c67ef5943784d09750dcfbb31020f0ab?{hashlib.md5(str(timestamp).encode()).hexdigest()}${device_id}&com.coolapk.market"
            token = f"{hashlib.md5(b64encode(v62.encode())).hexdigest()}{device_id}{hex(timestamp)}"
            self.token = {'value': token, 'time': datetime.now()}
        return self.token['value']

    def get_feedlist(self, page):
        url = 'https://api.coolapk.com/v6/main/indexV8'
        params = {
            'page': page,
        }
        response = self.session.get(url, headers=self.headers, params=params)
        if response.status_code == 200:
            try:
                data = response.json()['data']
                fromapi = f"/v6/main/indexV8?page={page}"
                return data, fromapi
            except Exception as e:
                print(f" -- feedlist -- error while get feedlist, error:{e}")

    def __parse_feedlist(self, response):
        feedid_list = []
        if response:
            datalist, fromapi = response
            feedid_list.append(fromapi)
            for data in datalist:
                feed_id = data.get("id")
                if not feed_id:
                    continue
                username = data.get("username")
                userid = data.get("uid")
                print("*"*20 + "动态列表" + "*"*20)
                print(f"feed_id: {feed_id}, username: {username}, userid: {userid}")
                feedid_list.append(feed_id)
        return feedid_list

    def get_feed_detail(self, feed_id, fromapi):
        url = f"https://api.coolapk.com/v6/feed/detail"
        params = {
            "id": feed_id,
            "fromApi": fromapi,
        }
        response = self.session.get(url, headers=self.headers, params=params)
        if response.status_code == 200:
            try:
                data = response.json()['data']
                return data
            except Exception as e:
                print(f" -- feedlist -- error while get feedlist, error:{e}")

    def get_feed_comment(self, feed_id, page):
        url = f"https://api.coolapk.com/v6/feed/replyList"
        params = {
            "id": feed_id,
            "listType": "lastupdate_desc",
            "page": page,
            "discussMode": "1",
            "feedType": "feed",
            "blockStatus": "0",
            "fromFeedAuthor": 0,
        }
        response = self.session.get(url, headers=self.headers, params=params)
        if response.status_code == 200:
            try:
                data = response.json()['data']
                return data
            except Exception as e:
                print(f" -- feedlist -- error while get feedlist, error:{e}")

    def __parse_feed_detail(self, data):
        if data:
            message = data.get("message")
            title = data.get("title")
            username = data.get("username")
            userid = data.get("uid")
            print("*"*20 + "动态详情" + "*"*20)
            print(f"username: {username}, userid: {userid}")
            print(f"title: {title}")
            print(f"message: {message}")

    def __parse_feed_comment(self, datalist):
        if datalist:
            for data in datalist:
                feedid = data.get("fid")
                replyid = data.get("id")
                message = data.get("message")
                username = data.get("username")
                userid = data.get("uid")
                print("*"*20 + "评论列表" + "*"*20)
                print(f"原帖ID: {feedid}, 评论ID: {replyid}, 评论用户ID: {userid}, 评论用户昵称: {username}")
                print(f"评论详情: {message}")

    def run(self, max_page):
        for page in range(1, max_page):
            response = self.get_feedlist(page)
            data = self.__parse_feedlist(response)
            fromapi = data[0]
            feedid_list = data[1:]
            for feed_id in feedid_list:
                feed_detail_data = self.get_feed_detail(feed_id, fromapi)
                self.__parse_feed_detail(feed_detail_data)
                feed_comment_data = self.get_feed_comment(feed_id, fromapi)
                self.__parse_feed_comment(feed_comment_data)


if __name__ == '__main__':
    coolapk_spider = CoolapkSpider()
    coolapk_spider.run(10)