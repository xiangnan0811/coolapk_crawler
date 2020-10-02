# -*- coding:utf-8 -*-
"""
@author: XiangNan
@desc: 
"""
import time
from datetime import datetime, timedelta
import hashlib
import requests
from base64 import b64encode
from random import choice
from loguru import logger
from crawler.config import DEVICE_LIST


class CoolapkSpider:
    def __init__(self):
        self.session = requests.Session()
        self.host = "https://api.coolapk.com"
        self.token = {'value': '', 'time': datetime.now()}
        self.headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-App-Id': 'com.coolapk.market',
            'X-App-Token': self.__get_token(),
        }
        logger.add('../logs/crawler.log', format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}", level="INFO")

    def __get_token(self):
        """
        Get the token value for the request API
        :return: the value of token
        """
        device_id = choice(DEVICE_LIST)
        if self.token['value'] == '' or datetime.now() - self.token['time'] > timedelta(seconds=60 * 4):
            timestamp = int(time.time())
            v62 = f"token://com.coolapk.market/c67ef5943784d09750dcfbb31020f0ab?{hashlib.md5(str(timestamp).encode()).hexdigest()}${device_id}&com.coolapk.market"
            token = f"{hashlib.md5(b64encode(v62.encode())).hexdigest()}{device_id}{hex(timestamp)}"
            self.token = {'value': token, 'time': datetime.now()}
        return self.token['value']

    def __request_api(self, url: str, params: dict, mode: str):
        """
        request the api and return the response
        :param url:  api url
        :param params: url parameter
        :param mode: api mode: feed reply user feed_list
        :return: the response of request
        """
        try:
            token = self.__get_token()
            self.headers.update({"X-App-Token": token})
            response = self.session.get(url=url, headers=self.headers, params=params)
            response_data = response.json()
            return response_data
        except Exception as e:
            logger.error(f" -- feed {mode} -- error while get data, error:{e}")
            return {"data": None}

    def __request_feed_list(self, page: int):
        """
        request the feed_list url and return response
        :param page: page of feed_list
        :return: the response of request
        """
        url = 'https://api.coolapk.com/v6/main/indexV8'
        params = {'page': page}
        response = self.__request_api(url=url, params=params, mode="list")
        return response

    def __parse_feed_list(self, data: list) -> tuple:
        """
        parse the feed_list response and return a tuple contains the lists of feeds and users
        :param data: feed_list response
        :return: feeds list and users list
        """
        feed_info = []
        user_info = []
        for feed in data:
            feed_id = feed.get("id", None)
            if not feed_id:
                continue
            feed_data, user_data = self.__parse_feed_detail(feed)
            if feed_data:
                feed_info.append(feed_data)
            if user_data:
                user_info.append(user_data)
        return feed_info, self.__delete_duplicate(user_info)

    def get_feeds_from_feed_list(self, max_page: int) -> tuple:
        """
        request the main activity of app and get the feeds
        :param max_page: max page of feed_list
        :return: feeds and users
        """
        feed_infos = []
        user_infos = []
        page = 1
        while page <= max_page:
            logger.info(f"get_feeds_from_feed_list, max_page is-->{max_page}, current page is-->{page}")
            response = self.__request_feed_list(page)
            page += 1
            data = response.get("data", None)
            if not data:
                continue
            feed_info, user_info = self.__parse_feed_list(data)
            if feed_info:
                feed_infos.extend(feed_info)
            if user_info:
                user_infos.extend(user_info)
        return feed_infos, self.__delete_duplicate(user_infos)

    def __request_feed_detail(self, feed_id: str, fromapi: str = None):
        """
        request the feed detail url and return response
        :param feed_id: the feed id
        :param fromapi: referer
        :return: the response of request
        """
        url = f"https://api.coolapk.com/v6/feed/detail"
        params = {"id": feed_id}
        if fromapi is not None:
            params.update({"fromApi": fromapi})
        mode = "detail"
        response = self.__request_api(url, params, mode)
        return response

    def __parse_feed_detail(self, data: dict) -> tuple:
        """
        parse the response of feed detail and return a tuple containing the information of feeds and users
        :param data: the response of feed detail
        :return: feeds and users
        """
        feed_data = {}
        user = data.get("userInfo", None)
        user_data = self.__parse_user(user) if user else None

        feed_data['id'] = int(data.get("id"))
        feed_data['userid'] = int(data.get("uid"))
        feed_data['username'] = data.get("username")
        cover = data.get("message_cover", None)
        feed_data['cover'] = cover if cover else None
        feed_data['message'] = data.get("message", None)
        message_length = data.get("message_length", None)
        feed_data['message_length'] = int(message_length) if message_length else None
        tags = data.get("tags", None)
        feed_data['tags'] = tags if tags else None
        feed_data['title'] = data.get("title")
        feed_data['create_at'] = datetime.fromtimestamp(int(data.get("dateline")))
        feed_data['last_update_at'] = datetime.fromtimestamp(int(data.get("lastupdate")))
        feed_data['device_name'] = data.get("device_name", None)
        device_title = data.get("device_title", None)
        feed_data['device_title'] = device_title if device_title else None
        feed_data['feed_Type'] = data.get("feedType")
        feed_data['feed_Type_Name'] = data.get("feedTypeName")
        feed_data['entityType'] = data.get("entityType")        # feed feed_reply user
        feed_data['extra_fromApi'] = self.host + data.get("extra_fromApi")
        long_location = data.get("long_location", None)
        feed_data['long_location'] = long_location if long_location else None
        feed_data['pic_list'] = data.get("picArr")
        feed_data['url'] = self.host + data.get("url")
        feed_data['like_num'] = int(data.get("likenum"))                      # 点赞数
        feed_data['reply_num'] = int(data.get("replynum"))                    # 回复数
        feed_data['fav_num'] = int(data.get("favnum"))                        # 收藏数
        feed_data['forward_num'] = int(data.get("forwardnum"))                # 转发数
        feed_data['share_num'] = int(data.get("share_num"))                   # 分享数
        comment_num = data.get("commentnum", None)                            # 评论数，不包含楼中楼
        feed_data['comment_num'] = int(comment_num) if comment_num else None
        feed_data['gather_time'] = datetime.now()

        print("*" * 50)
        print(f"抓取动态成功：feed_id-->{feed_data['id']}<--username-->{feed_data['username']}<--")

        return feed_data, user_data

    def get_feed_detail(self, feed_id: str) -> tuple:
        """
        Returns the corresponding feed data based on the given feed_id
        :param feed_id:
        :return: feed_data and corresponding user_data
        """
        response = self.__request_feed_detail(feed_id)
        data = response.get("data", None)
        feed_data = None
        user_data = None
        if data:
            feed_data, user_data = self.__parse_feed_detail(data)
        else:
            logger.error(f" -- feed detail -- can't get feed detail which feed_id is {feed_id}, response is {response}")
        return feed_data, user_data

    def __request_feed_reply(self, feed_id, page):
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
        mode = "reply"
        response = self.__request_api(url, params, mode)
        return response

    def __parse_feed_reply(self, data):
        reply_info = []
        user_info = []

        for feed_reply in data:
            reply_data, user_data = self.__parse_reply(feed_reply)
            reply_info.append(reply_data)
            if user_data:
                user_info.append(user_data)
            reply_rows = feed_reply.get('replyRows', None)  # 楼中楼
            if reply_rows is not None:
                for reply_row in reply_rows:
                    reply_row_reply_data, reply_row_user_data = self.__parse_reply(reply_row)
                    reply_info.append(reply_row_reply_data)
                    user_info.append(reply_row_user_data)

        return reply_info, self.__delete_duplicate(user_info)

    def get_feed_reply(self, feed_id):
        page = 1
        reply_infos = []
        user_infos = []
        while True:
            logger.info(f"get_feed_reply, current page is-->{page}")
            response = self.__request_feed_reply(feed_id, page)
            page += 1
            data = response.get("data", None)
            if not data:
                logger.error(
                    f" -- feed reply -- can't get feed reply feed_id --> {feed_id}, page --> {page}, response --> {response}")
                break
            reply_info, user_info = self.__parse_feed_reply(data)
            if reply_info:
                reply_infos.extend(reply_info)
            if user_info:
                user_infos.extend(user_info)
        return reply_infos, self.__delete_duplicate(user_infos)

    def __parse_reply(self, feed_reply):
        reply_data = {}
        user = feed_reply.get("userInfo", None)
        user_data = self.__parse_user(user) if user else None
        reply_data['id'] = feed_reply.get("id", None)
        reply_data['uid'] = feed_reply.get("uid", None)
        reply_id = feed_reply.get("rid", None)                       # 若是有楼中楼的话，此为原回复ID
        reply_data['reply_id'] = reply_id
        if reply_id == 0:
            reply_data['reply_id'] = None
        reply_uid = feed_reply.get("ruid", None)                     # 若是有楼中楼的话，此为原回复用户ID
        reply_data['reply_uid'] = reply_uid
        if reply_uid == 0:
            reply_data['reply_uid'] = None
        reply_data['username'] = feed_reply.get("username")
        reply_data['message'] = feed_reply.get("message")
        reply_data['reply_num'] = feed_reply.get("replynum")
        reply_data['like_num'] = feed_reply.get("likenum")
        reply_data['create_at'] = datetime.fromtimestamp(int(feed_reply.get("dateline")))
        reply_data['last_update_at'] = datetime.fromtimestamp(int(feed_reply.get("lastupdate")))
        reply_data['feed_uid'] = feed_reply.get("feedUid")
        reply_data['feed_id'] = feed_reply.get("fid")  # feed ID
        reply_data['entityType'] = feed_reply.get("entityType")
        reply_data['gather_time'] = datetime.now()
        print("-" * 50)
        print(f"抓取动态回复成功：原动态ID-->{reply_data['feed_id']}<--回复ID-->{reply_data['id']}<--回复用户名-->{reply_data['username']}")

        return reply_data, user_data

    @staticmethod
    def __delete_duplicate(dict_list):
        li = [dict(t) for t in set([tuple(d.items()) for d in dict_list])]
        return li

    def __request_user_feedlist(self, user_id, page, first_item=None, last_item=None):
        url = f"https://api.coolapk.com/v6/user/feedList"
        params = {"uid": user_id, "page": page}
        if page > 1:
            params.update({"firstItem": first_item, "lastItem": last_item})
        mode = "user_home"
        if page == 1:
            self.__request_api(url="https://api.coolapk.com/v6/user/space", params={"uid": user_id}, mode="space")
        response = self.__request_api(url, params, mode)
        return response

    def __parse_user_feedlist(self, data_list):
        feed_list = []
        user_list = []
        first_item = None
        last_item = None
        for data in data_list:
            feed_data, user_data = self.__parse_feed_detail(data)
            if feed_data:
                feed_list.append(feed_data)
            if user_data:
                user_list.append(user_data)
        if feed_list:
            first_item = feed_list[0]['id']
            last_item = feed_list[-1]['id']
        return feed_list, user_list, first_item, last_item

    def get_user_feedlist(self, user_id):
        page = 1
        feed_infos = []
        user_infos = []
        first_item = None
        last_item = None
        while True:
            response = self.__request_user_feedlist(user_id, page, first_item, last_item)
            page += 1
            data = response.get("data", None)
            if not data:
                break
            feed_list, user_list, first_item, last_item = self.__parse_user_feedlist(data)
            if feed_list:
                feed_infos.extend(feed_list)
            if user_list:
                user_infos.extend(user_list)
        return feed_infos, self.__delete_duplicate(user_infos)

    @staticmethod
    def __parse_user(data):
        user_data = {}
        user_data['id'] = data.get("uid")
        user_data['user_name'] = data.get("username")
        user_data['entity_type'] = data.get("entityType")
        user_data['level'] = data.get("level")
        user_data['is_developer'] = int(data.get("isDeveloper"))
        user_data['login_time'] = datetime.fromtimestamp(int(data.get("logintime")))
        user_data['gather_time'] = datetime.now()
        user_data['next_level_experience'] = data.get("next_level_experience")
        user_data['next_level_percentage'] = float(data.get("next_level_percentage"))
        user_data['user_url'] = data.get("url")
        user_data['avatar'] = data.get("userBigAvatar").split("?")[0]
        verify_title = data.get("verify_title")
        user_data['verify_title'] = data.get("verify_title") if verify_title else None
        user_data['verify_icon'] = data.get("verify_icon") if verify_title else None

        return user_data

    def __request_search(self, keyword, search_mode, page, rank_type="default"):
        params = {"q": keyword, "page": page}
        if search_mode == 1:       # 应用
            params.update({"apkType": 1, "rankType": rank_type})
            url = "https://api.coolapk.com/v6/apk/search"
        elif search_mode == 2:     # 游戏
            params.update({"apkType": 2, "rankType": rank_type})
            url = "https://api.coolapk.com/v6/apk/search"
        elif search_mode == 3:     # 应用集
            url = "https://api.coolapk.com/v6/album/search"
        elif search_mode == 4:     # 发现
            url = "https://api.coolapk.com/v6/discovery/search"
        elif search_mode == 5:     # 酷图
            url = "https://api.coolapk.com/v6/picture/search"
        elif search_mode == 6:     # 用户
            url = "https://api.coolapk.com/v6/user/search"
        elif search_mode == 7:     # 动态
            url = "https://api.coolapk.com/v6/feed/search"
        else:  # search_mode == 8  # 评论
            url = "https://api.coolapk.com/v6/comment/search"

        mode = "search"
        response = self.__request_api(url, params, mode)
        return response

    def __parse_app_data(self, data):
        app_data = {}
        app_data['admin_score'] = float(data.get("adminscore"))
        app_data['apk_length'] = data.get("apklength")
        app_data['apk_md5'] = data.get("apkmd5")
        app_data['package_name'] = data.get("packageName")
        app_data['apk_size'] = data.get("apksize")
        app_data['version'] = data.get("version")
        app_data['description'] = data.get("description")
        app_data['developer_name'] = data.get("developername")
        app_data['keywords'] = data.get("keywords")
        last_comment_update = data.get("last_comment_update")
        app_data['last_comment_update'] = datetime.fromtimestamp(int(last_comment_update)) if last_comment_update else None
        app_data['last_update'] = datetime.fromtimestamp(int(data.get("lastupdate")))
        app_data['pub_date'] = datetime.fromtimestamp(int(data.get("pubdate")))
        app_data['logo'] = data.get("logo")
        app_data['reply_num'] = int(data.get("replynum"))
        app_data['score'] = float(data.get("score"))
        app_data['score_v10'] = data.get("score_v10")
        app_data['star'] = float(data.get("star"))
        app_data['title'] = data.get("title")
        app_data['vote_num'] = int(data.get("votenum"))
        app_data['id'] = int(data.get("id"))
        app_data['hot_num'] = int(data.get("hot_num"))
        app_data['follow_num'] = int(data.get("follownum"))
        app_data['fav_num'] = int(data.get("favnum"))
        app_data['download_num'] = int(data.get("downnum"))
        app_data['developer_uid'] = int(data.get("developeruid"))
        app_data['comment_num'] = int(data.get("commentnum"))
        app_data['apk_type'] = int(data.get("apktype"))
        app_data['apk_type_name'] = data.get("apkTypeName")
        app_data['entity_type'] = data.get("entityType")
        app_data['short_tags'] = data.get("shortTags")
        app_data['cat_name'] = data.get("catName")
        app_data['origin_data'] = data.get("originData", None)
        app_data['url'] = self.host + data.get("url")
        app_data['gather_time'] = datetime.now()
        return app_data

    def __parse_album_data(self, data):
        album_data = {}
        user = data.get("userInfo", None)
        user_data = self.__parse_user(user) if user else None
        album_data['description'] = data.get("description", None)
        album_data['id'] = int(data.get("id", None))
        album_data['user_id'] = int(data.get("uid", None))
        album_data['logo'] = data.get("logo", None)
        album_data['related_text'] = data.get("related_text", None)
        album_data['title'] = data.get("title", None)
        album_data['username'] = data.get("username", None)
        album_data['apk_num'] = int(data.get("apknum", None))
        album_data['click'] = int(data.get("click", None))
        album_data['comment_num'] = int(data.get("commentnum", None))
        album_data['create_at'] = datetime.fromtimestamp(int(data.get("dateline", None)))
        album_data['last_update'] = datetime.fromtimestamp(int(data.get("lastupdate", None)))
        last_comment = data.get("lastcomment", None)
        album_data['last_comment'] = datetime.fromtimestamp(int(last_comment)) if last_comment else None
        last_recommend = data.get("lastrecommend", None)
        album_data['last_comment'] = datetime.fromtimestamp(int(last_recommend)) if last_recommend else None
        album_data['fav_num'] = int(data.get("favnum", None))
        album_data['note_num'] = int(data.get("notenum", None))
        album_data['replynum'] = int(data.get("replynum", None))
        album_data['entity_type'] = data.get("entityType", None)
        album_data['url'] = self.host + data.get("url", None)
        return album_data, user_data

    def __parse_albums(self, albums):
        album_info = []
        user_info = []
        for album in albums:
            album_data, user_data = self.__parse_album_data(album)
            album_info.append(album_data)
            user_info.append(user_data)
        return album_info, self.__delete_duplicate(user_info)

    def search(self, keyword, search_mode=1, rank_type="default", max_page=10):
        page = 1
        app_infos = []
        feed_infos = []
        user_infos = []
        reply_infos = []
        album_infos = []
        if search_mode not in range(1, 8):
            return app_infos, feed_infos, user_infos, reply_infos, album_infos
        if rank_type not in ['default', 'follow', 'rating', 'comment', 'download', 'pubdate', 'lastupdate']:
            return app_infos, feed_infos, user_infos, reply_infos, album_infos
        while page <= max_page:
            response = self.__request_search(keyword, search_mode, page, rank_type)
            logger.info(f"search: {keyword}, total_page: {max_page}, current_page: {page}, search_mode: {search_mode}")
            page += 1
            data = response.get("data", None)
            if not data:
                break
            if search_mode in [4, 5, 7]:
                feed_info, user_info = self.__parse_feed_list(data)
                if feed_info:
                    feed_infos.extend(feed_info)
                if user_info:
                    user_infos.extend(user_info)
            elif search_mode == 6:
                for user in data:
                    user_infos.append(self.__parse_user(user))
            elif search_mode == 8:
                reply_info, user_info = self.__parse_feed_reply(data)
                if reply_info and user_info:
                    reply_infos.extend(reply_info)
                    user_infos.extend(user_info)
            elif search_mode in [1, 2]:
                for app in data:
                    app_infos.append(self.__parse_app_data(app))
            else:
                album_info, user_info = self.__parse_albums(data)
                if album_info:
                    album_infos.extend(album_info)
                if user_info:
                    user_infos.extend(user_info)

        return app_infos, feed_infos, user_infos, reply_infos, album_infos
