# -*- coding:utf-8 -*-
"""
@author: XiangNan
@desc: Retrieve, insert, and update information in MongoDB
"""
import pymongo
from loguru import logger
from datetime import datetime, timedelta, timezone
from crawler.config import MONGO_HOST, MONGO_PORT, MONGO_USERNAME, MONGO_PASSWORD, MONGO_DATABASE


class CoolapkMongo:

    def __init__(self):
        self.client = pymongo.MongoClient(host=MONGO_HOST, port=MONGO_PORT, username=MONGO_USERNAME, password=MONGO_PASSWORD)
        self.db = self.client[MONGO_DATABASE]
        self.user = self.db["user"]
        self.feed = self.db["feed"]
        self.feed_reply = self.db["feed_reply"]
        logger.add('../logs/mongo.log', format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}", level="INFO")

    def update_feed(self, feed):
        result = self.feed.update_one({"_id": feed["id"]}, {"$set": feed}, upsert=True)
        logger.info(self.__process_update_result(result))

    def update_reply(self, reply):
        result = self.feed_reply.update_one({"_id": reply['id']}, {"$set": reply}, upsert=True)
        logger.info(self.__process_update_result(result))

    def update_feeds(self, feeds):
        for feed in feeds:
            self.update_feed(feed)

    def update_replies(self, replies):
        for reply in replies:
            self.update_reply(reply)

    def update_user(self, user):
        result = self.user.update_one(
            {"_id": user["id"]},
            {"$set": user},
            upsert=True
        )
        logger.info(self.__process_update_result(result))

    def update_users(self, users):
        for user in users:
            self.update_user(user)
            
    def find_recent_feed_ids(self, recent_time=1):
        recent_time = timedelta(days=recent_time)
        now = datetime.now()
        result = self.feed.aggregate([
            {
                '$match': {
                    'gather_time': {
                        '$lte': now,
                        '$gte': now - recent_time,
                    }
                }
            }, {
                '$project': {
                    '_id': 1
                }
            }
        ])
        feed_ids = [feed_id['_id'] for feed_id in list(result)]
        return feed_ids

    def find_recent_user_ids(self, recent_time=1):
        recent_time = timedelta(days=recent_time)
        now = datetime.now()
        result = self.user.aggregate([
            {
                '$match': {
                    'gather_time': {
                        '$lte': now,
                        '$gte': now - recent_time,
                    }
                }
            }, {
                '$project': {
                    '_id': 1
                }
            }
        ])
        user_ids = [user_id['_id'] for user_id in list(result)]
        return user_ids

    @staticmethod
    def __process_update_result(result):
        return f"matched_count: {result.matched_count},modified_count: {result.modified_count}"
