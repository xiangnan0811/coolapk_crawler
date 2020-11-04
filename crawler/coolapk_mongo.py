# -*- coding:utf-8 -*-
"""
@author: XiangNan
@desc: Retrieve, insert, and update information in MongoDB
"""
import pymongo
from loguru import logger
from datetime import datetime, timedelta
from crawler.config import MONGO_HOST, MONGO_PORT, MONGO_USERNAME, MONGO_PASSWORD, MONGO_DATABASE


class CoolapkMongo:

    def __init__(self):
        self.client = pymongo.MongoClient(host=MONGO_HOST, port=MONGO_PORT, username=MONGO_USERNAME,
                                          password=MONGO_PASSWORD)
        self.db = self.client[MONGO_DATABASE]
        self.user = self.db["user"]
        self.feed = self.db["feed"]
        self.app = self.db["app"]
        self.album = self.db["album"]
        self.feed_reply = self.db["feed_reply"]
        logger.add('../logs/mongo_{time}.log', format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
                   level="WARNING", rotation='00:00')

    def update_feed(self, feed):
        result = self.feed.update_one({"_id": feed["id"]}, {"$set": feed}, upsert=True)
        logger.info(f"update feed successfully feed id --> {feed['id']}")
        return result

    def update_reply(self, reply):
        result = self.feed_reply.update_one({"_id": reply['id']}, {"$set": reply}, upsert=True)
        logger.info(f"update reply successfully reply id --> {reply['id']}")
        return result

    def update_app(self, app):
        result = self.app.update_one({"_id": app["id"]}, {"$set": app}, upsert=True)
        logger.info(f"update app successfully app id --> {app['id']}")
        return result

    def update_album(self, album):
        result = self.album.update_one({"_id": album["id"]}, {"$set": album}, upsert=True)
        logger.info(f"update album successfully album id --> {album['id']}")
        return result

    def update_apps(self, apps):
        matched_count = 0
        modified_count = 0
        inserted_count = 0
        for app in apps:
            result = self.update_app(app)
            mat, mod, ins = self.__process_update_result(result)
            matched_count += mat
            modified_count += mod
            inserted_count += ins
        logger.warning(
            f"matched_count: {matched_count}, modified_count: {modified_count}, inserted_count: {inserted_count}")

    def update_albums(self, albums):
        matched_count = 0
        modified_count = 0
        inserted_count = 0
        for album in albums:
            result = self.update_album(album)
            mat, mod, ins = self.__process_update_result(result)
            matched_count += mat
            modified_count += mod
            inserted_count += ins
        logger.warning(
            f"matched_count: {matched_count}, modified_count: {modified_count}, inserted_count: {inserted_count}")

    def update_feeds(self, feeds):
        matched_count = 0
        modified_count = 0
        inserted_count = 0
        for feed in feeds:
            result = self.update_feed(feed)
            mat, mod, ins = self.__process_update_result(result)
            matched_count += mat
            modified_count += mod
            inserted_count += ins
        logger.warning(
            f"matched_count: {matched_count}, modified_count: {modified_count}, inserted_count: {inserted_count}")

    def update_replies(self, replies):
        matched_count = 0
        modified_count = 0
        inserted_count = 0
        for reply in replies:
            result = self.update_reply(reply)
            mat, mod, ins = self.__process_update_result(result)
            matched_count += mat
            modified_count += mod
            inserted_count += ins
        logger.warning(
            f"matched_count: {matched_count}, modified_count: {modified_count}, inserted_count: {inserted_count}")

    def update_user(self, user):
        result = self.user.update_one(
            {"_id": user["id"]},
            {"$set": user},
            upsert=True
        )
        logger.info(f"update user successfully user id --> {user['id']}")
        return result

    def update_users(self, users):
        matched_count = 0
        modified_count = 0
        inserted_count = 0
        for user in users:
            result = self.update_user(user)
            mat, mod, ins = self.__process_update_result(result)
            matched_count += mat
            modified_count += mod
            inserted_count += ins
        logger.warning(
            f"matched_count: {matched_count}, modified_count: {modified_count}, inserted_count: {inserted_count}")

    def find_recent_feed_ids(self, after_time=1, before_time=0, limit=20000):
        after_time = timedelta(days=after_time)
        before_time = timedelta(hours=before_time)
        now = datetime.now()
        before = now - before_time
        after = now - after_time
        result = self.feed.aggregate([
            {
                '$match': {
                    'gather_time': {
                        '$lte': before,
                        '$gte': after,
                    },
                    'status': {
                        "$nin": ['deleted', 'unauthorized', 'unknown']
                    }
                }
            }, {
                '$project': {
                    '_id': 1
                }
            }, {
                '$limit': limit,
            }
        ], batchSize=10000)
        feed_ids = [feed_id['_id'] for feed_id in list(result)]
        return feed_ids

    def find_recent_user_ids(self, after_time=1, before_time=0, limit=20000):
        after_time = timedelta(days=after_time)
        before_time = timedelta(hours=before_time)
        now = datetime.now()
        before = now - before_time
        after = now - after_time
        result = self.user.aggregate([
            {
                '$match': {
                    'gather_time': {
                        '$lte': before,
                        '$gte': after,
                    },
                    'status': {
                        "$nin": ['deleted', 'unauthorized', 'unknown']
                    }
                }
            }, {
                '$project': {
                    '_id': 1
                }
            }, {
                '$limit': limit,
            }
        ], batchSize=10000)
        user_ids = [res['_id'] for res in result]
        return user_ids

    @staticmethod
    def __process_update_result(result):
        matched_count = 0
        inserted_count = 0
        modified_count = 0
        if result.matched_count and result.modified_count:
            matched_count = 1
            modified_count = 1
        if not result.matched_count and not result.modified_count:
            inserted_count = 1
        if result.matched_count and not result.modified_count:
            matched_count = 1

        return matched_count, modified_count, inserted_count

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()
