# -*- coding:utf-8 -*-
"""
@author: XiangNan
@desc: Program debugging file
"""
from crawler.coolapk_mongo import CoolapkMongo
from crawler.coolapk_crawler import CoolapkSpider
from crawler import task

coolapk_mongo = CoolapkMongo()
coolapk_spider = CoolapkSpider()

# ------------------------------ test crawler ------------------------------ #
# 1. test get feed detail
# feed_id = "21894563"
# feed_data, user_data = coolapk_spider.get_feed_detail(feed_id)
# print(feed_data)
# print(user_data)

# 2. test get feed_ids from feed_list
# feedid_list = coolapk_spider.get_feed_ids_from_feed_list(max_page=3)
# print(feedid_list)
# print(len(feedid_list))

# 3. test get feed reply
# reply_infos, user_infos = coolapk_spider.get_feed_reply(feed_id="21932746")
# for reply in reply_infos:
#     print(reply['message'])
# print("*" * 100)
# for user in user_infos:
#     print(user['username'])
# print(len(reply_infos))
# print(len(user_infos))

# 4. test __request_feed_reply
# response = coolapk_spider.request_feed_reply(feed_id="21894563", page=3)
# print(response)

# 5. test get_user_feedlist
# feed_infos, user_infos = coolapk_spider.get_user_feedlist(user_id="1127996")
# for feed in feed_infos:
#     print(feed['message'])
#     print()
# print("*" * 100)
# for user in user_infos:
#     print(user['username'])
# print(len(feed_infos))
# print(len(user_infos))

# ------------------------------ test crawler ------------------------------ #

# ------------------------------  test mongo  ------------------------------ #
# 1. test update user
# coolapk_mongo.update_user(user_data)

# 2. test update feed
# coolapk_mongo.update_feed(feed_data)

# 3. find feed_ids to update
# feed_ids = coolapk_mongo.find_recent_feed_ids(recent_time=2)
# print(feed_ids)

# ------------------------------  test mongo  ------------------------------ #

# ------------------------------  test tasks  ------------------------------ #
# 1. update feed detail
# result = task.update_feed_detail()
# print(result)

# 2. get feed from feed_list and save to mongo
# result = task.get_feed_from_feed_list(max_page=15)
# print(f"feed_count: {result[0]}, user_count: {result[1]}")

# 3. get feed reply and save to mongo
result = task.update_feed_reply()
print(result)

# 4. get get user feeds from userhome and save to mongo
# result = task.update_user_feeds_from_userhome()
# print(result)

# 5. get update feed reply and save to mongo
# result = task.update_feed_reply()
# print(result)
# ------------------------------  test tasks  ------------------------------ #
