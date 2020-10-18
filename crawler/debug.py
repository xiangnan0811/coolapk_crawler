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

# 6. test search
# result = coolapk_spider.search(keyword="MT管理器", max_page=2)
# print(result[0])
# print(result[1])
# print(result[2])
# print(result[3])
# print(result[4])
# print(len(result[0]), len(result[1]), len(result[2]), len(result[3]), len(result[4]))

# ------------------------------ test crawler ------------------------------ #

# ------------------------------  test mongo  ------------------------------ #
# 1. test update user
# coolapk_mongo.update_user(user_data)

# 2. test update feed
# coolapk_mongo.update_feed(feed_data)

# 3. find feed_ids to update
# feed_ids = coolapk_mongo.find_recent_feed_ids(recent_time=2)
# print(feed_ids)

# 4. test modified_count matched_count
# result = coolapk_mongo.update_app({"id": 67678, "name": "杜甫"})
# print(result)

# ------------------------------  test mongo  ------------------------------ #

# ------------------------------  test tasks  ------------------------------ #
# 1. update feed detail
# result = task.update_feed_detail()
# print(result)

# 2. get feed from feed_list and save to mongo
# result = task.get_feed_from_feed_list(max_page=150)
# print(f"feed_count: {result[0]}, user_count: {result[1]}")

# 3. get feed reply and save to mongo
# result = task.update_feed_reply()
# print(result)

# 4. get get user feeds from userhome and save to mongo
# result = task.update_user_feeds_from_userhome()
# print(result)

# 5. get update feed reply and save to mongo
# result = task.update_feed_reply()
# print(result)

# 6. search_feed
keywords = ["破解", "magisk", "刷机", "模块", "风景", "美女", "高清", "4k", "教程", "理财", "壁纸", "美", "magisk", "xposed",
            "能量", "模块", "论坛", "微博", "球", "王者荣耀", "微博", "美", "上分", "基金", "绿色版", "面具", "想不到", "一加",
            "华为", 'OPPO', 'VIVO', '三星', 'SAMSUNG', 'APPLE', 'apple', '苹果', '银行', '锤子', '努比亚', '小米', '红米',
            'realme', 'redmi', '诺基亚', 'nokia', 'HTC', 'htc', '荣耀', 'honor', 'iqoo', 'iQOO', '魅族', 'nubia', '联想',
            'Moto', '摩托罗拉', '黑鲨', '黑莓', 'ROG', 'google', '谷歌', '佳能', '尼康', '松下', '耳机', '降噪', '真无线',
            'qq', '音乐', 'root', '天气', '阅读', 'iphone12', '原神', '图标包', 'kwgt', '桌面', '充电', '相机', 'airpods']

result = task.search_feed(keywords)
print(f"feed_count --> {result[0]}, user_count --> {result[1]}")

# 7. search_picture
result = task.search_picture(keywords)
print(f"feed_count --> {result[0]}, user_count --> {result[1]}")

# 8. search_discovery
result = task.search_discovery(keywords)
print(f"feed_count --> {result[0]}, user_count --> {result[1]}")

# 9. search_album
result = task.search_album(keywords)
print(f"album_count --> {result[0]}, user_count --> {result[1]}")

# 10. search_apk
result = task.search_apk(keywords)
print(f"app_count --> {result}")

# 11. search_game
result = task.search_game(keywords)
print(f"game_count --> {result}")

# 12. search_user
result = task.search_user(keywords)
print(f"user_count --> {result}")

# ------------------------------  test tasks  ------------------------------ #
