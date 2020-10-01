from crawler.coolapk_crawler import CoolapkSpider
from crawler.coolapk_mongo import CoolapkMongo
from crawler.config import FEED_TO_UPDATE_DAYS, UPDATE_USER_FEEDS_DAYS

coolapk_mongo = CoolapkMongo()
coolapk_crawler = CoolapkSpider()


def update_feed_detail():
    feed_ids = coolapk_mongo.find_recent_feed_ids(recent_time=FEED_TO_UPDATE_DAYS)
    print(len(feed_ids))
    result = get_feed_detail_and_save(feed_ids)
    return result


def get_feed_detail_and_save(feed_ids):
    feed_count = 0
    user_count = 0
    for feed_id in feed_ids:
        feed, user = coolapk_crawler.get_feed_detail(feed_id=feed_id)
        if feed:
            feed_count += 1
            coolapk_mongo.update_feed(feed)
        if user:
            user_count += 1
            coolapk_mongo.update_user(user)
    return feed_count, user_count


def get_user_feeds_from_userhome(user_ids):
    feed_count = 0
    user_count = 0
    for user_id in user_ids:
        feed_infos, user_infos = coolapk_crawler.get_user_feedlist(user_id)
        if feed_infos:
            feed_count += len(feed_infos)
            coolapk_mongo.update_feeds(feed_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return feed_count, user_count


def update_user_feeds_from_userhome():
    user_ids = coolapk_mongo.find_recent_user_ids(recent_time=UPDATE_USER_FEEDS_DAYS)
    result = get_user_feeds_from_userhome(user_ids)
    return result


def update_feed_reply():
    feed_ids = coolapk_mongo.find_recent_feed_ids(recent_time=FEED_TO_UPDATE_DAYS)
    print(len(feed_ids))
    result = get_feed_reply(feed_ids)
    return result


def get_feed_reply(feed_ids):
    reply_count = 0
    user_count = 0
    for feed_id in feed_ids:
        reply_infos, user_infos = coolapk_crawler.get_feed_reply(feed_id=feed_id)
        if reply_infos:
            reply_count += len(reply_infos)
            coolapk_mongo.update_replies(reply_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return reply_count, user_count


def get_feed_from_feed_list(max_page=10):
    feed_infos, user_infos = coolapk_crawler.get_feeds_from_feed_list(max_page=max_page)
    if feed_infos:
        coolapk_mongo.update_feeds(feed_infos)
    if user_infos:
        coolapk_mongo.update_users(user_infos)
    return len(feed_infos), len(user_infos)
