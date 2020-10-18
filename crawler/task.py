from crawler.coolapk_crawler import CoolapkSpider
from crawler.coolapk_mongo import CoolapkMongo
from crawler.config import UPDATE_USER_FEEDS_AFTER, UPDATE_USER_FEEDS_BEFORE, UPDATE_LIMIT

coolapk_mongo = CoolapkMongo()
coolapk_crawler = CoolapkSpider()


def update_feed_detail():
    feed_ids = coolapk_mongo.find_recent_feed_ids(after_time=UPDATE_USER_FEEDS_AFTER, before_time=UPDATE_USER_FEEDS_BEFORE, limit=UPDATE_LIMIT)
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
    user_ids = coolapk_mongo.find_recent_user_ids(after_time=UPDATE_USER_FEEDS_AFTER, before_time=UPDATE_USER_FEEDS_BEFORE, limit=UPDATE_LIMIT)
    print(len(user_ids))
    result = get_user_feeds_from_userhome(user_ids)
    return result


def update_feed_reply():
    feed_ids = coolapk_mongo.find_recent_feed_ids(after_time=UPDATE_USER_FEEDS_AFTER, before_time=UPDATE_USER_FEEDS_BEFORE, limit=UPDATE_LIMIT)
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


def search_feed(keywords, max_page=150):
    feed_count = 0
    user_count = 0
    for keyword in keywords:
        _, feed_infos, user_infos, _, _ = coolapk_crawler.search(keyword, search_mode=7, max_page=max_page)
        if feed_infos:
            feed_count += len(feed_infos)
            coolapk_mongo.update_feeds(feed_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return feed_count, user_count


def search_picture(keywords, max_page=150):
    feed_count = 0
    user_count = 0
    for keyword in keywords:
        _, feed_infos, user_infos, _, _ = coolapk_crawler.search(keyword, search_mode=5, max_page=max_page)
        if feed_infos:
            feed_count += len(feed_infos)
            coolapk_mongo.update_feeds(feed_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return feed_count, user_count


def search_discovery(keywords, max_page=150):
    feed_count = 0
    user_count = 0
    for keyword in keywords:
        _, feed_infos, user_infos, _, _ = coolapk_crawler.search(keyword, search_mode=4, max_page=max_page)
        if feed_infos:
            feed_count += len(feed_infos)
            coolapk_mongo.update_feeds(feed_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return feed_count, user_count


def search_reply(keywords, max_page=150):
    reply_count = 0
    user_count = 0
    for keyword in keywords:
        _, _, user_infos, reply_infos, _ = coolapk_crawler.search(keyword, search_mode=8, max_page=max_page)
        if reply_infos:
            reply_count += len(reply_infos)
            coolapk_mongo.update_replies(reply_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return reply_count, user_count


def search_album(keywords, max_page=50):
    album_count = 0
    user_count = 0
    for keyword in keywords:
        _, _, user_infos, _, album_infos = coolapk_crawler.search(keyword, search_mode=3, max_page=max_page)
        if album_infos:
            album_count += len(album_infos)
            coolapk_mongo.update_albums(album_infos)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return album_count, user_count


def search_apk(keywords, max_page=50):
    app_count = 0
    for keyword in keywords:
        app_infos, _, _, _, _ = coolapk_crawler.search(keyword, search_mode=1, max_page=max_page, rank_type="default")
        if app_infos:
            app_count += len(app_infos)
            coolapk_mongo.update_apps(app_infos)
    return app_count


def search_game(keywords, max_page=50):
    game_count = 0
    for keyword in keywords:
        game_infos, _, _, _, _ = coolapk_crawler.search(keyword, search_mode=2, max_page=max_page, rank_type="default")
        if game_infos:
            game_count += len(game_infos)
            coolapk_mongo.update_apps(game_infos)
    return game_count


def search_user(keywords, max_page=50):
    user_count = 0
    for keyword in keywords:
        _, _, user_infos, _, _ = coolapk_crawler.search(keyword, search_mode=6, max_page=max_page)
        if user_infos:
            user_count += len(user_infos)
            coolapk_mongo.update_users(user_infos)
    return user_count
