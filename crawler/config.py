# -*- coding:utf-8 -*-
"""
@author: XiangNan
@desc: Program configuration information such as constants
"""

# the max times to request the API when occurred an error
MAX_RETRY_TIMES = 3

# Mongo configuration
MONGO_HOST = "XXX"
MONGO_PORT = 27017
MONGO_USERNAME = "coolapk"
MONGO_PASSWORD = "XXX"
MONGO_DATABASE = "coolapk"

# device_id list
DEVICE_LIST = [
    "XXX",
    "XXX",
]

# the recent of feed to update, unit: day
FEED_TO_UPDATE_DAYS = 5

# the recent time to update user feeds, unit: day
UPDATE_USER_FEEDS_DAYS = 5

# max sleep time while requesting api, unit: second
MAX_SLEEP_TIME = 3
