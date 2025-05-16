import redis
from dotenv import load_dotenv
import os
import json

load_dotenv(".env", override=True)
password = os.getenv("REDIS_PASSWORD")

r = redis.Redis(
    host='redis-10863.c250.eu-central-1-1.ec2.redns.redis-cloud.com',
    port=10863,
    decode_responses=True,
    username="default",
    password=password,
)

try:
    r.ping()
    print("Redis connected successfully.")
except redis.exceptions.ConnectionError as e:
    print("Redis connection failed:", e)
    

# filter by key
bicycle = r.scan_iter("sample_bicycle:*")


# retrieve data from redis
for key in bicycle:
    data = r.json().get(key)
    print(data)
    

# edit