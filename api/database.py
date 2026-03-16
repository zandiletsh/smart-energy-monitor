"""
database.py — MongoDB connection, collections, and index setup
"""

import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import IndexModel, ASCENDING, DESCENDING
from schemas import MONGO_INDEXES
import os

logger = logging.getLogger(__name__)

MONGO_URL = os.getenv("MONGO_URL", "mongodb://mongo:27017")
MONGO_DB  = os.getenv("MONGO_DB",  "energy_monitor")


class MongoDB:
    client: AsyncIOMotorClient | None = None
    db:     AsyncIOMotorDatabase | None = None


db_state = MongoDB()


async def connect_db():
    db_state.client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    db_state.db     = db_state.client[MONGO_DB]
    logger.info(f"Connected to MongoDB: {MONGO_URL}/{MONGO_DB}")
    await ensure_indexes()


async def close_db():
    if db_state.client:
        db_state.client.close()
        logger.info("MongoDB connection closed")


async def ensure_indexes():
    for collection_name, indexes in MONGO_INDEXES.items():
        collection = db_state.db[collection_name]
        for idx in indexes:
            key_fields = [(f, ASCENDING if d == 1 else DESCENDING) for f, d in idx["key"]]
            kwargs = {k: v for k, v in idx.items() if k != "key"}
            try:
                await collection.create_index(key_fields, **kwargs)
            except Exception as e:
                logger.warning(f"Index on {collection_name}: {e}")
    logger.info("MongoDB indexes ensured")


def get_db() -> AsyncIOMotorDatabase:
    if db_state.db is None:
        raise RuntimeError("Database not initialised")
    return db_state.db
