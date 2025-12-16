# -*- coding: utf-8 -*-
"""
Created on 2025-11-19
---------
@summary: 域名级QPS限制器（漏桶算法）
---------
@author: feapder
"""

import time
import threading
from typing import Dict
from urllib.parse import urlparse

import feapder.setting as setting
from feapder.db.redisdb import RedisDB
from feapder.utils.log import log


class LocalLeakyBucket:
    """
    @summary: 本地内存版漏桶，用于AirSpider（单机爬虫）
    ---------
    严格匀速控制，不允许突发流量
    线程安全，适用于多线程环境
    """

    def __init__(self, qps: int):
        """
        @summary: 初始化漏桶
        ---------
        @param qps: 每秒允许的请求数（Queries Per Second）
        """
        self.qps = qps
        self.interval = 1.0 / qps  # 两次请求的最小间隔（秒）
        self.last_time = 0.0  # 上次请求时间
        self.lock = threading.Lock()

    def acquire(self) -> float:
        """
        @summary: 尝试获取通行权
        ---------
        @result: 0表示可以立即通行，>0表示需要等待的秒数
        """
        with self.lock:
            now = time.time()
            next_allowed = self.last_time + self.interval

            if now >= next_allowed:
                # 可以立即通行
                self.last_time = now
                return 0
            else:
                # 需要等待，预占下一个时间槽
                wait_time = next_allowed - now
                self.last_time = next_allowed
                return wait_time


class RedisLeakyBucket:
    """
    @summary: Redis分布式漏桶，用于Spider/TaskSpider/BatchSpider（分布式爬虫）
    ---------
    严格匀速控制，不允许突发流量
    使用Lua脚本保证原子性，支持多机器共享QPS配额
    """

    # Lua脚本：原子性地检查并获取通行权
    # 关键：每次请求都预占一个时间槽，确保多机器分布式场景下严格限流
    ACQUIRE_SCRIPT = """
    local key = KEYS[1]
    local interval = tonumber(ARGV[1])
    local now = tonumber(ARGV[2])

    -- 获取上次预占的时间槽（不存在则返回nil）
    local last_scheduled_str = redis.call('GET', key)
    local last_scheduled = last_scheduled_str and tonumber(last_scheduled_str) or nil

    -- 计算本次请求应该被调度的时间
    -- scheduled_time = max(now, last_scheduled + interval)
    -- 确保：空闲时立即执行，并发时严格按interval排队
    local scheduled_time
    if last_scheduled == nil then
        -- 首次请求，立即执行
        scheduled_time = now
    else
        -- 计算下一个可用时间槽
        local next_slot = last_scheduled + interval
        if now > next_slot then
            scheduled_time = now
        else
            scheduled_time = next_slot
        end
    end

    -- 计算需要等待的时间
    local wait_time = scheduled_time - now
    if wait_time < 0 then
        wait_time = 0
    end

    -- 预占时间槽，使用string.format保留精度（6位小数）
    redis.call('SET', key, string.format('%.6f', scheduled_time))
    redis.call('EXPIRE', key, 3600)

    -- 返回字符串格式保留精度（Redis会将浮点数截断为整数）
    return string.format('%.6f', wait_time)
    """

    def __init__(self, redis_db: RedisDB, rate_limit_key: str, qps: int):
        """
        @summary: 初始化Redis漏桶
        ---------
        @param redis_db: RedisDB实例
        @param rate_limit_key: Redis中的key，格式: {redis_key}:h_rate_limit:{domain}
        @param qps: 每秒允许的请求数
        """
        self.redis = redis_db._redis
        self.rate_limit_key = rate_limit_key
        self.qps = qps
        self.interval = 1.0 / qps  # 两次请求的最小间隔（秒）
        self.acquire_sha = None  # Lua脚本的SHA值（延迟加载）

    def _ensure_script_loaded(self):
        """
        @summary: 确保Lua脚本已加载到Redis
        """
        if not self.acquire_sha:
            try:
                self.acquire_sha = self.redis.script_load(self.ACQUIRE_SCRIPT)
            except Exception as e:
                log.error(f"加载Lua脚本失败: {e}")
                raise

    def acquire(self) -> float:
        """
        @summary: 尝试获取通行权
        ---------
        @result: 0表示可以立即通行，>0表示需要等待的秒数
        """
        try:
            self._ensure_script_loaded()
            now = time.time()

            # 执行Lua脚本（原子操作）
            wait_time = self.redis.evalsha(
                self.acquire_sha,
                1,  # KEYS数量
                self.rate_limit_key,  # KEYS[1]
                self.interval,  # ARGV[1]
                now,  # ARGV[2]
            )

            return float(wait_time)

        except Exception as e:
            # Redis异常时放行请求，避免阻塞爬虫
            log.error(f"Redis漏桶异常: {e}, 放行请求")
            return 0


class DomainRateLimiter:
    """
    @summary: 域名级QPS限制器（统一管理器）
    ---------
    采用漏桶算法，严格匀速控制，不允许突发流量
    适合爬虫场景，避免突发请求导致被封IP

    职责:
    1. 自动检测Spider类型（AirSpider使用本地内存，分布式Spider使用Redis）
    2. 为每个域名创建对应的漏桶
    3. 提供统一的acquire接口
    """

    def __init__(self, rules: Dict[str, int] = None, default_qps: int = None, storage: str = None):
        """
        @summary: 初始化限速器
        ---------
        @param rules: QPS规则，格式: {"baidu.com": 5, "*.google.com": 8}
        @param default_qps: 默认QPS限制，0表示不限制
        @param storage: 存储类型，"local"/"memory"或"redis"，默认从setting读取或自动检测
        """
        self.rules = rules or getattr(setting, "DOMAIN_RATE_LIMIT_RULES", {}) or {}
        self.default_qps = (
            default_qps
            if default_qps is not None
            else getattr(setting, "DOMAIN_RATE_LIMIT_DEFAULT", 0)
        )
        # 优先使用传入的storage，否则从setting读取
        self.storage = storage or getattr(setting, "DOMAIN_RATE_LIMIT_STORAGE", "auto")

        self.local_buckets: Dict[str, LocalLeakyBucket] = {}  # 本地漏桶缓存
        self.redis_buckets: Dict[str, RedisLeakyBucket] = {}  # Redis漏桶缓存
        self.redis_db = None  # Redis连接（延迟初始化）
        self.use_redis = self._should_use_redis(self.storage)

    def _should_use_redis(self, storage: str = None) -> bool:
        """
        @summary: 判断是否应该使用Redis
        ---------
        @param storage: 存储类型配置
        ---------
        @result: True使用Redis（分布式爬虫），False使用本地内存（AirSpider）
        """
        if storage:
            storage = storage.lower()
            if storage in ("local", "memory"):
                return False
            if storage == "redis":
                return True

        # auto模式：检查是否配置了Redis连接
        if hasattr(setting, "REDISDB_IP_PORTS") and setting.REDISDB_IP_PORTS:
            return True
        return False

    def _get_redis_db(self):
        """
        @summary: 获取Redis连接（单例模式）
        """
        if not self.redis_db:
            self.redis_db = RedisDB()
        return self.redis_db

    def _get_rate_limit_key(self, request, domain: str) -> str:
        """
        @summary: 生成QPS限制的Redis key
        ---------
        @param request: 请求对象
        @param domain: 域名
        ---------
        @result: Redis key，格式: {redis_key}:h_rate_limit:{domain}
        """
        # 延迟导入避免循环依赖
        from feapder.network.request import Request

        # 优先从Request类变量获取（分布式Spider）
        redis_key = getattr(Request, "cached_redis_key", None)

        if not redis_key:
            # AirSpider情况，使用parser_name
            redis_key = getattr(request, "parser_name", None) or "default"

        return setting.TAB_RATE_LIMIT.format(redis_key=redis_key, domain=domain)

    def _get_local_bucket(self, domain: str, qps: int) -> LocalLeakyBucket:
        """
        @summary: 获取本地漏桶（带缓存）
        ---------
        @param domain: 域名
        @param qps: QPS限制
        ---------
        @result: LocalLeakyBucket实例
        """
        cache_key = f"{domain}:{qps}"

        if cache_key not in self.local_buckets:
            self.local_buckets[cache_key] = LocalLeakyBucket(qps)

        return self.local_buckets[cache_key]

    def _get_redis_bucket(self, rate_limit_key: str, qps: int) -> RedisLeakyBucket:
        """
        @summary: 获取Redis漏桶（带缓存）
        ---------
        @param rate_limit_key: Redis key
        @param qps: QPS限制
        ---------
        @result: RedisLeakyBucket实例
        """
        cache_key = f"{rate_limit_key}:{qps}"

        if cache_key not in self.redis_buckets:
            redis_db = self._get_redis_db()
            self.redis_buckets[cache_key] = RedisLeakyBucket(
                redis_db, rate_limit_key, qps
            )

        return self.redis_buckets[cache_key]

    def get_qps_limit(self, domain: str) -> int:
        """
        @summary: 获取域名的QPS限制
        ---------
        @param domain: 域名
        ---------
        @result: QPS限制值，0表示不限制

        规则优先级:
        1. 精确匹配（如 baidu.com）
        2. 通配符匹配（如 *.google.com）
        3. www回退（www.example.com -> example.com）
        4. 默认值
        """
        if not domain:
            return 0

        rules = self.rules or {}

        # 精确匹配
        if domain in rules:
            return rules[domain]

        # 通配符匹配
        for pattern, qps in rules.items():
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if domain.endswith("." + suffix):
                    return qps

        # www回退
        if domain.startswith("www."):
            domain_without_www = domain[4:]
            if domain_without_www in rules:
                return rules[domain_without_www]
            for pattern, qps in rules.items():
                if pattern.startswith("*.") and domain_without_www.endswith("." + pattern[2:]):
                    return qps

        return self.default_qps

    def acquire(self, request, domain: str, qps_limit: int) -> float:
        """
        @summary: 尝试获取通行权（统一入口）
        ---------
        @param request: 请求对象
        @param domain: 域名
        @param qps_limit: QPS限制
        ---------
        @result: 0表示可立即通行，>0表示需要等待的秒数

        根据Spider类型自动选择本地或Redis漏桶
        """
        if qps_limit is None or qps_limit <= 0:
            return 0

        if self.use_redis:
            # 分布式爬虫：使用Redis漏桶
            rate_limit_key = self._get_rate_limit_key(request, domain)
            bucket = self._get_redis_bucket(rate_limit_key, qps_limit)
        else:
            # 单机爬虫：使用本地内存漏桶
            bucket = self._get_local_bucket(domain, qps_limit)

        return bucket.acquire()

    def acquire_for_domain(self, request, domain: str) -> float:
        """
        @summary: 按配置规则自动获取指定域名的通行权
        ---------
        @param request: 请求对象
        @param domain: 域名
        ---------
        @result: 0表示可立即通行，>0表示需要等待的秒数
        """
        qps_limit = self.get_qps_limit(domain)
        return self.acquire(request, domain, qps_limit)

    @staticmethod
    def extract_domain(url: str) -> str:
        """
        @summary: 从URL提取域名
        ---------
        @param url: 完整URL
        ---------
        @result: 域名，提取失败返回空字符串
        """
        if not url:
            return ""

        try:
            parsed = urlparse(url)
            domain = parsed.hostname or parsed.netloc

            # 去除端口号
            if domain and ":" in domain:
                domain = domain.split(":")[0]

            return domain or ""
        except Exception as e:
            log.error(f"域名提取失败: {url}, 错误: {e}")
            return ""
