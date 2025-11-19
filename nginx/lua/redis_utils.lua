-- ==============================================================================
-- REDIS UTILITIES
-- Shared Redis helper functions for Lua scripts
-- ==============================================================================

local redis = require "resty.redis"

local _M = {}

-- Configuration
_M.REDIS_HOST = os.getenv("REDIS_HOST") or "127.0.0.1"
_M.REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
_M.REDIS_TIMEOUT = 100  -- milliseconds

-- Connect to Redis
function _M.connect()
    local red = redis:new()
    red:set_timeout(_M.REDIS_TIMEOUT)

    local ok, err = red:connect(_M.REDIS_HOST, _M.REDIS_PORT)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: ", err)
        return nil, err
    end

    return red, nil
end

-- Close Redis connection with pooling
function _M.close(red)
    if not red then
        return
    end

    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "Failed to set Redis keepalive: ", err)
    end
end

-- Increment counter with expiry
function _M.incr_with_expiry(key, expiry)
    local red, err = _M.connect()
    if not red then
        return nil, err
    end

    local count, err = red:incr(key)
    if not count then
        _M.close(red)
        return nil, err
    end

    if count == 1 then
        -- First increment, set expiry
        red:expire(key, expiry)
    end

    _M.close(red)
    return count, nil
end

-- Get value with default
function _M.get_with_default(key, default)
    local red, err = _M.connect()
    if not red then
        return default
    end

    local value, err = red:get(key)
    _M.close(red)

    if not value or value == ngx.null then
        return default
    end

    return value
end

-- Set value with expiry
function _M.setex(key, value, expiry)
    local red, err = _M.connect()
    if not red then
        return false, err
    end

    local ok, err = red:setex(key, expiry, value)
    _M.close(red)

    if not ok then
        return false, err
    end

    return true, nil
end

-- Add to set
function _M.sadd(key, member)
    local red, err = _M.connect()
    if not red then
        return false, err
    end

    local ok, err = red:sadd(key, member)
    _M.close(red)

    if not ok then
        return false, err
    end

    return true, nil
end

-- Check if member in set
function _M.sismember(key, member)
    local red, err = _M.connect()
    if not red then
        return false, err
    end

    local res, err = red:sismember(key, member)
    _M.close(red)

    if not res then
        return false, err
    end

    return res == 1, nil
end

-- Add to sorted set with score
function _M.zadd(key, score, member)
    local red, err = _M.connect()
    if not red then
        return false, err
    end

    local ok, err = red:zadd(key, score, member)
    _M.close(red)

    if not ok then
        return false, err
    end

    return true, nil
end

-- Get score from sorted set
function _M.zscore(key, member)
    local red, err = _M.connect()
    if not red then
        return nil, err
    end

    local score, err = red:zscore(key, member)
    _M.close(red)

    if not score or score == ngx.null then
        return nil, "not found"
    end

    return tonumber(score), nil
end

-- Remove from sorted set
function _M.zrem(key, member)
    local red, err = _M.connect()
    if not red then
        return false, err
    end

    local ok, err = red:zrem(key, member)
    _M.close(red)

    return ok ~= nil, err
end

-- Hash operations
function _M.hset(key, field, value)
    local red, err = _M.connect()
    if not red then
        return false, err
    end

    local ok, err = red:hset(key, field, value)
    _M.close(red)

    return ok ~= nil, err
end

function _M.hget(key, field)
    local red, err = _M.connect()
    if not red then
        return nil, err
    end

    local value, err = red:hget(key, field)
    _M.close(red)

    if not value or value == ngx.null then
        return nil, "not found"
    end

    return value, nil
end

function _M.hgetall(key)
    local red, err = _M.connect()
    if not red then
        return nil, err
    end

    local res, err = red:hgetall(key)
    _M.close(red)

    if not res then
        return nil, err
    end

    -- Convert flat array to hash table
    local hash = {}
    for i = 1, #res, 2 do
        hash[res[i]] = res[i + 1]
    end

    return hash, nil
end

-- Execute Lua script on Redis
function _M.eval_script(script, num_keys, ...)
    local red, err = _M.connect()
    if not red then
        return nil, err
    end

    local res, err = red:eval(script, num_keys, ...)
    _M.close(red)

    return res, err
end

-- Rate limiting using Redis (atomic operation)
function _M.rate_limit(key, limit, window)
    local script = [[
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local current = tonumber(redis.call('GET', key) or '0')

        if current >= limit then
            return {current, -1}  -- Limit exceeded
        end

        local count = redis.call('INCR', key)
        if count == 1 then
            redis.call('EXPIRE', key, window)
        end

        return {count, limit - count}  -- Current count, remaining
    ]]

    local res, err = _M.eval_script(script, 1, key, limit, window)

    if not res then
        return nil, nil, err
    end

    return res[1], res[2], nil  -- count, remaining
end

return _M
