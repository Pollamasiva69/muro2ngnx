-- ==============================================================================
-- ACCESS CONTROL - Main security entry point
-- Checks whitelist, blacklist, threat scores, and coordinates with Redis
-- ==============================================================================

local redis = require "resty.redis"
local cjson = require "cjson"

-- Configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "127.0.0.1"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_TIMEOUT = 100 -- milliseconds

local WHITELIST_THRESHOLD = 30  -- IPs with threat score < 30 are whitelisted temporarily
local CHALLENGE_THRESHOLD = 61  -- IPs with threat score 61-80 get challenge
local BLOCK_THRESHOLD = 81      -- IPs with threat score > 80 are blocked

-- Shared dictionaries
local whitelist_dict = ngx.shared.whitelist
local blacklist_dict = ngx.shared.blacklist
local threat_scores_dict = ngx.shared.threat_scores

-- Helper function: Connect to Redis
local function connect_redis()
    local red = redis:new()
    red:set_timeout(REDIS_TIMEOUT)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: ", err)
        return nil
    end

    return red
end

-- Helper function: Close Redis connection (with connection pooling)
local function close_redis(red)
    if not red then
        return
    end

    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "Failed to set Redis keepalive: ", err)
    end
end

-- Helper function: Check if IP is whitelisted
local function is_whitelisted(ip)
    -- Check local cache first
    local cached = whitelist_dict:get(ip)
    if cached then
        return true
    end

    -- Check Redis
    local red = connect_redis()
    if not red then
        return false
    end

    local res, err = red:sismember("WHITELIST:ips", ip)
    close_redis(red)

    if res == 1 then
        -- Cache for 60 seconds
        whitelist_dict:set(ip, true, 60)
        return true
    end

    return false
end

-- Helper function: Check if IP is blacklisted
local function is_blacklisted(ip)
    -- Check local cache first
    local cached = blacklist_dict:get(ip)
    if cached then
        return true, cached
    end

    -- Check Redis (sorted set with expiry timestamp as score)
    local red = connect_redis()
    if not red then
        return false, nil
    end

    local score, err = red:zscore("BLACKLIST:ips", ip)
    close_redis(red)

    if not score or score == ngx.null then
        return false, nil
    end

    -- Check if blacklist entry has expired
    local now = ngx.time()
    if tonumber(score) < now then
        -- Expired, remove from blacklist
        local red2 = connect_redis()
        if red2 then
            red2:zrem("BLACKLIST:ips", ip)
            close_redis(red2)
        end
        return false, nil
    end

    -- Still blacklisted, cache locally
    local ttl = tonumber(score) - now
    blacklist_dict:set(ip, "Blacklisted", ttl)

    return true, "Blacklisted until " .. os.date("%Y-%m-%d %H:%M:%S", score)
end

-- Helper function: Get threat score for IP
local function get_threat_score(ip)
    -- Check local cache first
    local cached = threat_scores_dict:get(ip)
    if cached then
        return tonumber(cached)
    end

    -- Check Redis
    local red = connect_redis()
    if not red then
        return 0
    end

    local res, err = red:get("THREATSCORE:" .. ip)
    close_redis(red)

    if not res or res == ngx.null then
        return 0
    end

    local score = tonumber(res) or 0

    -- Cache for 30 seconds
    threat_scores_dict:set(ip, score, 30)

    return score
end

-- Helper function: Add IP to blacklist
local function add_to_blacklist(ip, duration)
    duration = duration or 3600  -- Default 1 hour

    local expiry = ngx.time() + duration

    -- Add to local cache
    blacklist_dict:set(ip, "Auto-blacklisted", duration)

    -- Add to Redis
    local red = connect_redis()
    if red then
        red:zadd("BLACKLIST:ips", expiry, ip)
        close_redis(red)
    end

    ngx.log(ngx.WARN, "IP ", ip, " blacklisted for ", duration, " seconds")
end

-- Helper function: Increment threat score
local function increment_threat_score(ip, increment)
    local red = connect_redis()
    if not red then
        return
    end

    red:incrby("THREATSCORE:" .. ip, increment)
    red:expire("THREATSCORE:" .. ip, 3600)  -- Expire after 1 hour
    close_redis(red)
end

-- Helper function: Check User-Agent blacklist
local function is_user_agent_blacklisted(user_agent)
    if not user_agent or user_agent == "" then
        return true, "No User-Agent"
    end

    local red = connect_redis()
    if not red then
        return false
    end

    local res, err = red:sismember("BLACKLIST:useragents", user_agent)
    close_redis(red)

    if res == 1 then
        return true, "User-Agent blacklisted"
    end

    -- Check for common attack patterns
    local ua_lower = string.lower(user_agent)
    local attack_patterns = {
        "sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
        "metasploit", "nessus", "acunetix", "appscan", "w3af"
    }

    for _, pattern in ipairs(attack_patterns) do
        if string.find(ua_lower, pattern, 1, true) then
            -- Add to blacklist
            local red2 = connect_redis()
            if red2 then
                red2:sadd("BLACKLIST:useragents", user_agent)
                close_redis(red2)
            end
            return true, "Attack tool detected: " .. pattern
        end
    end

    return false
end

-- Helper function: Check request method
local function is_method_allowed(method)
    local allowed_methods = {
        GET = true,
        POST = true,
        PUT = true,
        DELETE = true,
        PATCH = true,
        HEAD = true,
        OPTIONS = true
    }

    if not allowed_methods[method] then
        return false, "Method not allowed: " .. method
    end

    return true
end

-- Main execution
local function main()
    local ip = ngx.var.remote_addr
    local user_agent = ngx.var.http_user_agent or ""
    local method = ngx.req.get_method()
    local uri = ngx.var.request_uri

    -- 1. Check if whitelisted (bypass all checks)
    if is_whitelisted(ip) then
        ngx.var.threat_score = "0"
        ngx.var.blocked = "false"
        return
    end

    -- 2. Check if blacklisted
    local blacklisted, reason = is_blacklisted(ip)
    if blacklisted then
        ngx.var.threat_score = "100"
        ngx.var.blocked = "true"
        ngx.var.block_reason = reason

        ngx.log(ngx.WARN, "Blocked blacklisted IP: ", ip, " - ", reason)

        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Access Denied",
            message = "Your IP has been blacklisted",
            request_id = ngx.var.request_id
        }))
        return ngx.exit(403)
    end

    -- 3. Check User-Agent
    local ua_blacklisted, ua_reason = is_user_agent_blacklisted(user_agent)
    if ua_blacklisted then
        ngx.var.threat_score = "95"
        ngx.var.blocked = "true"
        ngx.var.block_reason = ua_reason

        -- Auto-blacklist IP
        add_to_blacklist(ip, 7200)  -- 2 hours

        ngx.log(ngx.WARN, "Blocked User-Agent: ", user_agent, " from IP: ", ip)

        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Access Denied",
            message = "Attack tool detected",
            request_id = ngx.var.request_id
        }))
        return ngx.exit(403)
    end

    -- 4. Check HTTP method
    local method_allowed, method_reason = is_method_allowed(method)
    if not method_allowed then
        ngx.var.threat_score = "70"
        ngx.var.blocked = "true"
        ngx.var.block_reason = method_reason

        increment_threat_score(ip, 10)

        ngx.log(ngx.WARN, "Blocked invalid method: ", method, " from IP: ", ip)

        ngx.status = 405
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Method Not Allowed",
            message = method_reason,
            request_id = ngx.var.request_id
        }))
        return ngx.exit(405)
    end

    -- 5. Get threat score from local cache or Redis
    local threat_score = get_threat_score(ip)
    ngx.var.threat_score = tostring(threat_score)

    -- 6. Take action based on threat score
    if threat_score >= BLOCK_THRESHOLD then
        -- Block immediately
        ngx.var.blocked = "true"
        ngx.var.block_reason = "High threat score: " .. threat_score

        -- Auto-blacklist
        add_to_blacklist(ip, 3600)  -- 1 hour

        ngx.log(ngx.WARN, "Blocked high threat IP: ", ip, " (score: ", threat_score, ")")

        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Access Denied",
            message = "Suspicious activity detected",
            request_id = ngx.var.request_id
        }))
        return ngx.exit(403)

    elseif threat_score >= CHALLENGE_THRESHOLD then
        -- Require challenge (handled by challenge.lua in specific locations)
        ngx.var.blocked = "false"
        ngx.var.block_reason = ""
        -- Let challenge.lua handle this

    else
        -- Allow with potential rate limiting
        ngx.var.blocked = "false"
        ngx.var.block_reason = ""
    end
end

-- Execute main function
local ok, err = pcall(main)
if not ok then
    ngx.log(ngx.ERR, "Error in access_control.lua: ", err)
    -- Allow request to proceed on error (fail open, but log it)
    ngx.var.threat_score = "0"
    ngx.var.blocked = "false"
end
