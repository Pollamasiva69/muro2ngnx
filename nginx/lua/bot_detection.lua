-- ==============================================================================
-- BOT DETECTION
-- Advanced bot detection using behavioral analysis and fingerprinting
-- ==============================================================================

local redis = require "resty.redis"
local cjson = require "cjson"

-- Configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "127.0.0.1"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_TIMEOUT = 100

-- Known good bots (search engines, etc.)
local GOOD_BOTS = {
    ["Googlebot"] = true,
    ["Bingbot"] = true,
    ["Slurp"] = true,  -- Yahoo
    ["DuckDuckBot"] = true,
    ["Baiduspider"] = true,
    ["YandexBot"] = true,
    ["facebookexternalhit"] = true,
    ["ia_archiver"] = true,  -- Alexa
}

-- Known bad bots
local BAD_BOTS = {
    ["MJ12bot"] = true,
    ["AhrefsBot"] = true,
    ["SemrushBot"] = true,
    ["DotBot"] = true,
    ["serpstatbot"] = true,
    ["BLEXBot"] = true,
    ["PetalBot"] = true,
}

-- Helper function: Connect to Redis
local function connect_redis()
    local red = redis:new()
    red:set_timeout(REDIS_TIMEOUT)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil
    end

    return red
end

-- Helper function: Close Redis connection
local function close_redis(red)
    if not red then
        return
    end

    red:set_keepalive(10000, 100)
end

-- Helper function: Check if User-Agent is a known bot
local function classify_user_agent(user_agent)
    if not user_agent or user_agent == "" then
        return "suspicious", 50  -- No UA is suspicious
    end

    -- Check good bots
    for bot_name, _ in pairs(GOOD_BOTS) do
        if string.find(user_agent, bot_name, 1, true) then
            return "good_bot", 0
        end
    end

    -- Check bad bots
    for bot_name, _ in pairs(BAD_BOTS) do
        if string.find(user_agent, bot_name, 1, true) then
            return "bad_bot", 80
        end
    end

    -- Check for generic bot indicators
    local ua_lower = string.lower(user_agent)
    local bot_indicators = {"bot", "crawl", "spider", "scrape", "curl", "wget", "python", "java"}

    for _, indicator in ipairs(bot_indicators) do
        if string.find(ua_lower, indicator, 1, true) then
            return "unknown_bot", 40
        end
    end

    -- Check for headless browser indicators
    local headless_indicators = {"headless", "phantom", "selenium", "puppeteer"}

    for _, indicator in ipairs(headless_indicators) do
        if string.find(ua_lower, indicator, 1, true) then
            return "headless", 70
        end
    end

    return "human", 0
end

-- Helper function: Analyze request patterns
local function analyze_request_pattern(ip)
    local red = connect_redis()
    if not red then
        return 0
    end

    local now = ngx.time()
    local window = 60  -- 1 minute window
    local key = "REQPATTERN:" .. ip

    -- Add current request timestamp
    red:zadd(key, now, now)
    red:expire(key, window)

    -- Remove old entries
    red:zremrangebyscore(key, 0, now - window)

    -- Get request count in window
    local count, err = red:zcard(key)

    close_redis(red)

    if not count then
        return 0
    end

    count = tonumber(count)

    -- Calculate threat score based on request rate
    local threat_score = 0

    if count > 100 then
        threat_score = 90  -- > 100 req/min is very suspicious
    elseif count > 50 then
        threat_score = 60  -- > 50 req/min is suspicious
    elseif count > 30 then
        threat_score = 30  -- > 30 req/min is moderately suspicious
    end

    return threat_score
end

-- Helper function: Check request timing consistency
local function check_timing_consistency(ip)
    local red = connect_redis()
    if not red then
        return 0
    end

    local key = "REQTIMING:" .. ip
    local now = ngx.now() * 1000  -- milliseconds

    -- Get last few request timestamps
    local timestamps, err = red:lrange(key, 0, 9)

    if not timestamps or #timestamps < 3 then
        -- Add current timestamp
        red:lpush(key, now)
        red:ltrim(key, 0, 9)  -- Keep last 10
        red:expire(key, 300)
        close_redis(red)
        return 0
    end

    -- Calculate intervals between requests
    local intervals = {}
    for i = 1, #timestamps - 1 do
        local interval = math.abs(tonumber(timestamps[i]) - tonumber(timestamps[i + 1]))
        table.insert(intervals, interval)
    end

    -- Add current timestamp
    red:lpush(key, now)
    red:ltrim(key, 0, 9)
    red:expire(key, 300)
    close_redis(red)

    -- Calculate variance in intervals
    if #intervals < 2 then
        return 0
    end

    local sum = 0
    for _, interval in ipairs(intervals) do
        sum = sum + interval
    end
    local mean = sum / #intervals

    local variance_sum = 0
    for _, interval in ipairs(intervals) do
        variance_sum = variance_sum + math.pow(interval - mean, 2)
    end
    local variance = variance_sum / #intervals

    -- Bots tend to have very consistent timing (low variance)
    -- Humans have more random timing (high variance)
    local threat_score = 0

    if variance < 100 then  -- Very consistent (likely bot)
        threat_score = 50
    elseif variance < 1000 then  -- Somewhat consistent
        threat_score = 20
    end

    return threat_score
end

-- Helper function: Check for missing common headers
local function check_headers()
    local threat_score = 0

    -- Check for Accept header
    local accept = ngx.var.http_accept
    if not accept or accept == "" then
        threat_score = threat_score + 15
    end

    -- Check for Accept-Language
    local accept_lang = ngx.var.http_accept_language
    if not accept_lang or accept_lang == "" then
        threat_score = threat_score + 10
    end

    -- Check for Accept-Encoding
    local accept_enc = ngx.var.http_accept_encoding
    if not accept_enc or accept_enc == "" then
        threat_score = threat_score + 10
    end

    -- Check for Referer (optional, but suspicious if always missing)
    local referer = ngx.var.http_referer
    -- Not penalizing missing referer as it's often legitimately absent

    return threat_score
end

-- Helper function: Update bot classification in Redis
local function update_bot_classification(ip, classification, score)
    local red = connect_redis()
    if not red then
        return
    end

    local key = "BOTCLASS:" .. ip
    local data = cjson.encode({
        classification = classification,
        score = score,
        timestamp = ngx.time()
    })

    red:setex(key, 3600, data)  -- Cache for 1 hour
    close_redis(red)
end

-- Main bot detection function
local function detect_bot()
    local ip = ngx.var.remote_addr
    local user_agent = ngx.var.http_user_agent or ""

    -- 1. Classify based on User-Agent
    local ua_class, ua_score = classify_user_agent(user_agent)

    -- If it's a known good bot, allow with low score
    if ua_class == "good_bot" then
        update_bot_classification(ip, "good_bot", 0)
        return {
            is_bot = true,
            classification = "good_bot",
            threat_score = 0,
            details = "Known good bot"
        }
    end

    -- If it's a known bad bot, assign high score
    if ua_class == "bad_bot" then
        update_bot_classification(ip, "bad_bot", ua_score)
        return {
            is_bot = true,
            classification = "bad_bot",
            threat_score = ua_score,
            details = "Known bad bot"
        }
    end

    -- 2. Analyze request patterns
    local pattern_score = analyze_request_pattern(ip)

    -- 3. Check timing consistency
    local timing_score = check_timing_consistency(ip)

    -- 4. Check headers
    local header_score = check_headers()

    -- 5. Calculate combined threat score
    local total_score = ua_score + pattern_score + timing_score + header_score

    -- Cap at 100
    if total_score > 100 then
        total_score = 100
    end

    -- Determine classification
    local classification = "human"
    local is_bot = false

    if total_score > 70 then
        classification = "likely_bot"
        is_bot = true
    elseif total_score > 40 then
        classification = "suspicious"
        is_bot = true
    elseif ua_class == "unknown_bot" or ua_class == "headless" then
        classification = ua_class
        is_bot = true
    end

    -- Update classification in Redis
    update_bot_classification(ip, classification, total_score)

    return {
        is_bot = is_bot,
        classification = classification,
        threat_score = total_score,
        details = string.format(
            "UA:%d Pattern:%d Timing:%d Headers:%d",
            ua_score, pattern_score, timing_score, header_score
        )
    }
end

-- Return module
return {
    detect = detect_bot,
    classify_user_agent = classify_user_agent
}
