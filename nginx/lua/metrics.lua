-- ==============================================================================
-- PROMETHEUS METRICS EXPORTER
-- Exports Nginx and security metrics in Prometheus format
-- ==============================================================================

local redis = require "resty.redis"

-- Configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "127.0.0.1"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_TIMEOUT = 100

-- Shared dictionaries for metrics
local threat_scores_dict = ngx.shared.threat_scores
local blacklist_dict = ngx.shared.blacklist
local whitelist_dict = ngx.shared.whitelist
local challenge_dict = ngx.shared.challenge

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

-- Helper function: Get Redis metrics
local function get_redis_metrics()
    local red = connect_redis()
    if not red then
        return {}
    end

    local metrics = {}

    -- Get blacklist size
    local blacklist_size, err = red:zcard("BLACKLIST:ips")
    if blacklist_size then
        metrics.blacklist_size = tonumber(blacklist_size) or 0
    else
        metrics.blacklist_size = 0
    end

    -- Get whitelist size
    local whitelist_size, err = red:scard("WHITELIST:ips")
    if whitelist_size then
        metrics.whitelist_size = tonumber(whitelist_size) or 0
    else
        metrics.whitelist_size = 0
    end

    -- Get active sessions count
    local keys, err = red:keys("SESSION:*")
    metrics.active_sessions = (keys and #keys) or 0

    -- Get challenges in progress
    local challenge_keys, err = red:keys("CHALLENGE:*")
    metrics.active_challenges = (challenge_keys and #challenge_keys) or 0

    close_redis(red)

    return metrics
end

-- Helper function: Get threat score distribution
local function get_threat_score_distribution()
    local distribution = {
        low = 0,      -- 0-30
        medium = 0,   -- 31-60
        high = 0,     -- 61-80
        critical = 0  -- 81-100
    }

    local red = connect_redis()
    if not red then
        return distribution
    end

    -- Get all threat scores
    local keys, err = red:keys("THREATSCORE:*")

    if keys and #keys > 0 then
        for _, key in ipairs(keys) do
            local score, err = red:get(key)
            if score and score ~= ngx.null then
                local score_num = tonumber(score) or 0

                if score_num <= 30 then
                    distribution.low = distribution.low + 1
                elseif score_num <= 60 then
                    distribution.medium = distribution.medium + 1
                elseif score_num <= 80 then
                    distribution.high = distribution.high + 1
                else
                    distribution.critical = distribution.critical + 1
                end
            end
        end
    end

    close_redis(red)

    return distribution
end

-- Helper function: Format metric
local function format_metric(name, help, type_str, value, labels)
    local output = {}

    -- Help text
    table.insert(output, string.format("# HELP %s %s", name, help))

    -- Type
    table.insert(output, string.format("# TYPE %s %s", name, type_str))

    -- Value
    if labels and next(labels) then
        local label_pairs = {}
        for k, v in pairs(labels) do
            table.insert(label_pairs, string.format('%s="%s"', k, v))
        end
        table.insert(output, string.format("%s{%s} %s", name, table.concat(label_pairs, ","), value))
    else
        table.insert(output, string.format("%s %s", name, value))
    end

    return table.concat(output, "\n")
end

-- Main metrics collection function
local function collect_metrics()
    local metrics_output = {}

    -- 1. Nginx basic metrics (from stub_status)
    local stub_status = ngx.location.capture("/nginx_status")

    if stub_status and stub_status.status == 200 then
        local body = stub_status.body

        -- Parse stub_status output
        local active = string.match(body, "Active connections:%s+(%d+)")
        local accepts = string.match(body, "%s+(%d+)%s+%d+%s+%d+")
        local handled = string.match(body, "%s+%d+%s+(%d+)%s+%d+")
        local requests = string.match(body, "%s+%d+%s+%d+%s+(%d+)")
        local reading = string.match(body, "Reading:%s+(%d+)")
        local writing = string.match(body, "Writing:%s+(%d+)")
        local waiting = string.match(body, "Waiting:%s+(%d+)")

        if active then
            table.insert(metrics_output, format_metric(
                "nginx_connections_active",
                "Active client connections",
                "gauge",
                active
            ))
        end

        if accepts then
            table.insert(metrics_output, format_metric(
                "nginx_connections_accepted",
                "Total accepted connections",
                "counter",
                accepts
            ))
        end

        if handled then
            table.insert(metrics_output, format_metric(
                "nginx_connections_handled",
                "Total handled connections",
                "counter",
                handled
            ))
        end

        if requests then
            table.insert(metrics_output, format_metric(
                "nginx_requests_total",
                "Total client requests",
                "counter",
                requests
            ))
        end

        if reading then
            table.insert(metrics_output, format_metric(
                "nginx_connections_reading",
                "Connections reading request",
                "gauge",
                reading
            ))
        end

        if writing then
            table.insert(metrics_output, format_metric(
                "nginx_connections_writing",
                "Connections writing response",
                "gauge",
                writing
            ))
        end

        if waiting then
            table.insert(metrics_output, format_metric(
                "nginx_connections_waiting",
                "Idle keepalive connections",
                "gauge",
                waiting
            ))
        end
    end

    -- 2. Security metrics from Redis
    local redis_metrics = get_redis_metrics()

    table.insert(metrics_output, format_metric(
        "nginx_security_blacklist_size",
        "Number of blacklisted IPs",
        "gauge",
        redis_metrics.blacklist_size
    ))

    table.insert(metrics_output, format_metric(
        "nginx_security_whitelist_size",
        "Number of whitelisted IPs",
        "gauge",
        redis_metrics.whitelist_size
    ))

    table.insert(metrics_output, format_metric(
        "nginx_security_active_sessions",
        "Number of active sessions",
        "gauge",
        redis_metrics.active_sessions
    ))

    table.insert(metrics_output, format_metric(
        "nginx_security_active_challenges",
        "Number of active security challenges",
        "gauge",
        redis_metrics.active_challenges
    ))

    -- 3. Threat score distribution
    local distribution = get_threat_score_distribution()

    table.insert(metrics_output, format_metric(
        "nginx_security_threat_scores",
        "Distribution of threat scores",
        "gauge",
        distribution.low,
        {level = "low"}
    ))

    table.insert(metrics_output, format_metric(
        "nginx_security_threat_scores",
        "Distribution of threat scores",
        "gauge",
        distribution.medium,
        {level = "medium"}
    ))

    table.insert(metrics_output, format_metric(
        "nginx_security_threat_scores",
        "Distribution of threat scores",
        "gauge",
        distribution.high,
        {level = "high"}
    ))

    table.insert(metrics_output, format_metric(
        "nginx_security_threat_scores",
        "Distribution of threat scores",
        "gauge",
        distribution.critical,
        {level = "critical"}
    ))

    -- 4. Shared dictionary usage
    local threat_scores_free = threat_scores_dict:free_space()
    local threat_scores_capacity = threat_scores_dict:capacity()
    local threat_scores_used = threat_scores_capacity - threat_scores_free

    table.insert(metrics_output, format_metric(
        "nginx_shared_dict_used_bytes",
        "Used bytes in shared dictionary",
        "gauge",
        threat_scores_used,
        {dict = "threat_scores"}
    ))

    -- 5. Custom business metrics (example)
    table.insert(metrics_output, format_metric(
        "nginx_security_waf_enabled",
        "ModSecurity WAF status (1=enabled, 0=disabled)",
        "gauge",
        "1"
    ))

    -- Output all metrics
    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    ngx.say(table.concat(metrics_output, "\n\n"))
end

-- Execute metrics collection
local ok, err = pcall(collect_metrics)
if not ok then
    ngx.log(ngx.ERR, "Error collecting metrics: ", err)
    ngx.status = 500
    ngx.say("Error collecting metrics")
end
