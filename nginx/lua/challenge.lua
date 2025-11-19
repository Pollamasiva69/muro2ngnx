-- ==============================================================================
-- CHALLENGE-RESPONSE SYSTEM
-- Presents JavaScript challenge to suspicious traffic
-- Validates cookie-based proof of work
-- ==============================================================================

local redis = require "resty.redis"
local cjson = require "cjson"
local resty_md5 = require "resty.md5"
local str = require "resty.string"

-- Configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "127.0.0.1"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_TIMEOUT = 100

local CHALLENGE_THRESHOLD = 61  -- Threat score to trigger challenge
local CHALLENGE_COOKIE_NAME = "security_challenge"
local CHALLENGE_TTL = 3600      -- Challenge valid for 1 hour
local MAX_ATTEMPTS = 3          -- Maximum challenge attempts

-- Shared dictionaries
local challenge_dict = ngx.shared.challenge
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

-- Helper function: Close Redis connection
local function close_redis(red)
    if not red then
        return
    end

    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "Failed to set Redis keepalive: ", err)
    end
end

-- Helper function: Get threat score
local function get_threat_score(ip)
    local cached = threat_scores_dict:get(ip)
    if cached then
        return tonumber(cached)
    end

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
    threat_scores_dict:set(ip, score, 30)

    return score
end

-- Helper function: Generate challenge token
local function generate_challenge_token(ip)
    local md5 = resty_md5:new()
    local data = ip .. ngx.now() .. math.random(1000000)

    md5:update(data)
    local digest = md5:final()

    return str.to_hex(digest)
end

-- Helper function: Verify challenge cookie
local function verify_challenge_cookie(ip, cookie_value)
    if not cookie_value or cookie_value == "" then
        return false
    end

    -- Check Redis for valid challenge
    local red = connect_redis()
    if not red then
        return false
    end

    local key = "CHALLENGE:" .. ip
    local res, err = red:hget(key, "token")

    if not res or res == ngx.null then
        close_redis(red)
        return false
    end

    local stored_token = res

    -- Verify token matches
    if cookie_value ~= stored_token then
        close_redis(red)
        return false
    end

    -- Mark challenge as solved
    red:hset(key, "solved", "1")
    red:expire(key, CHALLENGE_TTL)

    close_redis(red)

    return true
end

-- Helper function: Check if challenge is already solved
local function is_challenge_solved(ip)
    local red = connect_redis()
    if not red then
        return false
    end

    local key = "CHALLENGE:" .. ip
    local res, err = red:hget(key, "solved")

    close_redis(red)

    if res and res ~= ngx.null and res == "1" then
        return true
    end

    return false
end

-- Helper function: Increment challenge attempts
local function increment_attempts(ip)
    local red = connect_redis()
    if not red then
        return 1
    end

    local key = "CHALLENGE:" .. ip
    local attempts = red:hincrby(key, "attempts", 1)
    red:expire(key, 300)  -- Attempts reset after 5 minutes

    close_redis(red)

    return tonumber(attempts)
end

-- Helper function: Get challenge attempts
local function get_attempts(ip)
    local red = connect_redis()
    if not red then
        return 0
    end

    local key = "CHALLENGE:" .. ip
    local res, err = red:hget(key, "attempts")

    close_redis(red)

    if not res or res == ngx.null then
        return 0
    end

    return tonumber(res) or 0
end

-- Helper function: Store challenge token
local function store_challenge_token(ip, token)
    local red = connect_redis()
    if not red then
        return false
    end

    local key = "CHALLENGE:" .. ip
    red:hset(key, "token", token)
    red:hset(key, "created", ngx.now())
    red:expire(key, 300)  -- Challenge valid for 5 minutes

    close_redis(red)

    return true
end

-- Helper function: Generate challenge HTML page
local function generate_challenge_page(token)
    local html = [[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Challenge</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            text-align: center;
        }
        h1 {
            color: #333;
            margin-bottom: 1rem;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .spinner {
            margin: 2rem auto;
            width: 50px;
            height: 50px;
            border: 5px solid #f3f3f3;
            border-top: 5px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .success {
            color: #22c55e;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Check</h1>
        <p>We need to verify you're a human. This will only take a moment...</p>
        <div class="spinner"></div>
        <p id="status">Verifying...</p>
    </div>

    <script>
        (function() {
            // Proof of work: Simple SHA-256 computation
            function sha256(ascii) {
                function rightRotate(value, amount) {
                    return (value >>> amount) | (value << (32 - amount));
                }

                var mathPow = Math.pow;
                var maxWord = mathPow(2, 32);
                var lengthProperty = 'length';
                var i, j;
                var result = '';

                var words = [];
                var asciiBitLength = ascii[lengthProperty] * 8;

                var hash = sha256.h = sha256.h || [];
                var k = sha256.k = sha256.k || [];
                var primeCounter = k[lengthProperty];

                var isComposite = {};
                for (var candidate = 2; primeCounter < 64; candidate++) {
                    if (!isComposite[candidate]) {
                        for (i = 0; i < 313; i += candidate) {
                            isComposite[i] = candidate;
                        }
                        hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
                        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
                    }
                }

                ascii += '\x80';
                while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
                for (i = 0; i < ascii[lengthProperty]; i++) {
                    j = ascii.charCodeAt(i);
                    if (j >> 8) return;
                    words[i >> 2] |= j << ((3 - i) % 4) * 8;
                }
                words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
                words[words[lengthProperty]] = (asciiBitLength);

                for (j = 0; j < words[lengthProperty];) {
                    var w = words.slice(j, j += 16);
                    var oldHash = hash;
                    hash = hash.slice(0, 8);

                    for (i = 0; i < 64; i++) {
                        var w15 = w[i - 15], w2 = w[i - 2];

                        var a = hash[0], e = hash[4];
                        var temp1 = hash[7]
                            + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                            + ((e & hash[5]) ^ ((~e) & hash[6]))
                            + k[i]
                            + (w[i] = (i < 16) ? w[i] : (
                                    w[i - 16]
                                    + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
                                    + w[i - 7]
                                    + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                                ) | 0
                            );

                        var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                            + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

                        hash = [(temp1 + temp2) | 0].concat(hash);
                        hash[4] = (hash[4] + temp1) | 0;
                    }

                    for (i = 0; i < 8; i++) {
                        hash[i] = (hash[i] + oldHash[i]) | 0;
                    }
                }

                for (i = 0; i < 8; i++) {
                    for (j = 3; j + 1; j--) {
                        var b = (hash[i] >> (j * 8)) & 255;
                        result += ((b < 16) ? 0 : '') + b.toString(16);
                    }
                }
                return result;
            }

            // Perform proof of work
            var token = "]] .. token .. [[";
            var pow = sha256(token + Date.now().toString());

            // Set cookie with proof
            document.cookie = "]] .. CHALLENGE_COOKIE_NAME .. [[=" + token + "; path=/; max-age=]] .. CHALLENGE_TTL .. [[; secure; samesite=strict";

            // Update status
            document.getElementById('status').innerHTML = '<span class="success">✓ Verification Complete!</span>';

            // Redirect back to original page
            setTimeout(function() {
                window.location.reload();
            }, 1000);
        })();
    </script>
</body>
</html>
]]

    return html
end

-- Main execution
local function main()
    local ip = ngx.var.remote_addr
    local uri = ngx.var.request_uri

    -- Get threat score
    local threat_score = get_threat_score(ip)

    -- Only challenge if threat score is high enough
    if threat_score < CHALLENGE_THRESHOLD then
        return  -- Allow request to proceed
    end

    -- Check if challenge is already solved
    if is_challenge_solved(ip) then
        return  -- Allow request to proceed
    end

    -- Check for challenge cookie
    local cookie_header = ngx.var.http_cookie
    local challenge_cookie = nil

    if cookie_header then
        challenge_cookie = ngx.var["cookie_" .. CHALLENGE_COOKIE_NAME]
    end

    -- If cookie present, verify it
    if challenge_cookie then
        if verify_challenge_cookie(ip, challenge_cookie) then
            ngx.log(ngx.INFO, "Challenge solved by IP: ", ip)
            return  -- Allow request to proceed
        else
            -- Invalid cookie, increment attempts
            local attempts = increment_attempts(ip)

            if attempts >= MAX_ATTEMPTS then
                -- Too many failed attempts, block
                ngx.log(ngx.WARN, "Too many failed challenge attempts from IP: ", ip)

                ngx.status = 403
                ngx.header["Content-Type"] = "application/json"
                ngx.say(cjson.encode({
                    error = "Access Denied",
                    message = "Too many failed verification attempts",
                    request_id = ngx.var.request_id
                }))
                return ngx.exit(403)
            end
        end
    end

    -- Generate and show challenge
    local token = generate_challenge_token(ip)
    store_challenge_token(ip, token)

    ngx.log(ngx.INFO, "Presenting challenge to IP: ", ip, " (threat score: ", threat_score, ")")

    ngx.status = 403
    ngx.header["Content-Type"] = "text/html"
    ngx.say(generate_challenge_page(token))
    return ngx.exit(403)
end

-- Execute main function
local ok, err = pcall(main)
if not ok then
    ngx.log(ngx.ERR, "Error in challenge.lua: ", err)
    -- Allow request to proceed on error
end
