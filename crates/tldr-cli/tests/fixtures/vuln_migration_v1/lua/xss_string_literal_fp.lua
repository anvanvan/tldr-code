-- vt=Xss lang=lua — names below are inside strings/comments only
-- ngx.req.get_uri_args is a source. db:query, ngx.say, os.execute,
-- io.open are sinks. Referenced in strings only below.

local function docs()
    local doc = "ngx.req.get_uri_args flows into db:query(SELECT ... )"
    local more = "ngx.say, os.execute, io.open — string-only references here"
    return doc .. more
end
return docs
