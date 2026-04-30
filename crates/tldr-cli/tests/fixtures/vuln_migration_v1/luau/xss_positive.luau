local function handler(db)
    local name = ngx.req.get_uri_args()["name"]
    ngx.say("<h1>" .. name .. "</h1>")
end
return handler
