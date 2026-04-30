local function handler(db)
    local p = ngx.req.get_uri_args()["p"]
    io.open(p, "r")
end
return handler
