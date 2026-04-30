local function handler(db)
    local id = ngx.req.get_uri_args()["id"]
    db:query("SELECT * FROM u WHERE id = " .. id)
end
return handler
