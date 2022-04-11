global iptoagent: table[addr] of set[string] = table();

event http_header(c:connection, is_orig:bool, name:string, value:string)
{
    local srcip:addr = c$id$orig_h;
    if(c$http?$user_agent)
    {
        local ua: string =to_lower(c$http$user_agent);
        if(srcip in iptoagent)
        {
            add iptoagent[srcip][ua];
        }
        else
        {
            iptoagent[srcip] = set(ua);
        }
    }
}

event zeek_done()
{
    for(ip in iptoagent)
    {
        if(|iptoagent[ip]|>=3)
        {
            print fmt("%s is a proxy",ip);
        }
    }
}