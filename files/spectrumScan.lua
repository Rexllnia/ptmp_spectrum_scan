#! /usr/bin/lua

module("spectrumScan", package.seeall);  --必须要有
-- Load module
ubus = require "ubus"
json = require "dkjson"
cjson_safe = require "cjson.safe"
module_debug = require "utils.debug"
lib_param = require "utils.param_check"
uci = require("uci")

config_file = "/etc/spectrum_scan_cache"
-- read the exist file
-- @path: File path
-- @return file content, if the action success; otherwise return nil.
local function file_read(file)
    local content
    local f = io.open(file,'r')

    if f then
        content = f:read("*all")
        f:close()
    end

    return content
end

local function file_write(path, content, mode)
    mode = mode or "w+b"
    local f = io.open(path, mode)

    if (f) then
        if f:write(content) == nil then
            module_debug.lua_debug(module_debug.ERROR, "the file [%s] write failed", path)

            return -1
        end
        io.close(f)

        return 0
    else
        module_debug.lua_debug(module_debug.ERROR, "the file [%s] can't open.", path)

        return -1
    end
end
function module_default_config_get()
    local config = '{}'

    return config
end

function module_set(param)
    local param_tab 
    local config_tab
    -- Establish connection
    param_tab = cjson_safe.decode(param)

    local conn = ubus.connect()
    if not conn then
        error("Failed to connect to ubusd")
    end
    local status = conn:call("channel_score", "scan",param_tab)
    config_tab = cjson_safe.encode(status)
    -- Close connection
    conn:close()
    return(config_tab)
end

--dev_sta需要有，dev_config ac_config不调用这个
function module_get(param)
    local param_tab 
    local config_tab
    -- Establish connection
    param_tab = cjson_safe.decode(param)
    local res
    local conn = ubus.connect()
    if not conn then
        error("Failed to connect to ubusd")
    end
    local status = conn:call("channel_score", "get",{})


    if  status["status_code"] == "0" then
        config_tab = file_read(config_file)
    elseif status["status_code"] == "2" then
        config_tab = cjson_safe.encode(status)
        file_write(config_file,config_tab)
        res = conn:call("rlog", "upload_stream",{module_name = "spectrumScan",server = "http://apidemo.rj.link/service/api/warnlog?sn=MACCEG20WJL01",data = "12345" })
    else 
        config_tab = cjson_safe.encode(status)         
    end
    -- Close connection
    conn:close()

    return(config_tab)
end

function module_add(param)
    local param_tab 
    local config_tab

    return (param)
end

function module_update(param)

end

function module_delete(param)
    return (param)
end

function module_apply(param, cmd)
    return (param)
end