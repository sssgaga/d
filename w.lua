util = {}
util.allocateMemory = allocateMemory;
util.startThread = executeCode;
util.freeMemory = deAlloc;
openProcess("Windows10Universal.exe")

util.aobScan = function(aob, code)
    local new_results = {}
    local results = AOBScan(aob, "*X*C*W")
    if not results then
        return new_results
    end
    for i = 1,results.Count do
        local x = getAddress(results[i - 1])
        table.insert(new_results, x)
    end
    return new_results
end

util.intToBytes = function(val)
    if val == nil then
        error'Cannot convert nil value to byte table'
    end
    local t = { val & 0xFF }
    for i = 1,7 do
        table.insert(t, (val >> (8 * i)) & 0xFF)
    end
    return t
end

util.stringToBytes = function(str)
    local result = {}
	for i = 1, #str do
		table.insert(result, string.byte(str, i))
	end
	return result
end

local strexecg = ''

loader = {}
loader.start = function(strexec, pid)
    local results = util.aobScan("62616E616E6173706C697473????????0C")
    for rn = 1,#results do
        local result = results[rn];
       
        print(string.format("Result: %08X", result))

        local str = strexec
        local b = {}
        for i = 1, #str + 4 do
            if i <= string.len(str) then
                print('i <= : ' .. i)
                table.insert(b, str:byte(i,i))
            else
                print(i)
                table.insert(b, 0)
            end
        end

        table.insert(b, string.len(str))
        writeBytes(result, b)

        closeRemoteHandle(pid)
        strexegc = ""
    end

    return nil
end

function onOpenProcess(pid)
    print(#strexecg)
    if #strexecg == 0 then
        return
    end
    loader.start(strexecg, pid)
end

loader.start2 = function()

    local players, nameOffset, valid;
    local results = util.aobScan("506C6179657273??????????????????07000000000000000F")
    for rn = 1,#results do
        local result = results[rn];

        if not result then
            return false
        end

        local bres = util.intToBytes(result);
        local aobs = ""
        for i = 1,8 do
            aobs = aobs .. string.format("%02X", bres[i])
        end

        local first = false
        local res = util.aobScan(aobs)
        if res then
            valid = false
            for i = 1,#res do
                result = res[i]
                for j = 1,10 do
                    local ptr = readQword(result - (8 * j))
                    if ptr then
                        ptr = readQword(ptr + 8)
                        if (readString(ptr) == "Players") then

                                print(string.format("Got result: %08X", result))
                                -- go to where the vftable is, 0x18 before classname offset (always)
                                players = (result - (8 * j)) - 0x18
                                -- calculate where we just were
                                nameOffset = result - players
                                value = true
                                break

                        end
                    end
                end
                if valid then break end
            end
        end

        if valid then break end
    end

    print(string.format("Players: %08X", players))
    print(string.format("Name offset: %02X", nameOffset))

    local parentOffset = 0;
    for i = 0x10, 0x120, 8 do
        local ptr = readQword(players + i)
        if ptr ~= 0 and ptr % 4 == 0 then
            if (readQword(ptr + 8) == ptr) then
                parentOffset = i
                break
            end
        end
    end
    print(string.format("Parent offset: %02X", parentOffset))

    local dataModel = readQword(players + parentOffset)
   
    print(string.format("DataModel: %08X", dataModel))

    local childrenOffset = 0;
    for i = 0x10, 0x200, 8 do
        local ptr = readQword(dataModel + i)
        if ptr then
            local childrenStart = readQword(ptr)
            local childrenEnd = readQword(ptr + 8)
            if childrenStart and childrenEnd then
                if childrenEnd > childrenStart --[[and ((childrenEnd - childrenStart) % 16) == 0]] and childrenEnd - childrenStart > 1 and childrenEnd - childrenStart < 0x1000 then
                    childrenOffset = i
                    break
                end
            end
        end
    end
    print(string.format("Children offset: %02X", childrenOffset))

    local rapi = {}
    rapi.toInstance = function(address)
        return setmetatable({},{
            __index = function(self, name)
                if (name == "self") then
                    return address
                elseif (name == "Name") then
                    local ptr = readQword(self.self + nameOffset);
                    if ptr then
                        local fl = readQword(ptr + 0x18);
                        if fl == 0x1F then
                            ptr = readQword(ptr);
                        end
                        return readString(ptr);
                    else
                        return "???";
                    end
                elseif (name == "className" or name == "ClassName") then
                    local ptr = readQword(self.self + 0x18);
                    ptr = readQword(ptr + 0x8);
                    if ptr then
                        local fl = readQword(ptr + 0x18);
                        if fl == 0x1F then
                            ptr = readQword(ptr);
                        end
                        return readString(ptr);
                    else
                        return "???";
                    end
                elseif (name == "Parent") then
                    return rapi.toInstance(readQword(self.self + parentOffset))
                elseif (name == "getChildren" or name == "GetChildren") then
                    return function(self)
                        local instances = {}
                        local ptr = readQword(self.self + childrenOffset)
                        if ptr then
                            local childrenStart = readQword(ptr + 0)
                            local childrenEnd = readQword(ptr + 8)
                            local at = childrenStart
                            while at < childrenEnd do
                                local child = readQword(at)
                                table.insert(instances, rapi.toInstance(child))
                                at = at + 16
                            end
                        end
                        return instances
                    end
                elseif (name == "findFirstChild" or name == "FindFirstChild") then
                    return function(self, name)
                        for _,v in pairs(self:getChildren()) do
                            if v.Name == name then
                                return v
                            end
                        end
                        return nil
                    end
                elseif (name == "findFirstClass" or name == "FindFirstClass") then
                    return function(self, name)
                        for _,v in pairs(self:getChildren()) do
                            if v.className == name then
                                return v
                            end
                        end
                        return nil
                    end
                elseif (name == "setParent" or name == "SetParent") then
                    return function(self, other)
                        writeQword(self.self + parentOffset, other.self)

                         local newChildren = util.allocateMemory(0x400)
                         writeQword(newChildren + 0, newChildren + 0x40)

                         local ptr = readQword(other.self + childrenOffset)
                         local childrenStart = readQword(ptr + 0)
                         local childrenEnd = readQword(ptr + 8)
                         if not childrenEnd then
                            childrenEnd = 0
                         end
                         if not childrenStart then
                            childrenStart = 0
                         end
                         local b = readBytes(childrenStart, childrenEnd - childrenStart, true)
                         writeBytes(newChildren + 0x40, b)
                         local e = newChildren + 0x40 + (childrenEnd - childrenStart);
                         writeQword(e, self.self)
                         writeQword(e + 8, readQword(self.self + 0x10))
                         e = e + 0x10

                         writeQword(newChildren + 0x8, e)
                         writeQword(newChildren + 0x10, e)
                    end
                else
                    return self:findFirstChild(name)
                end
            end,
            __metatable = "The metatable is locked"
        })
    end

    players = rapi.toInstance(players)
    game = rapi.toInstance(dataModel)
    
    local localPlayerOffset = 0
    for i = 0x10,0x600,4 do
        local ptr = readQword(players.self + i)
        if readQword(ptr + parentOffset) == players.self then
            localPlayerOffset = i
            break
        end
    end
    print(string.format("Players->LocalPlayer offset: %02X", localPlayerOffset))

    local localPlayer = rapi.toInstance(readQword(players.self + localPlayerOffset));
    print(string.format("Got localplayer: %08X", localPlayer.self))
    print(string.format("Got localplayer: %s", localPlayer.Name))
	--print(string.format("Got UserID: ",localPlayer.FindFirstChild("UserID")))

    local locals = game:findFirstChild("Script Context").StarterScript
    local char = game.Workspace:FindFirstChild(localPlayer.Name)
    for i = 1, #game:findFirstChild("Script Context"):GetChildren() do
        if game:findFirstChild("Script Context"):GetChildren()[i].Name ~= "CoreScripts/AvatarMood" and game:findFirstChild("Script Context"):GetChildren()[i].Name ~= "CoreScripts/ChatEmoteUsage" then locals = game:findFirstChild("Script Context"):GetChildren()[i] end
    end

    local targetScript = char.Animate
    print("Got script: ", targetScript.Name)
    local localscripts = localPlayer.PlayerScripts:GetChildren()
    injectScript = nil
    local results = util.aobScan("496E6A656374????????????????????06")
    for rn = 1,#results do
        local result = results[rn];
        local bres = util.intToBytes(result);
        local aobs = ""
        for i = 1,8 do
            aobs = aobs .. string.format("%02X", bres[i])
        end
        local first = false
        local res = util.aobScan(aobs)
        if res then
            valid = false
            for i = 1,#res do
                result = res[i]
                print(string.format("Result: %08X", result))

                if (readQword(result - nameOffset + 8) == result - nameOffset) then
                    injectScript = result - nameOffset
                    valid = true
                    break
                end
            end
        end

        if valid then break end
    end
    injectScript = rapi.toInstance(injectScript)
    -- Copy erm....all the important stuff :------)
    local b = readBytes(injectScript.self + 0x100, 0x150, true)
    writeBytes(targetScript.self + 0x100, b)
    targetScript:SetParent(localPlayer.PlayerScripts)
	print(string.format("Inject Script: %08X", injectScript.self))
end
loader.suicide()

-- The Main Form
f = createForm()
f.Width = 500
f.Height = 30
f.Position = 'poScreenCenter'
f.Color = '0x232323'
f.BorderStyle = 'bsNone'
f.onMouseDown = DragIt

fTitle = createLabel(f)
fTitle.setPosition(10,5)
fTitle.Font.Color = '0xFFFFFF'
fTitle.Font.Size = 11
fTitle.Font.Name = 'Verdana'
fTitle.Caption = 'Netflix Injector'
fTitle.Anchors = '[akTop,akLeft]'

img_BtnMax = createButton(f)
img_BtnMax.Caption = "Inject"
img_BtnMax.setSize(70,20)
img_BtnMax.setPosition(390,4)
img_BtnMax.onClick = loader.start2

img_BtnClose = createButton(f)
img_BtnClose.setSize(22,22)
img_BtnClose.setPosition(475,4)
img_BtnClose.Stretch = true
img_BtnClose.Cursor = -21
img_BtnClose.Anchors = '[akTop,akRight]'
img_BtnClose.onClick = function()
    print("LoL don't close this!")
end
