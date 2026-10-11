' ================================================================
'  PC-Guardian 실행.vbs
'  이 파일을 더블클릭하면 PC-Guardian GUI가 바로 뜹니다.
'  (파워셸 창이 안 보이고, 명령어 입력도 필요 없습니다)
'
'  ※ 반드시 PC-Guardian-GUI.ps1 파일과 같은 폴더에 두세요.
'  ※ 더블클릭하면 윈도우가 "관리자 권한 허용?" 창을 띄웁니다.
'    (이건 정상입니다 - "예"를 눌러주세요)
' ================================================================

Dim objFSO, objShell, scriptDir, psPath

Set objFSO = CreateObject("Scripting.FileSystemObject")
scriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
psPath = scriptDir & "\PC-Guardian-GUI.ps1"

If Not objFSO.FileExists(psPath) Then
    MsgBox "PC-Guardian-GUI.ps1 파일을 찾을 수 없습니다." & vbCrLf & _
           "이 실행기와 같은 폴더에 있는지 확인해주세요.", vbExclamation, "PC-Guardian"
    WScript.Quit
End If

Set objShell = CreateObject("Shell.Application")
objShell.ShellExecute "powershell.exe", _
    "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & psPath & """", _
    "", "runas", 0
