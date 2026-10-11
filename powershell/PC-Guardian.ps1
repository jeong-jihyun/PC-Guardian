<#
================================================================
 PC-Guardian.ps1
 개인 PC 보호 프로그램 (진단 / 감시 / 백업 / 복구 / 격리)
================================================================

 [이 프로그램이 하는 일 - 쉬운 설명]

 1) 진단   : 지금 내 PC 상태(실행중인 프로그램, 시작프로그램,
             블루투스 기기, 네트워크 연결)를 스냅샷으로 찍어둡니다.
 2) 감시   : 일정 시간마다 다시 스냅샷을 찍어서, 이전과 달라진
             부분(새로 생긴 프로그램, 새 블루투스 기기 등)을 찾아
             로그 파일에 기록합니다.
 3) 백업   : 문제가 생기기 전 상태로 돌아갈 수 있도록
             윈도우 "시스템 복원 지점"을 만들어둡니다.
 4) 복구   : 저장해둔 복원 지점 목록을 보여주고, 선택해서
             그 시점으로 되돌릴 수 있게 해줍니다.
 5) 격리   : 의심스러운 프로세스를 "종료"만 합니다.
             (다른 컴퓨터를 공격하거나 추적하지 않습니다 -
              오직 내 PC 안에서만 동작합니다)

 ※ 주의: 이 스크립트는 "관리자 권한"으로 실행해야 전체 기능이
   작동합니다. (파워셸 아이콘 오른쪽 클릭 → 관리자 권한으로 실행)
================================================================
#>

# ---------- 기본 설정 ----------
$ErrorActionPreference = "SilentlyContinue"
$BaseDir   = "$env:USERPROFILE\PC-Guardian"
$LogDir    = "$BaseDir\Logs"
$SnapDir   = "$BaseDir\Snapshots"
$QuarantineDir = "$BaseDir\Quarantine"

# 필요한 폴더들 미리 만들기
foreach ($dir in @($BaseDir, $LogDir, $SnapDir, $QuarantineDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# 로그 기록용 함수 (모든 동작을 시간과 함께 파일에 남김)
function Write-Log {
    param([string]$Message, [string]$Level = "정보")
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$time] [$Level] $Message"
    $logFile = "$LogDir\guardian_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# ================================================================
# 1) 진단 / 스냅샷 찍기
#    - 지금 이 순간의 PC 상태를 파일로 저장합니다.
#    - 나중에 "뭐가 달라졌는지" 비교하는 기준이 됩니다.
# ================================================================
function New-Snapshot {
    param([string]$Label = "manual")

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $snapFile = "$SnapDir\snapshot_${Label}_$stamp.json"

    Write-Host "`n[진단] 현재 PC 상태를 확인하는 중..." -ForegroundColor Cyan

    # (1) 실행중인 프로세스 목록
    $processes = Get-Process | Select-Object Name, Id, Path,
        @{N='StartTime';E={ try { $_.StartTime } catch { $null } }}

    # (2) 윈도우 시작 시 자동 실행되는 프로그램 목록
    $startupItems = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location

    # (3) 현재 페어링/연결된 블루투스 기기 목록
    $bluetoothDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
        Select-Object FriendlyName, InstanceId, Status

    # (4) 현재 맺어져 있는 네트워크 연결(어디와 통신 중인지)
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Established' } |
        Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess

    # (5) 예약된 작업 (악성코드가 자동 실행되도록 몰래 등록하는 경우가 많음)
    $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Disabled' } |
        Select-Object TaskName, TaskPath, State

    $snapshot = [ordered]@{
        Timestamp        = $stamp
        Label            = $Label
        Processes        = $processes
        StartupItems     = $startupItems
        BluetoothDevices = $bluetoothDevices
        NetworkConnections = $connections
        ScheduledTasks   = $scheduledTasks
    }

    $snapshot | ConvertTo-Json -Depth 6 | Out-File -FilePath $snapFile -Encoding UTF8

    Write-Log "스냅샷 저장 완료: $snapFile"
    Write-Host "[완료] 스냅샷이 저장되었습니다: $snapFile" -ForegroundColor Green

    return $snapFile
}

# ================================================================
# 2) 두 스냅샷을 비교해서 "무엇이 달라졌는지" 찾기
# ================================================================
function Compare-Snapshots {
    param([string]$OldFile, [string]$NewFile)

    Write-Host "`n[비교] 두 시점의 PC 상태를 비교하는 중..." -ForegroundColor Cyan

    $old = Get-Content $OldFile -Raw | ConvertFrom-Json
    $new = Get-Content $NewFile -Raw | ConvertFrom-Json

    # --- 새로 생긴 프로세스 찾기 ---
    $oldProcNames = $old.Processes.Name
    $newProcs = $new.Processes | Where-Object { $_.Name -notin $oldProcNames }

    # --- 새로 생긴 시작프로그램 찾기 ---
    $oldStartup = $old.StartupItems.Name
    $newStartup = $new.StartupItems | Where-Object { $_.Name -notin $oldStartup }

    # --- 새로 생긴/바뀐 블루투스 기기 찾기 ---
    $oldBtIds = $old.BluetoothDevices.InstanceId
    $newBt = $new.BluetoothDevices | Where-Object { $_.InstanceId -notin $oldBtIds }

    # --- 새로 생긴 예약 작업 찾기 ---
    $oldTasks = $old.ScheduledTasks.TaskName
    $newTasks = $new.ScheduledTasks | Where-Object { $_.TaskName -notin $oldTasks }

    Write-Host "`n===== 비교 결과 =====" -ForegroundColor Yellow

    if ($newProcs) {
        Write-Host "`n[새로 실행된 프로그램]" -ForegroundColor Red
        $newProcs | Format-Table Name, Id, Path -AutoSize
        Write-Log "새 프로세스 감지: $($newProcs.Name -join ', ')" "경고"
    } else {
        Write-Host "`n[새로 실행된 프로그램] 없음" -ForegroundColor Green
    }

    if ($newStartup) {
        Write-Host "`n[새로 등록된 시작프로그램]" -ForegroundColor Red
        $newStartup | Format-Table Name, Command -AutoSize
        Write-Log "새 시작프로그램 감지: $($newStartup.Name -join ', ')" "경고"
    } else {
        Write-Host "`n[새로 등록된 시작프로그램] 없음" -ForegroundColor Green
    }

    if ($newBt) {
        Write-Host "`n[새로 연결/인식된 블루투스 기기]" -ForegroundColor Red
        $newBt | Format-Table FriendlyName, Status -AutoSize
        Write-Log "새 블루투스 기기 감지: $($newBt.FriendlyName -join ', ')" "경고"
    } else {
        Write-Host "`n[새로 연결/인식된 블루투스 기기] 없음" -ForegroundColor Green
    }

    if ($newTasks) {
        Write-Host "`n[새로 등록된 예약 작업]" -ForegroundColor Red
        $newTasks | Format-Table TaskName, TaskPath -AutoSize
        Write-Log "새 예약작업 감지: $($newTasks.TaskName -join ', ')" "경고"
    } else {
        Write-Host "`n[새로 등록된 예약 작업] 없음" -ForegroundColor Green
    }

    Write-Host "`n참고: 새로 생긴 것 = 무조건 악성은 아닙니다." -ForegroundColor Gray
    Write-Host "      본인이 설치/연결한 게 맞는지 먼저 확인해보세요." -ForegroundColor Gray
}

# ================================================================
# 3) 실시간 감시 모드
#    - 설정한 시간 간격으로 계속 스냅샷을 찍고 자동으로 비교합니다.
#    - Ctrl+C로 중단할 수 있습니다.
# ================================================================
function Start-Watch {
    param([int]$IntervalMinutes = 10)

    Write-Host "`n[감시 시작] ${IntervalMinutes}분마다 PC 상태를 확인합니다." -ForegroundColor Cyan
    Write-Host "중단하려면 Ctrl+C 를 누르세요.`n"

    Write-Log "실시간 감시 시작 (주기: ${IntervalMinutes}분)"

    $baseline = New-Snapshot -Label "watch_baseline"

    while ($true) {
        Start-Sleep -Seconds ($IntervalMinutes * 60)
        $current = New-Snapshot -Label "watch_check"
        Compare-Snapshots -OldFile $baseline -NewFile $current
        $baseline = $current   # 다음 비교를 위해 기준점 갱신
    }
}

# ================================================================
# 4) 보호 조치: 시스템 복원 지점 생성 (나중에 되돌릴 수 있는 "저장점")
# ================================================================
function Protect-CreateRestorePoint {
    Write-Host "`n[보호] 시스템 복원 지점을 생성하는 중..." -ForegroundColor Cyan
    Write-Host "(관리자 권한이 필요합니다)"

    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "PC-Guardian 보호 지점 $(Get-Date -Format 'yyyy-MM-dd HH:mm')" `
            -RestorePointType "MODIFY_SETTINGS"
        Write-Log "시스템 복원 지점 생성 완료"
        Write-Host "[완료] 복원 지점이 생성되었습니다." -ForegroundColor Green
    } catch {
        Write-Host "[실패] 복원 지점 생성 실패. 관리자 권한으로 다시 실행해보세요." -ForegroundColor Red
        Write-Host "이유: $_" -ForegroundColor Red
        Write-Log "복원 지점 생성 실패: $_" "오류"
    }
}

# ================================================================
# 5) 복구: 저장된 복원 지점 목록 보여주고 되돌리기
# ================================================================
function Restore-FromPoint {
    Write-Host "`n[복구] 사용 가능한 복원 지점 목록:" -ForegroundColor Cyan

    $points = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if (-not $points) {
        Write-Host "복원 지점이 없습니다. 먼저 '보호' 기능으로 복원 지점을 만들어두세요." -ForegroundColor Yellow
        return
    }

    $points | Format-Table SequenceNumber, CreationTime, Description -AutoSize

    $seq = Read-Host "`n되돌릴 복원 지점 번호(SequenceNumber)를 입력하세요 (취소하려면 빈칸 Enter)"
    if ([string]::IsNullOrWhiteSpace($seq)) {
        Write-Host "취소되었습니다."
        return
    }

    $confirm = Read-Host "정말로 $seq 번으로 되돌리시겠습니까? PC가 재부팅됩니다. (예/아니오)"
    if ($confirm -eq "예") {
        Write-Log "시스템 복원 실행: 지점 번호 $seq" "경고"
        Restore-Computer -RestorePoint $seq -Confirm:$false
    } else {
        Write-Host "취소되었습니다."
    }
}

# ================================================================
# 6) 격리: 의심 프로세스 "종료" (공격 아님 - 내 PC 안에서만 동작)
# ================================================================
function Stop-SuspiciousProcess {
    Write-Host "`n[격리] 현재 실행중인 프로그램 목록:" -ForegroundColor Cyan
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 |
        Format-Table Name, Id, CPU, Path -AutoSize

    $name = Read-Host "`n종료할 프로그램 이름(Name)을 입력하세요 (취소하려면 빈칸 Enter)"
    if ([string]::IsNullOrWhiteSpace($name)) {
        Write-Host "취소되었습니다."
        return
    }

    $target = Get-Process -Name $name -ErrorAction SilentlyContinue
    if (-not $target) {
        Write-Host "해당 이름의 프로그램을 찾을 수 없습니다." -ForegroundColor Yellow
        return
    }

    $target | Format-Table Name, Id, Path -AutoSize
    $confirm = Read-Host "위 프로그램을 종료하시겠습니까? (예/아니오)"
    if ($confirm -eq "예") {
        $target | Stop-Process -Force
        Write-Log "프로세스 강제 종료: $name" "경고"
        Write-Host "[완료] 종료했습니다." -ForegroundColor Green
    } else {
        Write-Host "취소되었습니다."
    }
}

# ================================================================
# 7) 블루투스 기기 목록 확인 + 수상한 기기 안내
# ================================================================
function Show-BluetoothDevices {
    Write-Host "`n[블루투스] 현재 인식된 블루투스 기기 목록:" -ForegroundColor Cyan
    Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
        Select-Object FriendlyName, Status, InstanceId |
        Format-Table -AutoSize

    Write-Host "`n모르는 기기가 보인다면:" -ForegroundColor Yellow
    Write-Host "  설정 > 장치 > 블루투스 및 기타 장치 에서 직접 '제거'를 눌러주세요."
    Write-Host "  (이 스크립트는 안전을 위해 블루투스 기기를 자동으로 삭제하지 않습니다)"
}

# ================================================================
# 메인 메뉴
# ================================================================
function Show-Menu {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "           PC-Guardian  (개인 PC 보호)          " -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host " 1. 지금 상태 스냅샷 찍기 (진단)"
    Write-Host " 2. 이전 스냅샷과 비교하기"
    Write-Host " 3. 실시간 감시 시작 (주기적 자동 확인)"
    Write-Host " 4. 보호 지점 만들기 (시스템 복원 지점 생성)"
    Write-Host " 5. 복구하기 (복원 지점으로 되돌리기)"
    Write-Host " 6. 의심 프로그램 종료 (격리)"
    Write-Host " 7. 블루투스 기기 목록 보기"
    Write-Host " 8. 로그 폴더 열기"
    Write-Host " 0. 종료"
    Write-Host "================================================"
}

# ================================================================
# 프로그램 시작점
# ================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[안내] 관리자 권한이 아닙니다. 일부 기능(복원 지점 생성/복구)이 제한될 수 있습니다." -ForegroundColor Yellow
    Write-Host "       가능하면 '관리자 권한으로 실행'을 눌러 다시 실행해주세요.`n" -ForegroundColor Yellow
}

do {
    Show-Menu
    $choice = Read-Host "`n번호를 선택하세요"

    switch ($choice) {
        "1" { New-Snapshot -Label "manual" }
        "2" {
            $files = Get-ChildItem "$SnapDir\*.json" | Sort-Object LastWriteTime
            if ($files.Count -lt 2) {
                Write-Host "비교할 스냅샷이 2개 이상 필요합니다. 먼저 스냅샷을 더 찍어주세요." -ForegroundColor Yellow
            } else {
                Write-Host "`n저장된 스냅샷 목록:"
                for ($i=0; $i -lt $files.Count; $i++) { Write-Host "  [$i] $($files[$i].Name)" }
                $oldIdx = Read-Host "기준(이전) 스냅샷 번호"
                $newIdx = Read-Host "비교(이후) 스냅샷 번호"
                Compare-Snapshots -OldFile $files[$oldIdx].FullName -NewFile $files[$newIdx].FullName
            }
        }
        "3" {
            $min = Read-Host "몇 분마다 확인할까요? (예: 10)"
            if (-not $min) { $min = 10 }
            Start-Watch -IntervalMinutes ([int]$min)
        }
        "4" { Protect-CreateRestorePoint }
        "5" { Restore-FromPoint }
        "6" { Stop-SuspiciousProcess }
        "7" { Show-BluetoothDevices }
        "8" { Invoke-Item $LogDir }
        "0" { Write-Host "종료합니다."; break }
        default { Write-Host "잘못된 입력입니다." -ForegroundColor Red }
    }

    if ($choice -ne "0") {
        Write-Host "`n(아무 키나 누르면 메뉴로 돌아갑니다)"
        $null = Read-Host
    }

} while ($choice -ne "0")
