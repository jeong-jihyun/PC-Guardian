<#
================================================================
 PC-Guardian-GUI.ps1
 개인 PC 보호 프로그램 - GUI 버전
================================================================

 [이 프로그램이 하는 일]
  - 대시보드 : 현재 보호 상태를 한눈에 보여줌
  - 실시간 감시 : 주기적으로 PC 상태를 확인하고 변화 감지
  - 침입 차단 : 원격 로그인(RDP) 실패 반복 시 해당 IP 자동 차단
                + 수동으로 특정 IP/대역 차단 (GeoIP 차단의 개인PC 버전)
  - 파일 무결성 : 지정한 폴더의 파일이 변조/삭제/추가됐는지 감시
  - 복구/백업 : 시스템 복원 지점 생성 및 되돌리기
  - 격리함 : 의심 프로세스 종료 / 의심 파일 격리 및 복원
  - 증거/신고 : 로그·스크린샷을 모아 신고용 리포트 자동 생성

 ※ 이 프로그램은 내 PC를 지키기만 합니다.
   다른 컴퓨터를 공격하거나 추적하지 않습니다.

 ※ 반드시 "관리자 권한으로 실행"해야 전체 기능이 작동합니다.
================================================================
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "SilentlyContinue"

# ================================================================
# 기본 경로 / 상태 저장소
# ================================================================
$script:BaseDir        = "$env:USERPROFILE\PC-Guardian"
$script:LogDir          = "$script:BaseDir\Logs"
$script:SnapDir         = "$script:BaseDir\Snapshots"
$script:QuarantineDir   = "$script:BaseDir\Quarantine"
$script:EvidenceDir     = "$script:BaseDir\Evidence"
$script:StateFile       = "$script:BaseDir\state.json"

foreach ($dir in @($script:BaseDir, $script:LogDir, $script:SnapDir, $script:QuarantineDir, $script:EvidenceDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# 프로그램을 껐다 켜도 유지되는 상태값들 (감시 폴더, 차단 IP 목록, 격리 목록 등)
$script:State = [ordered]@{
    WatchedFolders  = @()
    BlockedIPs      = @()
    QuarantineItems = @()
    FileBaseline    = @{}
    LastSnapshot    = $null
}

function Save-State {
    $script:State | ConvertTo-Json -Depth 6 | Out-File -FilePath $script:StateFile -Encoding UTF8
}
function Load-State {
    if (Test-Path $script:StateFile) {
        try {
            $loaded = Get-Content $script:StateFile -Raw | ConvertFrom-Json
            foreach ($key in @('WatchedFolders','BlockedIPs','QuarantineItems','LastSnapshot')) {
                if ($loaded.$key) { $script:State[$key] = $loaded.$key }
            }
            if ($loaded.FileBaseline) {
                $ht = @{}
                $loaded.FileBaseline.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
                $script:State['FileBaseline'] = $ht
            }
        } catch {}
    }
}
Load-State

function Write-Log {
    param([string]$Message, [string]$Level = "정보")
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$time] [$Level] $Message"
    $logFile = "$script:LogDir\guardian_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    return $line
}

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ================================================================
# XAML (화면 디자인)
# ================================================================
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PC-Guardian" Height="700" Width="1050"
        WindowStartupLocation="CenterScreen"
        Background="#1B1D23" FontFamily="Malgun Gothic">
    <Window.Resources>
        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Height" Value="46"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#CFCFE0"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Padding" Value="20,0,0,0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" x:Name="bd">
                            <ContentPresenter VerticalAlignment="Center" HorizontalAlignment="Left" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#2A2D38"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="ActionButton" TargetType="Button">
            <Setter Property="Height" Value="34"/>
            <Setter Property="Background" Value="#3D7EFF"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="14,0,14,0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Margin" Value="0,0,8,0"/>
        </Style>
        <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource ActionButton}">
            <Setter Property="Background" Value="#E05260"/>
        </Style>
        <Style TargetType="TextBlock" x:Key="SectionTitle">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="20"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Margin" Value="0,0,0,14"/>
        </Style>
        <Style TargetType="TextBlock" x:Key="Label">
            <Setter Property="Foreground" Value="#B9BBCC"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
        <Style TargetType="ListBox">
            <Setter Property="Background" Value="#14161B"/>
            <Setter Property="Foreground" Value="#D8D8E8"/>
            <Setter Property="BorderBrush" Value="#30323C"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize" Value="12"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#14161B"/>
            <Setter Property="Foreground" Value="#D8D8E8"/>
            <Setter Property="BorderBrush" Value="#30323C"/>
            <Setter Property="Padding" Value="6"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="190"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- 좌측 사이드바 -->
        <Border Grid.Column="0" Background="#15161C">
            <DockPanel>
                <StackPanel DockPanel.Dock="Top" Margin="20,24,0,24">
                    <TextBlock Text="🛡 PC-Guardian" Foreground="White" FontSize="17" FontWeight="Bold"/>
                    <TextBlock x:Name="txtAdminBadge" Text="" Foreground="#F2A33D" FontSize="11" Margin="0,4,0,0"/>
                </StackPanel>
                <StackPanel DockPanel.Dock="Top">
                    <Button x:Name="btnNavDash"   Content="📊 대시보드"      Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavWatch"  Content="👁 실시간 감시"   Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavFw"     Content="🚫 침입 차단"     Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavFile"   Content="🗂 파일 무결성"   Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavRestore" Content="♻ 복구/백업"    Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavQuar"   Content="🔒 격리함"        Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavEvid"   Content="📁 증거/신고"     Style="{StaticResource NavButton}"/>
                    <Button x:Name="btnNavLog"    Content="📜 로그"          Style="{StaticResource NavButton}"/>
                </StackPanel>
            </DockPanel>
        </Border>

        <!-- 우측 컨텐츠 영역 -->
        <Grid Grid.Column="1" Margin="28">

            <!-- 대시보드 -->
            <StackPanel x:Name="PanelDash" Visibility="Visible">
                <TextBlock Text="대시보드" Style="{StaticResource SectionTitle}"/>
                <WrapPanel>
                    <Border Background="#20222B" CornerRadius="8" Width="220" Height="100" Margin="0,0,14,14" Padding="16">
                        <StackPanel>
                            <TextBlock Text="마지막 스냅샷" Style="{StaticResource Label}"/>
                            <TextBlock x:Name="txtDashSnap" Text="없음" Foreground="White" FontSize="16" FontWeight="Bold" Margin="0,8,0,0"/>
                        </StackPanel>
                    </Border>
                    <Border Background="#20222B" CornerRadius="8" Width="220" Height="100" Margin="0,0,14,14" Padding="16">
                        <StackPanel>
                            <TextBlock Text="감시 상태" Style="{StaticResource Label}"/>
                            <TextBlock x:Name="txtDashWatch" Text="꺼짐" Foreground="#E05260" FontSize="16" FontWeight="Bold" Margin="0,8,0,0"/>
                        </StackPanel>
                    </Border>
                    <Border Background="#20222B" CornerRadius="8" Width="220" Height="100" Margin="0,0,14,14" Padding="16">
                        <StackPanel>
                            <TextBlock Text="차단된 IP 수" Style="{StaticResource Label}"/>
                            <TextBlock x:Name="txtDashBlocked" Text="0" Foreground="White" FontSize="16" FontWeight="Bold" Margin="0,8,0,0"/>
                        </StackPanel>
                    </Border>
                    <Border Background="#20222B" CornerRadius="8" Width="220" Height="100" Margin="0,0,14,14" Padding="16">
                        <StackPanel>
                            <TextBlock Text="격리된 항목" Style="{StaticResource Label}"/>
                            <TextBlock x:Name="txtDashQuar" Text="0" Foreground="White" FontSize="16" FontWeight="Bold" Margin="0,8,0,0"/>
                        </StackPanel>
                    </Border>
                </WrapPanel>
                <StackPanel Orientation="Horizontal" Margin="0,16,0,0">
                    <Button x:Name="btnDashSnap" Content="지금 상태 스냅샷" Style="{StaticResource ActionButton}" Width="160"/>
                    <Button x:Name="btnDashProtect" Content="보호 지점 만들기" Style="{StaticResource ActionButton}" Width="160"/>
                </StackPanel>
                <TextBlock Text="최근 활동" Foreground="#B9BBCC" FontSize="14" Margin="0,24,0,8"/>
                <ListBox x:Name="lstDashRecent" Height="260"/>
            </StackPanel>

            <!-- 실시간 감시 -->
            <StackPanel x:Name="PanelWatch" Visibility="Collapsed">
                <TextBlock Text="실시간 감시" Style="{StaticResource SectionTitle}"/>
                <StackPanel Orientation="Horizontal">
                    <TextBlock Text="확인 주기(분):" Style="{StaticResource Label}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBox x:Name="txtWatchInterval" Width="60" Text="10"/>
                    <Button x:Name="btnWatchStart" Content="감시 시작" Style="{StaticResource ActionButton}" Margin="16,0,8,0"/>
                    <Button x:Name="btnWatchStop" Content="감시 중지" Style="{StaticResource DangerButton}"/>
                </StackPanel>
                <TextBlock Text="변화 감지 내역" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstWatchResult" Height="420"/>
            </StackPanel>

            <!-- 침입 차단 -->
            <StackPanel x:Name="PanelFw" Visibility="Collapsed">
                <TextBlock Text="침입 차단" Style="{StaticResource SectionTitle}"/>
                <TextBlock Text="① 원격 로그인(RDP) 실패 자동 차단 - fail2ban 방식" Foreground="#9BA0C0" FontSize="13" Margin="0,0,0,8"/>
                <StackPanel Orientation="Horizontal">
                    <TextBlock Text="허용 실패 횟수:" Style="{StaticResource Label}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBox x:Name="txtFwThreshold" Width="50" Text="5"/>
                    <Button x:Name="btnFwStart" Content="자동 차단 감시 시작" Style="{StaticResource ActionButton}" Margin="16,0,8,0"/>
                    <Button x:Name="btnFwStop" Content="감시 중지" Style="{StaticResource DangerButton}"/>
                </StackPanel>

                <TextBlock Text="② 수동 IP / 대역 차단 (GeoIP 차단의 개인PC 버전)" Foreground="#9BA0C0" FontSize="13" Margin="0,20,0,8"/>
                <StackPanel Orientation="Horizontal">
                    <TextBox x:Name="txtManualIP" Width="200" Text="" />
                    <Button x:Name="btnBlockIP" Content="차단 추가" Style="{StaticResource ActionButton}" Margin="8,0,0,0"/>
                    <Button x:Name="btnImportList" Content="차단목록 파일 불러오기" Style="{StaticResource ActionButton}"/>
                </StackPanel>
                <TextBlock Text="예: 203.0.113.10  또는  203.0.113.0/24" Foreground="#7A7D90" FontSize="11" Margin="0,4,0,0"/>

                <TextBlock Text="현재 차단 목록" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstBlocked" Height="200"/>
                <Button x:Name="btnUnblockIP" Content="선택 항목 차단 해제" Style="{StaticResource DangerButton}" Width="160" HorizontalAlignment="Left" Margin="0,8,0,0"/>
            </StackPanel>

            <!-- 파일 무결성 -->
            <StackPanel x:Name="PanelFile" Visibility="Collapsed">
                <TextBlock Text="파일 무결성 검사" Style="{StaticResource SectionTitle}"/>
                <StackPanel Orientation="Horizontal">
                    <Button x:Name="btnAddFolder" Content="감시 폴더 추가" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnBaseline" Content="기준 해시 생성" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnCheckIntegrity" Content="지금 검사" Style="{StaticResource ActionButton}"/>
                </StackPanel>
                <TextBlock Text="감시 중인 폴더" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstFolders" Height="100"/>
                <TextBlock Text="검사 결과" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstFileResult" Height="230"/>
            </StackPanel>

            <!-- 복구/백업 -->
            <StackPanel x:Name="PanelRestore" Visibility="Collapsed">
                <TextBlock Text="복구 / 백업" Style="{StaticResource SectionTitle}"/>
                <StackPanel Orientation="Horizontal">
                    <Button x:Name="btnCreateRestore" Content="복원 지점 생성" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnRefreshRestore" Content="목록 새로고침" Style="{StaticResource ActionButton}"/>
                </StackPanel>
                <TextBlock Text="복원 지점 목록" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstRestorePoints" Height="300"/>
                <Button x:Name="btnDoRestore" Content="선택 지점으로 되돌리기" Style="{StaticResource DangerButton}" Width="200" HorizontalAlignment="Left" Margin="0,8,0,0"/>
            </StackPanel>

            <!-- 격리함 -->
            <StackPanel x:Name="PanelQuar" Visibility="Collapsed">
                <TextBlock Text="격리함" Style="{StaticResource SectionTitle}"/>
                <StackPanel Orientation="Horizontal">
                    <Button x:Name="btnRefreshProc" Content="실행중인 프로그램 보기" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnKillProc" Content="선택 프로그램 종료(격리)" Style="{StaticResource DangerButton}"/>
                </StackPanel>
                <ListBox x:Name="lstProcesses" Height="180" Margin="0,8,0,0"/>

                <TextBlock Text="격리 이력" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstQuarHistory" Height="180"/>
            </StackPanel>

            <!-- 증거/신고 -->
            <StackPanel x:Name="PanelEvid" Visibility="Collapsed">
                <TextBlock Text="증거 수집 / 신고" Style="{StaticResource SectionTitle}"/>
                <TextBlock Text="피해를 입증할 자료를 모아두고, 아래 공식 경로로 신고하세요." Foreground="#9BA0C0" FontSize="13" Margin="0,0,0,12"/>
                <StackPanel Orientation="Horizontal">
                    <Button x:Name="btnScreenshot" Content="스크린샷 캡처" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnCollectEvidence" Content="증거 폴더 생성 (로그+스크린샷)" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnGenReport" Content="신고 리포트 생성" Style="{StaticResource ActionButton}"/>
                </StackPanel>
                <Border Background="#20222B" CornerRadius="8" Padding="16" Margin="0,16,0,0">
                    <StackPanel>
                        <TextBlock Text="공식 신고 창구" Foreground="White" FontWeight="Bold" Margin="0,0,0,8"/>
                        <TextBlock Text="• KISA 118센터 (인터넷 침해사고 신고) - kisa.or.kr / 국번없이 118" Foreground="#D8D8E8" Margin="0,2,0,2"/>
                        <TextBlock Text="• 경찰청 사이버수사국 - ecrm.cyber.go.kr" Foreground="#D8D8E8" Margin="0,2,0,2"/>
                        <TextBlock Text="신고 시 수사기관이 통신사에 영장을 받아 실제 가입자 정보를 확인합니다." Foreground="#7A7D90" FontSize="11" Margin="0,8,0,0"/>
                    </StackPanel>
                </Border>
                <TextBlock Text="생성된 증거 폴더 목록" Foreground="#B9BBCC" FontSize="14" Margin="0,16,0,8"/>
                <ListBox x:Name="lstEvidence" Height="160"/>
            </StackPanel>

            <!-- 로그 -->
            <StackPanel x:Name="PanelLog" Visibility="Collapsed">
                <TextBlock Text="로그" Style="{StaticResource SectionTitle}"/>
                <StackPanel Orientation="Horizontal">
                    <Button x:Name="btnLogRefresh" Content="새로고침" Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnLogOpenFolder" Content="로그 폴더 열기" Style="{StaticResource ActionButton}"/>
                </StackPanel>
                <ListBox x:Name="lstLog" Height="480" Margin="0,16,0,0"/>
            </StackPanel>

        </Grid>
    </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$Window = [Windows.Markup.XamlReader]::Load($reader)

# 컨트롤 찾기 헬퍼
function GUI($name) { return $Window.FindName($name) }

# ================================================================
# 네비게이션 (사이드바 클릭 시 패널 전환)
# ================================================================
$panels = @{
    Dash    = GUI "PanelDash"
    Watch   = GUI "PanelWatch"
    Fw      = GUI "PanelFw"
    File    = GUI "PanelFile"
    Restore = GUI "PanelRestore"
    Quar    = GUI "PanelQuar"
    Evid    = GUI "PanelEvid"
    Log     = GUI "PanelLog"
}
function Show-Panel($key) {
    foreach ($k in $panels.Keys) {
        $panels[$k].Visibility = if ($k -eq $key) { 'Visible' } else { 'Collapsed' }
    }
}
(GUI "btnNavDash").Add_Click({ Show-Panel "Dash"; Refresh-Dashboard })
(GUI "btnNavWatch").Add_Click({ Show-Panel "Watch" })
(GUI "btnNavFw").Add_Click({ Show-Panel "Fw"; Refresh-BlockedList })
(GUI "btnNavFile").Add_Click({ Show-Panel "File"; Refresh-FolderList })
(GUI "btnNavRestore").Add_Click({ Show-Panel "Restore"; Refresh-RestorePoints })
(GUI "btnNavQuar").Add_Click({ Show-Panel "Quar"; Refresh-QuarHistory })
(GUI "btnNavEvid").Add_Click({ Show-Panel "Evid"; Refresh-EvidenceList })
(GUI "btnNavLog").Add_Click({ Show-Panel "Log"; Refresh-LogView })

if (-not $script:IsAdmin) {
    (GUI "txtAdminBadge").Text = "⚠ 관리자 권한 아님 (일부 기능 제한)"
} else {
    (GUI "txtAdminBadge").Text = "✅ 관리자 권한으로 실행됨"
}

# ================================================================
# 대시보드
# ================================================================
function Refresh-Dashboard {
    (GUI "txtDashSnap").Text = if ($script:State.LastSnapshot) { $script:State.LastSnapshot } else { "없음" }
    (GUI "txtDashWatch").Text = if ($script:WatchTimer -and $script:WatchTimer.IsEnabled) { "켜짐" } else { "꺼짐" }
    (GUI "txtDashWatch").Foreground = if ($script:WatchTimer -and $script:WatchTimer.IsEnabled) { "#3DDC84" } else { "#E05260" }
    (GUI "txtDashBlocked").Text = [string]$script:State.BlockedIPs.Count
    (GUI "txtDashQuar").Text = [string]$script:State.QuarantineItems.Count

    $lb = GUI "lstDashRecent"
    $lb.Items.Clear()
    $logFile = "$script:LogDir\guardian_$(Get-Date -Format 'yyyyMMdd').log"
    if (Test-Path $logFile) {
        Get-Content $logFile -Tail 30 | Sort-Object -Descending | ForEach-Object { $lb.Items.Add($_) }
    }
}

# ================================================================
# 스냅샷 / 비교 (기존 로직 재사용)
# ================================================================
function Get-SystemSnapshot {
    $processes = Get-Process | Select-Object Name, Id, Path
    $startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
    $bluetoothDevices = Get-PnpDevice -Class Bluetooth | Select-Object FriendlyName, InstanceId, Status
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } |
        Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
    $scheduledTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
        Select-Object TaskName, TaskPath, State

    return [ordered]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Processes = $processes
        StartupItems = $startupItems
        BluetoothDevices = $bluetoothDevices
        NetworkConnections = $connections
        ScheduledTasks = $scheduledTasks
    }
}

function Save-Snapshot($snap, $label) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $file = "$script:SnapDir\snapshot_${label}_$stamp.json"
    $snap | ConvertTo-Json -Depth 6 | Out-File -FilePath $file -Encoding UTF8
    return $file
}

function Compare-TwoSnapshots($oldSnap, $newSnap) {
    $result = New-Object System.Collections.Generic.List[string]
    $oldProcNames = $oldSnap.Processes.Name
    $newProcs = $newSnap.Processes | Where-Object { $_.Name -notin $oldProcNames }
    foreach ($p in $newProcs) { $result.Add("[새 프로그램] $($p.Name)  ($($p.Path))") }

    $oldStartup = $oldSnap.StartupItems.Name
    $newStartup = $newSnap.StartupItems | Where-Object { $_.Name -notin $oldStartup }
    foreach ($s in $newStartup) { $result.Add("[새 시작프로그램] $($s.Name)  ($($s.Command))") }

    $oldBt = $oldSnap.BluetoothDevices.InstanceId
    $newBt = $newSnap.BluetoothDevices | Where-Object { $_.InstanceId -notin $oldBt }
    foreach ($b in $newBt) { $result.Add("[새 블루투스 기기] $($b.FriendlyName)") }

    $oldTasks = $oldSnap.ScheduledTasks.TaskName
    $newTasks = $newSnap.ScheduledTasks | Where-Object { $_.TaskName -notin $oldTasks }
    foreach ($t in $newTasks) { $result.Add("[새 예약작업] $($t.TaskName)") }

    return $result
}

(GUI "btnDashSnap").Add_Click({
    $snap = Get-SystemSnapshot
    $file = Save-Snapshot $snap "manual"
    $script:LastSnapshotObj = $snap
    $script:State.LastSnapshot = $snap.Timestamp
    Save-State
    Write-Log "수동 스냅샷 생성: $file" | Out-Null
    [System.Windows.MessageBox]::Show("스냅샷을 저장했습니다.`n$file", "완료") | Out-Null
    Refresh-Dashboard
})

(GUI "btnDashProtect").Add_Click({
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\"
        Checkpoint-Computer -Description "PC-Guardian 보호지점 $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "보호 지점(복원 지점) 생성 완료" | Out-Null
        [System.Windows.MessageBox]::Show("보호 지점이 생성되었습니다.", "완료") | Out-Null
    } catch {
        Write-Log "보호 지점 생성 실패: $_" "오류" | Out-Null
        [System.Windows.MessageBox]::Show("생성 실패. 관리자 권한인지 확인해주세요.`n$_", "오류") | Out-Null
    }
    Refresh-Dashboard
})

# ================================================================
# 실시간 감시 (DispatcherTimer 사용 - 창이 멈추지 않음)
# ================================================================
$script:WatchTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:WatchBaseline = $null

(GUI "btnWatchStart").Add_Click({
    $min = 10
    [int]::TryParse((GUI "txtWatchInterval").Text, [ref]$min) | Out-Null
    if ($min -lt 1) { $min = 1 }

    $script:WatchBaseline = Get-SystemSnapshot
    Save-Snapshot $script:WatchBaseline "watch_baseline" | Out-Null

    $script:WatchTimer.Interval = [TimeSpan]::FromMinutes($min)
    $script:WatchTimer.Remove_Tick($script:WatchTickHandler)
    $script:WatchTickHandler = {
        $current = Get-SystemSnapshot
        Save-Snapshot $current "watch_check" | Out-Null
        $diffs = Compare-TwoSnapshots $script:WatchBaseline $current
        $lb = GUI "lstWatchResult"
        if ($diffs.Count -gt 0) {
            $stamp = Get-Date -Format "HH:mm:ss"
            $lb.Items.Insert(0, "── $stamp 변화 감지 ──")
            foreach ($d in $diffs) {
                $lb.Items.Insert(1, $d)
                Write-Log $d "경고" | Out-Null
            }
        } else {
            $lb.Items.Insert(0, "[$(Get-Date -Format 'HH:mm:ss')] 변화 없음")
        }
        $script:WatchBaseline = $current
        Refresh-Dashboard
    }
    $script:WatchTimer.Add_Tick($script:WatchTickHandler)
    $script:WatchTimer.Start()
    Write-Log "실시간 감시 시작 (주기 ${min}분)" | Out-Null
    Refresh-Dashboard
})

(GUI "btnWatchStop").Add_Click({
    $script:WatchTimer.Stop()
    Write-Log "실시간 감시 중지" | Out-Null
    Refresh-Dashboard
})

# ================================================================
# 침입 차단 - ① RDP 로그인 실패 자동 차단 (fail2ban 방식)
# ================================================================
$script:FwTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:FwTimer.Interval = [TimeSpan]::FromSeconds(60)

function Block-IPAddress($ip, $reason) {
    if ($script:State.BlockedIPs -contains $ip) { return }
    try {
        New-NetFirewallRule -DisplayName "PCGuardian-Block-$ip" -Direction Inbound -RemoteAddress $ip -Action Block -ErrorAction Stop | Out-Null
        New-NetFirewallRule -DisplayName "PCGuardian-Block-$ip-Out" -Direction Outbound -RemoteAddress $ip -Action Block -ErrorAction SilentlyContinue | Out-Null
        $script:State.BlockedIPs += [pscustomobject]@{ IP = $ip; Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); Reason = $reason }
        Save-State
        Write-Log "IP 차단: $ip ($reason)" "경고" | Out-Null
        return $true
    } catch {
        Write-Log "IP 차단 실패: $ip - $_" "오류" | Out-Null
        return $false
    }
}

function Unblock-IPAddress($ip) {
    Remove-NetFirewallRule -DisplayName "PCGuardian-Block-$ip" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "PCGuardian-Block-$ip-Out" -ErrorAction SilentlyContinue
    $script:State.BlockedIPs = @($script:State.BlockedIPs | Where-Object { $_.IP -ne $ip })
    Save-State
    Write-Log "IP 차단 해제: $ip" | Out-Null
}

function Refresh-BlockedList {
    $lb = GUI "lstBlocked"
    $lb.Items.Clear()
    foreach ($item in $script:State.BlockedIPs) {
        $lb.Items.Add("$($item.IP)   |   $($item.Time)   |   $($item.Reason)")
    }
}

$script:FwTickHandler = {
    $threshold = 5
    [int]::TryParse((GUI "txtFwThreshold").Text, [ref]$threshold) | Out-Null

    # 보안 이벤트 로그에서 최근 10분 내 로그인 실패(4625) 이벤트 수집
    $since = (Get-Date).AddMinutes(-10)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction SilentlyContinue

    if ($events) {
        $grouped = $events | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            [pscustomobject]@{ IP = $ip }
        } | Where-Object { $_.IP -and $_.IP -ne '-' } | Group-Object IP

        foreach ($g in $grouped) {
            if ($g.Count -ge $threshold) {
                $blocked = Block-IPAddress $g.Name "RDP 로그인 실패 $($g.Count)회"
                if ($blocked) { Refresh-BlockedList; Refresh-Dashboard }
            }
        }
    }
}

(GUI "btnFwStart").Add_Click({
    $script:FwTimer.Remove_Tick($script:FwTickHandler)
    $script:FwTimer.Add_Tick($script:FwTickHandler)
    $script:FwTimer.Start()
    Write-Log "RDP 로그인 실패 자동 차단 감시 시작" | Out-Null
    [System.Windows.MessageBox]::Show("자동 차단 감시를 시작했습니다.`n(1분마다 최근 10분 내 로그인 실패 기록을 확인합니다)", "시작됨") | Out-Null
})
(GUI "btnFwStop").Add_Click({
    $script:FwTimer.Stop()
    Write-Log "RDP 로그인 실패 자동 차단 감시 중지" | Out-Null
})

# ---- ② 수동 IP / 대역 차단 ----
(GUI "btnBlockIP").Add_Click({
    $ip = (GUI "txtManualIP").Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ip)) { return }
    $ok = Block-IPAddress $ip "수동 차단"
    if ($ok) {
        (GUI "txtManualIP").Text = ""
        Refresh-BlockedList
        Refresh-Dashboard
    } else {
        [System.Windows.MessageBox]::Show("차단 실패. 관리자 권한과 IP/대역 형식을 확인해주세요.", "오류") | Out-Null
    }
})

(GUI "btnImportList").Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "텍스트 파일 (*.txt)|*.txt|모든 파일 (*.*)|*.*"
    $dlg.Title = "차단할 IP/대역 목록 파일 선택 (한 줄에 하나씩)"
    if ($dlg.ShowDialog() -eq 'OK') {
        $lines = Get-Content $dlg.FileName | Where-Object { $_.Trim() -ne "" }
        $count = 0
        foreach ($line in $lines) {
            if (Block-IPAddress $line.Trim() "목록 가져오기") { $count++ }
        }
        Refresh-BlockedList
        Refresh-Dashboard
        [System.Windows.MessageBox]::Show("$count 개의 항목을 차단했습니다.", "완료") | Out-Null
    }
})

(GUI "btnUnblockIP").Add_Click({
    $sel = (GUI "lstBlocked").SelectedItem
    if (-not $sel) { return }
    $ip = ($sel -split '\s+\|\s+')[0]
    Unblock-IPAddress $ip
    Refresh-BlockedList
    Refresh-Dashboard
})

# ================================================================
# 파일 무결성 검사
# ================================================================
function Refresh-FolderList {
    $lb = GUI "lstFolders"
    $lb.Items.Clear()
    foreach ($f in $script:State.WatchedFolders) { $lb.Items.Add($f) }
}

(GUI "btnAddFolder").Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "감시할 폴더를 선택하세요 (예: 중요 문서 폴더)"
    if ($dlg.ShowDialog() -eq 'OK') {
        if ($script:State.WatchedFolders -notcontains $dlg.SelectedPath) {
            $script:State.WatchedFolders += $dlg.SelectedPath
            Save-State
            Refresh-FolderList
            Write-Log "감시 폴더 추가: $($dlg.SelectedPath)" | Out-Null
        }
    }
})

(GUI "btnBaseline").Add_Click({
    if ($script:State.WatchedFolders.Count -eq 0) {
        [System.Windows.MessageBox]::Show("먼저 감시 폴더를 추가해주세요.", "안내") | Out-Null
        return
    }
    $hashes = @{}
    foreach ($folder in $script:State.WatchedFolders) {
        Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $h = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($h) { $hashes[$_.FullName] = $h }
        }
    }
    $script:State.FileBaseline = $hashes
    Save-State
    Write-Log "파일 무결성 기준 해시 생성 완료 ($($hashes.Count)개 파일)" | Out-Null
    [System.Windows.MessageBox]::Show("기준 해시를 생성했습니다. ($($hashes.Count)개 파일)", "완료") | Out-Null
})

(GUI "btnCheckIntegrity").Add_Click({
    $lb = GUI "lstFileResult"
    $lb.Items.Clear()
    if ($script:State.FileBaseline.Count -eq 0) {
        $lb.Items.Add("기준 해시가 없습니다. 먼저 '기준 해시 생성'을 눌러주세요.")
        return
    }

    $current = @{}
    foreach ($folder in $script:State.WatchedFolders) {
        Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $h = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($h) { $current[$_.FullName] = $h }
        }
    }

    $baseline = $script:State.FileBaseline
    $changed = 0

    foreach ($path in $baseline.Keys) {
        if (-not $current.ContainsKey($path)) {
            $lb.Items.Add("[삭제됨] $path")
            Write-Log "파일 삭제 감지: $path" "경고" | Out-Null
            $changed++
        } elseif ($current[$path] -ne $baseline[$path]) {
            $lb.Items.Add("[변경됨] $path")
            Write-Log "파일 변조 감지: $path" "경고" | Out-Null
            $changed++
        }
    }
    foreach ($path in $current.Keys) {
        if (-not $baseline.ContainsKey($path)) {
            $lb.Items.Add("[새 파일] $path")
            $changed++
        }
    }

    if ($changed -eq 0) { $lb.Items.Add("변화 없음 - 모든 파일이 기준과 일치합니다.") }
    Refresh-Dashboard
})

# ================================================================
# 복구 / 백업 (시스템 복원 지점)
# ================================================================
function Refresh-RestorePoints {
    $lb = GUI "lstRestorePoints"
    $lb.Items.Clear()
    $points = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    foreach ($p in $points) {
        $lb.Items.Add([pscustomobject]@{
            Display = "#$($p.SequenceNumber)  |  $($p.CreationTime)  |  $($p.Description)"
            Seq = $p.SequenceNumber
        })
    }
    $lb.DisplayMemberPath = "Display"
}

(GUI "btnCreateRestore").Add_Click({
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\"
        Checkpoint-Computer -Description "PC-Guardian 수동 생성 $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "복원 지점 생성 완료" | Out-Null
        [System.Windows.MessageBox]::Show("복원 지점이 생성되었습니다.", "완료") | Out-Null
        Refresh-RestorePoints
    } catch {
        [System.Windows.MessageBox]::Show("생성 실패: $_", "오류") | Out-Null
    }
})
(GUI "btnRefreshRestore").Add_Click({ Refresh-RestorePoints })

(GUI "btnDoRestore").Add_Click({
    $sel = (GUI "lstRestorePoints").SelectedItem
    if (-not $sel) { return }
    $result = [System.Windows.MessageBox]::Show(
        "선택한 복원 지점으로 되돌리시겠습니까?`nPC가 재부팅됩니다.",
        "확인", "YesNo", "Warning")
    if ($result -eq 'Yes') {
        Write-Log "시스템 복원 실행: #$($sel.Seq)" "경고" | Out-Null
        Restore-Computer -RestorePoint $sel.Seq -Confirm:$false
    }
})

# ================================================================
# 격리함
# ================================================================
function Refresh-QuarHistory {
    $lb = GUI "lstQuarHistory"
    $lb.Items.Clear()
    foreach ($item in $script:State.QuarantineItems) {
        $lb.Items.Add("$($item.Time)  |  $($item.Type)  |  $($item.Target)")
    }
}

(GUI "btnRefreshProc").Add_Click({
    $lb = GUI "lstProcesses"
    $lb.Items.Clear()
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 40 | ForEach-Object {
        $lb.Items.Add([pscustomobject]@{
            Display = "$($_.Name)  (PID $($_.Id))  -  $($_.Path)"
            Name = $_.Name
        })
    }
    $lb.DisplayMemberPath = "Display"
})

(GUI "btnKillProc").Add_Click({
    $sel = (GUI "lstProcesses").SelectedItem
    if (-not $sel) { return }
    $result = [System.Windows.MessageBox]::Show("`"$($sel.Name)`" 프로그램을 종료하시겠습니까?", "확인", "YesNo")
    if ($result -eq 'Yes') {
        Stop-Process -Name $sel.Name -Force -ErrorAction SilentlyContinue
        $script:State.QuarantineItems += [pscustomobject]@{
            Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; Type = "프로세스 종료"; Target = $sel.Name
        }
        Save-State
        Write-Log "프로세스 격리(종료): $($sel.Name)" "경고" | Out-Null
        Refresh-QuarHistory
        Refresh-Dashboard
        [System.Windows.MessageBox]::Show("종료했습니다.", "완료") | Out-Null
    }
})

# ================================================================
# 증거 수집 / 신고 리포트
# ================================================================
(GUI "btnScreenshot").Add_Click({
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $path = "$script:EvidenceDir\screenshot_$stamp.png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Log "스크린샷 저장: $path" | Out-Null
    [System.Windows.MessageBox]::Show("스크린샷을 저장했습니다.`n$path", "완료") | Out-Null
    Refresh-EvidenceList
})

function Refresh-EvidenceList {
    $lb = GUI "lstEvidence"
    $lb.Items.Clear()
    Get-ChildItem $script:EvidenceDir -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
        ForEach-Object { $lb.Items.Add("$($_.Name)   ($($_.LastWriteTime))") }
}

(GUI "btnCollectEvidence").Add_Click({
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $folder = "$script:EvidenceDir\evidence_$stamp"
    New-Item -ItemType Directory -Path $folder -Force | Out-Null

    # 1) 최근 로그인 실패 이벤트
    $since = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction SilentlyContinue
    if ($events) {
        $events | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            [pscustomobject]@{ 시간 = $_.TimeCreated; IP = $ip; 메시지 = $_.Message.Split("`n")[0] }
        } | Export-Csv "$folder\로그인실패기록.csv" -NoTypeInformation -Encoding UTF8
    }

    # 2) 방화벽 차단 목록
    $script:State.BlockedIPs | ConvertTo-Json -Depth 4 | Out-File "$folder\차단된IP목록.json" -Encoding UTF8

    # 3) 오늘 활동 로그 복사
    $todayLog = "$script:LogDir\guardian_$(Get-Date -Format 'yyyyMMdd').log"
    if (Test-Path $todayLog) { Copy-Item $todayLog "$folder\활동로그.txt" }

    # 4) 스크린샷
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bmp.Save("$folder\화면캡처.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()

    Write-Log "증거 폴더 생성: $folder" | Out-Null
    [System.Windows.MessageBox]::Show("증거 자료를 모았습니다.`n$folder", "완료") | Out-Null
    Refresh-EvidenceList
})

(GUI "btnGenReport").Add_Click({
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = "$script:EvidenceDir\신고리포트_$stamp.txt"

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("====================================")
    [void]$sb.AppendLine(" 침해사고 신고용 리포트")
    [void]$sb.AppendLine(" 생성 시각: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("====================================")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("[차단된 IP 목록]")
    foreach ($b in $script:State.BlockedIPs) {
        [void]$sb.AppendLine("  - $($b.IP)  |  차단시각: $($b.Time)  |  사유: $($b.Reason)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("[격리(종료)된 프로세스]")
    foreach ($q in $script:State.QuarantineItems) {
        [void]$sb.AppendLine("  - $($q.Target)  |  시각: $($q.Time)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("[최근 로그인 실패 이벤트 - 최근 24시간]")
    $since = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction SilentlyContinue
    if ($events) {
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            [void]$sb.AppendLine("  - $($e.TimeCreated)  |  IP: $ip")
        }
    } else {
        [void]$sb.AppendLine("  (기록 없음)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("====================================")
    [void]$sb.AppendLine(" 신고 접수처")
    [void]$sb.AppendLine("  - KISA 118센터 (kisa.or.kr / 국번없이 118)")
    [void]$sb.AppendLine("  - 경찰청 사이버수사국 (ecrm.cyber.go.kr)")
    [void]$sb.AppendLine("====================================")

    $sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "신고 리포트 생성: $reportPath" | Out-Null
    [System.Windows.MessageBox]::Show("신고용 리포트를 만들었습니다.`n$reportPath", "완료") | Out-Null
    Refresh-EvidenceList
    Invoke-Item $reportPath
})

# ================================================================
# 로그 보기
# ================================================================
function Refresh-LogView {
    $lb = GUI "lstLog"
    $lb.Items.Clear()
    $logFile = "$script:LogDir\guardian_$(Get-Date -Format 'yyyyMMdd').log"
    if (Test-Path $logFile) {
        Get-Content $logFile | Sort-Object -Descending | ForEach-Object { $lb.Items.Add($_) }
    }
}
(GUI "btnLogRefresh").Add_Click({ Refresh-LogView })
(GUI "btnLogOpenFolder").Add_Click({ Invoke-Item $script:LogDir })

# ================================================================
# 실행
# ================================================================
Refresh-Dashboard
$Window.ShowDialog() | Out-Null
