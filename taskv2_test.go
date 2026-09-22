package main

import (
	"strings"
	"testing"
)

func TestParseScheduledTasksXML_TaskV2(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Windows11 AD Group Membership Sync" image="2" userContext="0" removePolicy="0" changed="2026-07-14 19:10:21" uid="{C53D6D03-E32E-4150-8F90-1D5F284DCFBD}">
    <Properties action="U" name="Windows11 AD Group Membership Sync" runAs="AAWH\SVCVaronisSQL" logonType="S4U">
      <Task version="1.3">
        <Principals>
          <Principal id="Author">
            <UserId>AAWH\SVCVaronisSQL</UserId>
            <LogonType>S4U</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Triggers>
          <BootTrigger>
            <Enabled>true</Enabled>
            <Delay>PT1M</Delay>
            <Repetition><Interval>PT30M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
            <StartBoundary>2026-07-14T14:57:26</StartBoundary>
          </BootTrigger>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
            <Arguments>-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\AtlasAir\Windows11-AD-GroupMemberships\Sync-Windows11-ADGroupMemberships.ps1"</Arguments>
            <WorkingDirectory>C:\ProgramData\AtlasAir\Windows11-AD-GroupMemberships</WorkingDirectory>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>`

	findings := parseScheduledTasksXML([]byte(xml))

	if len(findings) == 0 {
		t.Fatal("expected findings from TaskV2, got none")
	}

	// Should have: 1 HIGH for HighestAvailable task + 1 HIGH for writable path
	var highFindings []Finding
	for _, f := range findings {
		if f.Severity == "HIGH" {
			highFindings = append(highFindings, f)
		}
	}
	if len(highFindings) < 2 {
		t.Errorf("expected at least 2 HIGH findings (task + writable path), got %d: %+v", len(highFindings), highFindings)
	}

	// Check task finding
	foundTask := false
	for _, f := range findings {
		if strings.Contains(f.Description, "HighestAvailable") && strings.Contains(f.Description, "SVCVaronisSQL") {
			foundTask = true
			if !strings.Contains(f.Detail, "powershell") {
				t.Errorf("task detail should contain command: %s", f.Detail)
			}
			if !strings.Contains(f.Detail, "trigger=BootTrigger interval=PT30M") {
				t.Errorf("task detail should contain trigger info: %s", f.Detail)
			}
			break
		}
	}
	if !foundTask {
		t.Error("expected a finding for HighestAvailable task running as SVCVaronisSQL")
	}

	// Check writable path finding
	foundWritable := false
	for _, f := range findings {
		if strings.Contains(f.Description, "user-writable path") {
			foundWritable = true
			if !strings.Contains(f.Detail, "ProgramData") {
				t.Errorf("writable path detail should mention ProgramData: %s", f.Detail)
			}
			break
		}
	}
	if !foundWritable {
		t.Error("expected a finding for script in user-writable path (C:\\ProgramData)")
	}
}

func TestParseScheduledTasksXML_TaskV2_LowPriv(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Cleanup Task" image="2">
    <Properties action="U" name="Cleanup Task" runAs="DOMAIN\svccleanup" logonType="Password">
      <Task version="1.3">
        <Principals>
          <Principal id="Author">
            <UserId>DOMAIN\svccleanup</UserId>
            <LogonType>Password</LogonType>
            <RunLevel>LeastPrivilege</RunLevel>
          </Principal>
        </Principals>
        <Actions Context="Author">
          <Exec>
            <Command>C:\Scripts\cleanup.bat</Command>
            <Arguments></Arguments>
            <WorkingDirectory>C:\Scripts</WorkingDirectory>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>`

	findings := parseScheduledTasksXML([]byte(xml))

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for low-priv task, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "MEDIUM" {
		t.Errorf("low-priv task with runAs should be MEDIUM, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Description, "svccleanup") {
		t.Errorf("should mention the runAs account: %s", findings[0].Description)
	}
}

func TestParseScheduledTasksXML_V1CPassword(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <Task clsid="{2DEECB1C-261F-4e13-9B21-16FB83BC03BD}" name="OldTask">
    <Properties runAs="DOMAIN\admin" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" appName="cmd.exe"/>
  </Task>
</ScheduledTasks>`

	findings := parseScheduledTasksXML([]byte(xml))

	var cpass, cmd []Finding
	for _, f := range findings {
		if strings.Contains(f.Description, "cpassword") {
			cpass = append(cpass, f)
		}
		if strings.Contains(f.Description, "interesting command") {
			cmd = append(cmd, f)
		}
	}
	if len(cpass) != 1 {
		t.Errorf("expected 1 cpassword finding, got %d", len(cpass))
	}
	if len(cmd) != 1 {
		t.Errorf("expected 1 interesting command finding, got %d", len(cmd))
	}
}

func TestIsWritablePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{`C:\ProgramData\AtlasAir\script.ps1`, true},
		{`c:\programdata\test`, true},
		{`C:\Temp\run.bat`, true},
		{`C:\Windows\Temp\x.ps1`, true},
		{`C:\Users\Public\script.ps1`, true},
		{`C:\Program Files\App\run.exe`, false},
		{`C:\Windows\System32\cmd.exe`, false},
		{`\\server\share\script.ps1`, false},
	}
	for _, tc := range tests {
		got := isWritablePath(tc.path)
		if got != tc.want {
			t.Errorf("isWritablePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
