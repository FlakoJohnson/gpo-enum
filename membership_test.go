package main

import (
	"strings"
	"testing"
)

func TestParseGroupsXML_GroupMembership(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"
         name="Administrators (built-in)" image="2" changed="2026-01-15 09:00:00"
         uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}">
    <Properties action="U" newName="" description="" deleteAllUsers="0"
                deleteAllGroups="0" removeAccounts="0"
                groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members>
        <Member name="YOURDOM\ITAdmins" action="ADD" sid="S-1-5-21-123456789-1-1001"/>
        <Member name="YOURDOM\DesktopSupport" action="ADD" sid="S-1-5-21-123456789-1-1002"/>
      </Members>
    </Properties>
  </Group>
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"
         name="Remote Desktop Users" image="2" changed="2026-01-15 09:00:00"
         uid="{B2C3D4E5-F6A7-8901-BCDE-F23456789012}">
    <Properties action="U" newName="" description="" deleteAllUsers="0"
                deleteAllGroups="0" removeAccounts="0"
                groupSid="S-1-5-32-555" groupName="Remote Desktop Users">
      <Members>
        <Member name="YOURDOM\HelpDesk" action="ADD" sid="S-1-5-21-123456789-1-1003"/>
      </Members>
    </Properties>
  </Group>
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"
         name="Event Log Readers" image="2" changed="2026-01-15 09:00:00"
         uid="{C3D4E5F6-A7B8-9012-CDEF-345678901234}">
    <Properties action="U" newName="" description="" deleteAllUsers="0"
                deleteAllGroups="0" removeAccounts="0"
                groupSid="S-1-5-32-573" groupName="Event Log Readers">
      <Members>
        <Member name="YOURDOM\MonitorSvc" action="ADD" sid="S-1-5-21-123456789-1-1004"/>
      </Members>
    </Properties>
  </Group>
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="TestUser" image="2" changed="2026-01-15 09:00:00"
        uid="{D4E5F6A7-B8C9-0123-DEFA-456789012345}">
    <Properties action="U" newName="" fullName="" description=""
                cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
                changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0"
                userName="TestUser"/>
  </User>
</Groups>`

	findings := parseGroupsXML([]byte(xml))

	// Should have: 2 Administrators members (HIGH) + 1 RDP (HIGH) + 1 Event Log (INFO) + 1 cpassword (CRITICAL)
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	// cpassword should still work
	var cpass []Finding
	for _, f := range findings {
		if strings.Contains(f.Description, "cpassword") {
			cpass = append(cpass, f)
		}
	}
	if len(cpass) != 1 {
		t.Errorf("expected 1 cpassword finding, got %d", len(cpass))
	}
	if cpass[0].Severity != "CRITICAL" {
		t.Errorf("cpassword severity: got %s, want CRITICAL", cpass[0].Severity)
	}

	// Administrators group membership should be HIGH
	var adminFindings []Finding
	for _, f := range findings {
		if strings.Contains(f.Description, "Administrators") && strings.Contains(f.Description, "GPP Local Group") {
			adminFindings = append(adminFindings, f)
		}
	}
	if len(adminFindings) != 2 {
		t.Errorf("expected 2 Administrators group membership findings, got %d", len(adminFindings))
	}
	for _, f := range adminFindings {
		if f.Severity != "HIGH" {
			t.Errorf("Administrators membership severity: got %s, want HIGH", f.Severity)
		}
	}

	// RDP group should be HIGH (security-sensitive)
	var rdpFindings []Finding
	for _, f := range findings {
		if strings.Contains(f.Description, "Remote Desktop Users") {
			rdpFindings = append(rdpFindings, f)
		}
	}
	if len(rdpFindings) != 1 {
		t.Errorf("expected 1 RDP finding, got %d", len(rdpFindings))
	}
	if rdpFindings[0].Severity != "HIGH" {
		t.Errorf("RDP membership severity: got %s, want HIGH", rdpFindings[0].Severity)
	}

	// Event Log Readers should be INFO
	var eventLogFindings []Finding
	for _, f := range findings {
		if strings.Contains(f.Description, "Event Log Readers") {
			eventLogFindings = append(eventLogFindings, f)
		}
	}
	if len(eventLogFindings) != 1 {
		t.Errorf("expected 1 Event Log Readers finding, got %d", len(eventLogFindings))
	}
	if eventLogFindings[0].Severity != "INFO" {
		t.Errorf("Event Log Readers severity: got %s, want INFO", eventLogFindings[0].Severity)
	}

	// Verify detail contains useful info
	if !strings.Contains(adminFindings[0].Detail, "groupSid=S-1-5-32-544") {
		t.Errorf("missing groupSid in detail: %s", adminFindings[0].Detail)
	}
	if !strings.Contains(adminFindings[0].Description, "ITAdmins") {
		t.Errorf("missing member name in description: %s", adminFindings[0].Description)
	}
}

func TestParseGroupsXML_EmptyMembers(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"
         name="Administrators" image="2" changed="2026-01-15 09:00:00"
         uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}">
    <Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members/>
    </Properties>
  </Group>
</Groups>`

	findings := parseGroupsXML([]byte(xml))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty members, got %d", len(findings))
	}
}

func TestParseGroupsXML_SIDOnlyGroup(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"
         name="" image="2" changed="2026-01-15 09:00:00"
         uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}">
    <Properties action="U" groupSid="S-1-5-32-544" groupName="">
      <Members>
        <Member name="" action="ADD" sid="S-1-5-21-999-1234"/>
      </Members>
    </Properties>
  </Group>
</Groups>`

	findings := parseGroupsXML([]byte(xml))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Description, "Administrators") {
		t.Errorf("SID should resolve to Administrators: %s", findings[0].Description)
	}
	if !strings.Contains(findings[0].Description, "S-1-5-21-999-1234") {
		t.Errorf("member SID should appear when name is empty: %s", findings[0].Description)
	}
}

func TestParseGptTmpl_RestrictedGroups(t *testing.T) {
	inf := `[Unicode]
Unicode=yes
[Group Membership]
*S-1-5-32-544__Members = *S-1-5-21-123456789-1001-1234,*S-1-5-21-123456789-1001-5678
*S-1-5-32-544__Memberof =
*S-1-5-32-555__Members = *S-1-5-21-123456789-1001-9999
Administrators__Members = YOURDOM\HelpDesk
[System Access]
MinimumPasswordLength = 14
`
	findings := parseGptTmpl([]byte(inf))

	var restricted []Finding
	for _, f := range findings {
		if strings.Contains(f.Description, "Restricted Groups") {
			restricted = append(restricted, f)
		}
	}

	// __Members with empty value should be skipped, __Memberof with empty value skipped
	// So: S-1-5-32-544__Members (2 members), S-1-5-32-555__Members (1), Administrators__Members (1)
	if len(restricted) != 3 {
		t.Fatalf("expected 3 restricted group findings, got %d: %+v", len(restricted), restricted)
	}

	// Administrators (S-1-5-32-544) should be HIGH
	highCount := 0
	for _, f := range restricted {
		if f.Severity == "HIGH" {
			highCount++
		}
	}
	if highCount < 2 {
		t.Errorf("expected at least 2 HIGH findings (S-1-5-32-544 + S-1-5-32-555), got %d", highCount)
	}

	// Should resolve well-known SIDs in descriptions
	found544 := false
	for _, f := range restricted {
		if strings.Contains(f.Description, "Administrators") && strings.Contains(f.Description, "S-1-5-32-544") {
			found544 = true
			break
		}
	}
	if !found544 {
		t.Error("S-1-5-32-544 should resolve to 'Administrators (S-1-5-32-544)'")
	}

	// Named group ("Administrators__Members") should also work
	foundNamed := false
	for _, f := range restricted {
		if strings.Contains(f.Description, "HelpDesk") {
			foundNamed = true
			break
		}
	}
	if !foundNamed {
		t.Error("Administrators__Members = YOURDOM\\HelpDesk should produce a finding")
	}
}

func TestParseGptTmpl_RestrictedGroups_EmptyMembers(t *testing.T) {
	inf := `[Group Membership]
*S-1-5-32-544__Members =
*S-1-5-32-544__Memberof =
`
	findings := parseGptTmpl([]byte(inf))

	for _, f := range findings {
		if strings.Contains(f.Description, "Restricted Groups") {
			t.Errorf("empty member lists should produce no findings, got: %s", f.Description)
		}
	}
}

func TestResolveSID(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"*S-1-5-32-544", "Administrators (S-1-5-32-544)"},
		{"S-1-5-32-555", "Remote Desktop Users (S-1-5-32-555)"},
		{"*S-1-5-11", "Authenticated Users (S-1-5-11)"},
		{"S-1-5-21-123-456", "S-1-5-21-123-456"},
		{"DOMAIN\\User", "DOMAIN\\User"},
	}
	for _, tc := range tests {
		got := resolveSID(tc.in)
		if got != tc.want {
			t.Errorf("resolveSID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
