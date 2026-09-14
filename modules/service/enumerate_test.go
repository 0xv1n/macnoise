package service

import (
	"reflect"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

const sampleLaunchdOutput = `com.apple.xpc.launchd.domain.system = {
	path = /System/Library/LaunchDaemons/com.apple.decoy.plist
	services = {
		    1234     0	com.apple.mdworker
		       -     0	com.apple.securityd
		     999     0	com.example.thirdparty
		       -     0	localservice
	}
	endpoints = {
		"com.apple.system.notification_center" = {
	}
}

func TestParseLaunchdServices_UnqualifiedLabel(t *testing.T) {
	got := parseLaunchdServices(sampleLaunchdOutput, "", 10)
	if !reflect.DeepEqual(got, []string{"com.apple.mdworker", "com.apple.securityd", "com.example.thirdparty", "localservice"}) {
		t.Errorf("services = %v, want every label in the services block", got)
	}
}
`

func TestSvcEnumerateMetadata(t *testing.T) {
	info := (&svcEnumerate{}).Info()
	if info.Name != "svc_enumerate" {
		t.Errorf("Name = %q, want svc_enumerate", info.Name)
	}
	if info.Category != module.CategoryService {
		t.Errorf("Category = %q, want service", info.Category)
	}
	if !reflect.DeepEqual(info.EventTypes, []string{"service_enumerate"}) {
		t.Errorf("EventTypes = %v, want service_enumerate", info.EventTypes)
	}
}

func TestParseLaunchdServices(t *testing.T) {
	got := parseLaunchdServices(sampleLaunchdOutput, "com.apple", 10)
	want := []string{"com.apple.mdworker", "com.apple.securityd"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("services = %v, want %v", got, want)
	}
}

func TestEnumerationDomains(t *testing.T) {
	const user = "gui/501"
	tests := []struct {
		scope string
		want  []string
	}{
		{scope: "all", want: []string{user, systemDomain}},
		{scope: "user", want: []string{user}},
		{scope: "system", want: []string{systemDomain}},
	}
	for _, tt := range tests {
		if got := enumerationDomains(tt.scope, user); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("enumerationDomains(%q) = %v, want %v", tt.scope, got, tt.want)
		}
	}
}
