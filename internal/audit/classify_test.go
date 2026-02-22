package audit

import "testing"

func TestClassify_NetworkTCP(t *testing.T) {
	cl := Classify("network", "tcp_connect")
	if cl.ClassUID != 4001 {
		t.Errorf("expected class_uid 4001, got %d", cl.ClassUID)
	}
	if cl.CategoryUID != 4 {
		t.Errorf("expected category_uid 4, got %d", cl.CategoryUID)
	}
	if cl.ActivityID != 1 {
		t.Errorf("expected activity_id 1 (Connect), got %d", cl.ActivityID)
	}
}

func TestClassify_NetworkHTTP(t *testing.T) {
	cl := Classify("network", "http_get")
	if cl.ClassUID != 4002 {
		t.Errorf("expected class_uid 4002 for http_get, got %d", cl.ClassUID)
	}
	if cl.ClassName != "HTTP Activity" {
		t.Errorf("expected 'HTTP Activity', got %q", cl.ClassName)
	}
}

func TestClassify_NetworkDNS(t *testing.T) {
	cl := Classify("network", "dns_query")
	if cl.ClassUID != 4003 {
		t.Errorf("expected class_uid 4003 for dns_query, got %d", cl.ClassUID)
	}
}

func TestClassify_NetworkListen(t *testing.T) {
	cl := Classify("network", "tcp_listen")
	if cl.ClassUID != 4001 {
		t.Errorf("expected class_uid 4001, got %d", cl.ClassUID)
	}
	if cl.ActivityID != 5 {
		t.Errorf("expected activity_id 5 (Listen), got %d", cl.ActivityID)
	}
}

func TestClassify_Process(t *testing.T) {
	cl := Classify("process", "spawn")
	if cl.ClassUID != 1007 {
		t.Errorf("expected class_uid 1007 for process, got %d", cl.ClassUID)
	}
	if cl.CategoryUID != 1 {
		t.Errorf("expected category_uid 1, got %d", cl.CategoryUID)
	}
	if cl.ActivityID != 1 {
		t.Errorf("expected activity_id 1 (Launch), got %d", cl.ActivityID)
	}
}

func TestClassify_ProcessTerminate(t *testing.T) {
	cl := Classify("process", "terminate")
	if cl.ActivityID != 2 {
		t.Errorf("expected activity_id 2 (Terminate), got %d", cl.ActivityID)
	}
}

func TestClassify_FileCreate(t *testing.T) {
	cl := Classify("file", "create")
	if cl.ClassUID != 1001 {
		t.Errorf("expected class_uid 1001 for file, got %d", cl.ClassUID)
	}
	if cl.ActivityID != 3 {
		t.Errorf("expected activity_id 3 (Create), got %d", cl.ActivityID)
	}
}

func TestClassify_FileRead(t *testing.T) {
	cl := Classify("file", "read")
	if cl.ActivityID != 4 {
		t.Errorf("expected activity_id 4 (Read), got %d", cl.ActivityID)
	}
}

func TestClassify_PlistModify(t *testing.T) {
	cl := Classify("plist", "modify")
	if cl.ClassUID != 1001 {
		t.Errorf("expected class_uid 1001 for plist, got %d", cl.ClassUID)
	}
	if cl.ActivityID != 5 {
		t.Errorf("expected activity_id 5 (Update) for modify, got %d", cl.ActivityID)
	}
}

func TestClassify_TCC(t *testing.T) {
	cl := Classify("tcc", "fda_access")
	if cl.ClassUID != 6003 {
		t.Errorf("expected class_uid 6003 for tcc, got %d", cl.ClassUID)
	}
	if cl.CategoryUID != 6 {
		t.Errorf("expected category_uid 6 for tcc, got %d", cl.CategoryUID)
	}
}

func TestClassify_XPC(t *testing.T) {
	cl := Classify("xpc", "connect")
	if cl.ClassUID != 6003 {
		t.Errorf("expected class_uid 6003 for xpc, got %d", cl.ClassUID)
	}
}

func TestClassify_Service(t *testing.T) {
	cl := Classify("service", "launch_agent")
	if cl.ClassUID != 1006 {
		t.Errorf("expected class_uid 1006 for service, got %d", cl.ClassUID)
	}
}

func TestClassify_EndpointSecurityFile(t *testing.T) {
	cl := Classify("endpoint_security", "es_file_create")
	if cl.ClassUID != 1001 {
		t.Errorf("expected class_uid 1001 for es_file_*, got %d", cl.ClassUID)
	}
}

func TestClassify_EndpointSecurityProcess(t *testing.T) {
	cl := Classify("endpoint_security", "es_process_exec")
	if cl.ClassUID != 1007 {
		t.Errorf("expected class_uid 1007 for es_process_*, got %d", cl.ClassUID)
	}
}

func TestClassify_UnknownFallback(t *testing.T) {
	cl := Classify("unknown_category", "unknown_event")
	if cl.ClassUID != 6003 {
		t.Errorf("expected fallback class_uid 6003, got %d", cl.ClassUID)
	}
	if cl.ActivityID != 99 {
		t.Errorf("expected fallback activity_id 99 (Other), got %d", cl.ActivityID)
	}
}

func TestClassify_TypeUID(t *testing.T) {
	cl := Classify("network", "tcp_connect")
	typeUID := cl.ClassUID*100 + cl.ActivityID
	if typeUID != 400101 {
		t.Errorf("expected type_uid 400101, got %d", typeUID)
	}
}
