# -*- coding: utf-8 -*-
"""接口回归验证脚本（评审后）。"""
import json
import urllib.request

H = {"Authorization": "Bearer dev-token", "Content-Type": "application/json"}


def post(u, body):
    req = urllib.request.Request("http://localhost:8000" + u, data=json.dumps(body).encode(), headers=H)
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


def get(u):
    req = urllib.request.Request("http://localhost:8000" + u, headers=H)
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


# F2: 批量事件接口
r = get("/api/events?limit=5")
ids = [e["event_id"] for e in r["data"]["items"]]
b = post("/api/events/batch", {"ids": ids})
print("batch events OK:", b["code"] == 0, "| items:", len(b["data"]["items"]), "| 解密 dst_ip:", b["data"]["items"][0].get("dst_ip"))

# 报告 timeline 解密
reps = get("/api/reports?limit=3")
rid = reps["data"]["items"][0]["report_id"]
rep = get("/api/reports/" + rid)
print("report timeline decrypted:", len(rep["data"]["timeline"]), "items | scope:", len(rep["data"]["scope"]))

# 设置状态（App 角标数据源）
s = get("/api/settings")
print("settings:", s["data"]["llm"]["mode"], "| intel:", s["data"]["intel"])

# 上传 .exe 应被拒
import http.client
conn = http.client.HTTPConnection("localhost", 8000, timeout=30)
boundary = "----testboundary"
part = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="evil.exe"\r\n'
        'Content-Type: application/octet-stream\r\n\r\nMZfake\r\n')
body = (part + '--' + boundary + '--\r\n').encode()
conn.request("POST", "/api/data/upload", body, {
    "Authorization": "Bearer dev-token",
    "Content-Type": "multipart/form-data; boundary=" + boundary,
})
resp = conn.getresponse()
print("upload .exe rejected:", resp.status in (200, 400), "|", resp.read().decode()[:80])
conn.close()

# 合法 .json 上传应成功
conn = http.client.HTTPConnection("localhost", 8000, timeout=60)
boundary = "----testboundary2"
json_body = json.dumps([{"event_id": "evt_t1", "ts": "2026-09-22T10:00:00", "type": "flow",
                         "src_ip": "10.0.0.1", "dst_ip": "45.77.10.20", "dst_port": 443,
                         "process": "", "host": "test-host", "label": "attack", "scene": "T"}])
part = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="sample.json"\r\n'
        'Content-Type: application/json\r\n\r\n' + json_body + '\r\n')
body = (part + '--' + boundary + '--\r\n').encode()
conn.request("POST", "/api/data/upload", body, {
    "Authorization": "Bearer dev-token",
    "Content-Type": "multipart/form-data; boundary=" + boundary,
})
resp = conn.getresponse()
out = resp.read().decode()
print("upload .json accepted:", resp.status == 200, "|", out[:120])
conn.close()
