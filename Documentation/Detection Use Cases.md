# Detection Use Cases

## 1. Process Creation Monitoring

**Objective**

Detect newly created processes on Windows endpoints.

**Event Code**

Sysmon Event Code 1

**SPL Query**

```spl
index=main EventCode=1
| table _time Image User CommandLine ParentImage
```

---

## 2. User Activity Monitoring

**Objective**

Identify the most active users on the endpoint.

**SPL Query**

```spl
index=main
| stats count by User
| sort -count
```

---

## 3. Event Volume Monitoring

**Objective**

Monitor total log volume received by Splunk.

**SPL Query**

```spl
index=main
| stats count
```

---

## 4. Event Code Distribution

**Objective**

Identify the most common Windows events.

**SPL Query**

```spl
index=main
| stats count by EventCode
```

---

## 5. Top Executed Processes

**Objective**

Identify frequently executed applications.

**SPL Query**

```spl
index=main EventCode=1
| stats count by Image
| sort -count
```