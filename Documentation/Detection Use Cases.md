# Detection Use Cases

## Use Case 1 — Process Creation Monitoring

### Objective

Detect newly created processes using Sysmon EventCode 1.

### SPL Query

```spl
index=main EventCode=1
| table _time Computer User Image CommandLine ParentImage
```

---

## Use Case 2 — Failed Login Detection

### Objective

Detect failed Windows logon attempts.

### SPL Query

```spl
index=main EventCode=4625
```

---

## Use Case 3 — Successful Login Monitoring

### Objective

Monitor successful user logins.

### SPL Query

```spl
index=main EventCode=4624
```

---

## Use Case 4 — Network Connection Monitoring

### Objective

Monitor outbound network connections using Sysmon.

### SPL Query

```spl
index=main EventCode=3
```

---

## Use Case 5 — PowerShell Activity

### Objective

Detect PowerShell execution for possible malicious activity.

### SPL Query

```spl
index=main powershell
```

---

## Use Case 6 — Command Prompt Execution

### Objective

Detect execution of cmd.exe.

### SPL Query

```spl
index=main cmd.exe
```
