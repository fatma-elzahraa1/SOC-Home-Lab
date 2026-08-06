# Splunk SPL Queries

## Search All Events

```spl
index=main
```

---

## Count Total Events

```spl
index=main
| stats count
```

---

## Events by Source

```spl
index=main
| stats count by source
```

---

## Events by EventCode

```spl
index=main
| stats count by EventCode
```

---

## Top Users

```spl
index=main
| stats count by User
```

---

## Recent Process Creation Events

```spl
index=main EventCode=1
| table _time Computer User Image CommandLine ParentImage
```

---

## Search PowerShell Events

```spl
index=main powershell
```

---

## Search CMD Events

```spl
index=main cmd.exe
```

---

## Search Network Connections

```spl
index=main EventCode=3
```

---

## Search Failed Logons

```spl
index=main EventCode=4625
```

---

## Search Successful Logons

```spl
index=main EventCode=4624
```
