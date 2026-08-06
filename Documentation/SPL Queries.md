# Splunk SPL Queries

## 1. Total Events

```spl
index=main
| stats count
```

---

## 2. Event Code Distribution

```spl
index=main
| stats count by EventCode
```

---

## 3. Top Users

```spl
index=main
| stats count by User
| sort -count
```

---

## 4. Recent Process Creation Events

```spl
index=main EventCode=1
| table _time Image User CommandLine ParentImage
```

---

## 5. Top Process Names

```spl
index=main EventCode=1
| stats count by Image
| sort -count
```