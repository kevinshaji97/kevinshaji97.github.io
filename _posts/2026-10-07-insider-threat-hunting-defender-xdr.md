---
title: "USB Is Blocked. So They Used the Cloud."
date: 2026-10-07 10:00:00 +0100
categories: [Incident Response, Threat Hunting]
tags: [defender-xdr, kql, insider-threat, data-exfiltration, cloud-storage]
description: Hunting cloud storage exfiltration in Defender XDR when USB is locked down, and the drive-letter trick that keeps catching it.
---

So you've blocked USB. Removable storage policy, deployed, tested, ticket closed. Data exfil: solved.

Reader, it was not solved.

People who want to walk out with data don't give up because the USB port stopped working. They just install Google Drive. Or pCloud. Or Dropbox. And now the data leaves over HTTPS to a perfectly legitimate cloud service, mixed in with everyone else's perfectly legitimate traffic.

This post is about the one hunt that has caught this more often than anything else I've tried in Defender XDR, and it's almost embarrassingly simple.

## The giveaway: cloud drives look like drives

Desktop sync clients for personal cloud storage love to pretend they're a disk.

- **Google Drive for desktop** mounts a virtual drive, usually `G:`
- **pCloud Drive** mounts one too, typically `P:`
- Others do similar things, or sync to a local folder you can watch instead

From the user's point of view, it's just another drive in File Explorer. Drag the client folder onto `G:`, go get a coffee, done.

From Defender's point of view, that's a big pile of `FileCreated` events on a drive letter that isn't `C:`.

That's the whole trick. **Bulk file creation on a non-system drive is a fantastic exfil signal**, especially in an estate where USB is already blocked, because there are far fewer legitimate reasons for it.

## Step 1: Work out what "normal" drive letters look like

Before you go hunting for weird drives, find out which ones are normal in your estate. Some laptops have a `D:` data partition. Some users have mapped network drives. Some VDI images have their own oddities.

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| extend Drive = toupper(substring(FolderPath, 0, 2))
| where Drive matches regex @"^[A-Z]:$"
| summarize Devices = dcount(DeviceId),
            Events = count()
            by Drive
| sort by Devices desc
```

You'll get `C:` on basically everything, then a long tail. The letters that show up on a large chunk of your fleet are usually system partitions or mapped shares. The letters that show up on a handful of devices are the interesting ones.

Turn the boring ones into an exclusion list. Mine started as `C:` plus whatever our standard images and drive mappings use.

## Step 2: Bulk file creation on everything else

```kql
let SystemDrives = dynamic(["C:", "D:"]);   // from Step 1 – tune for your estate
let Threshold = 50;
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| extend Drive = toupper(substring(FolderPath, 0, 2))
| where Drive matches regex @"^[A-Z]:$"
| where Drive !in (SystemDrives)
| summarize Files = count(),
            Extensions = make_set(tostring(split(FileName, ".")[-1]), 15),
            SampleFiles = make_set(FileName, 15),
            Processes = make_set(InitiatingProcessFileName, 5)
            by DeviceName, InitiatingProcessAccountName, Drive, bin(Timestamp, 1h)
| where Files > Threshold
| sort by Files desc
```

What I look at in the results:

- **The drive letter.** `G:` and `P:` jump out immediately.
- **The extensions.** `.xlsx`, `.docx`, `.pdf`, `.pptx`, `.csv`, `.zip` in bulk = business data. A pile of `.tmp` and `.log` files = probably an app being an app.
- **The process.** `explorer.exe` means a human dragged and dropped. That's very different from a backup agent or a sync service writing its own cache.
- **The file names.** Honestly, half the time the file names alone tell you whether this is "my holiday photos" or "Client_Pricing_Master_FINAL_v3".

## Step 2b: Only alert on drives that are new for that device

Static exclusion lists drift. A more robust version compares each device against its own history and only flags drive letters it hasn't used before:

```kql
let Lookback = 30d;
let Window = 1d;
let Threshold = 50;
let KnownDrives = DeviceFileEvents
| where Timestamp between (ago(Lookback) .. ago(Window))
| extend Drive = toupper(substring(FolderPath, 0, 2))
| where Drive matches regex @"^[A-Z]:$"
| distinct DeviceId, Drive;
DeviceFileEvents
| where Timestamp > ago(Window)
| where ActionType == "FileCreated"
| extend Drive = toupper(substring(FolderPath, 0, 2))
| where Drive matches regex @"^[A-Z]:$" and Drive != "C:"
| join kind=leftanti KnownDrives on DeviceId, Drive
| summarize Files = count(),
            SampleFiles = make_set(FileName, 15)
            by DeviceName, InitiatingProcessAccountName, Drive
| where Files > Threshold
```

The trade-off: this catches the "installed Google Drive yesterday and immediately dumped everything into it" pattern really well, but it'll miss someone who's had the drive mounted for months. I run both.

## Step 3: Confirm what the drive actually is

A new `G:` drive is a lead, not a conclusion. Check what's actually installed and running:

```kql
// What cloud sync clients are installed?
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("google drive", "pcloud", "dropbox", "mega", "box")
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion
```

```kql
// Is the client actually running, and since when?
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("GoogleDriveFS.exe", "pCloud.exe", "Dropbox.exe", "MEGAsync.exe")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, AccountName, FileName
| sort by FirstSeen desc
```

`FirstSeen` is gold. "Client first ran on Monday, bulk copy to `G:` on Monday afternoon" is a much stronger story than either fact on its own.

## Step 4: Connect it back to where the data came from

Exfil usually has a shape: **collect → stage → move**. The `G:` drive is the "move". The "collect" is often a bulk download from SharePoint or OneDrive just beforehand.

```kql
let Downloads = CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Downloaded = count(),
            FirstDownload = min(Timestamp)
            by AccountObjectId, AccountDisplayName;
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| extend Drive = toupper(substring(FolderPath, 0, 2))
| where Drive in ("G:", "P:")      // or reuse your non-system drive logic
| summarize CopiedToCloudDrive = count(),
            FirstCopy = min(Timestamp)
            by AccountObjectId = InitiatingProcessAccountObjectId, DeviceName, Drive
| join kind=inner Downloads on AccountObjectId
| where FirstCopy > FirstDownload
| project AccountDisplayName, DeviceName, Drive, Downloaded, FirstDownload, CopiedToCloudDrive, FirstCopy
```

Pulled 300 files from the Clients site, then 280 files appeared on `G:` an hour later? That's your timeline.

## Step 5: Don't forget the browser

Not everyone installs a client. Some just drag files into `drive.google.com` in a browser tab, and no drive letter ever appears.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("drive.google.com", "pcloud.com", "dropbox.com",
                           "mega.nz", "wetransfer.com", "box.com")
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| summarize Connections = count(),
            Sites = make_set(RemoteUrl, 10)
            by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1d)
| sort by Connections desc
```

**Caveat I learned the hard way:** `DeviceNetworkEvents` tells you a connection happened, not how much data left. Browsing Google Drive and uploading 4GB to it look the same here. For volume, you need Defender for Cloud Apps, your proxy logs, or Endpoint DLP. Don't oversell what this query proves.

## Things that made this hunt actually work

- **Baseline your drive letters first.** Skipping Step 1 gets you a results table full of `D:` partitions and mapped shares, and a sad afternoon.
- **Watch leavers harder.** The weeks before someone's last day are where most of the real hits came from. Defender doesn't know who's resigned, HR does. A leavers watchlist you can join against is worth more than any threshold tuning.
- **Look at the content, not just the count.** 500 files can be a photo library. 40 files can be the entire pricing model.
- **Close the door after you find it.** If personal cloud storage isn't sanctioned, block the clients from installing, mark the apps as unsanctioned in Defender for Cloud Apps, and use Endpoint DLP to restrict uploads to unapproved cloud domains. 

## The non-technical bit (which is the important bit)

- **Get HR and Legal involved early**, not after you've built a 40-slide timeline on a named person.
- **Have an agreed process** for who can approve investigating an individual and who sees the results.
- **Privacy is real.**  Monitoring needs to be justified, documented and covered in policy.
- **Assume innocence until the story says otherwise.** Plenty of "suspicious" `G:` drives turn out to be someone who didn't know the policy. That's a conversation, not an investigation.
- **Write facts, not vibes.** "User installed Google Drive at 14:02, downloaded 312 files from the Clients site between 14:10 and 14:35, and created 298 files on G: between 14:40 and 15:05." Not "user acted suspiciously."

## TL;DR

- Blocking USB moves the problem to the cloud, it doesn't remove it
- Cloud sync clients like Google Drive and pCloud mount as drive letters, usually `G:` and `P:`
- Find your normal system drives, then hunt for bulk `FileCreated` on everything else
- Confirm the client, then link it back to SharePoint/OneDrive downloads for the full timeline
- Browser uploads won't show a drive letter, so hunt those separately and know the limits

If you've got a cloud exfil query I haven't covered, I'd genuinely like to steal it. For research purposes. Obviously.
