#!/usr/bin/env python
#
# Objective of this small program is to report memory usage using
# useful memory metrics for Linux.
#
# It will group processes according to their URES (unique resident set size)
# and also do reports based on per-username, per-program name and per-cpu
# statistics.
#
# Copyright 2006-2013 Aleksandr Koltsoff (czr@iki.fi)
# Released under GPL Version 2 (please see included file COPYING for
# details).
#
# Please see the included CHANGELOG for change-related information
#
# VERSION: 1.0.3 (move to github, no code changes)

from __future__ import print_function
import os
import string
import pwd
import grp
import time

# set this to 1 for debugging
DEBUG=0

# utility class to act as a cache for UID lookups
# since UID lookups will cause possible NSS activity
# over the network, it's better to cache all lookups.
class usernameCache:

  def __init__(self):
    self.uidMap = {}
    self.gidMap = {}

  def getUID(self, uid):
    if self.uidMap.has_key(uid):
      return self.uidMap[uid]

    nameData = None
    try:
      nameData = pwd.getpwuid(uid)
    except:
      pass
    if nameData != None:
      name = nameData.pw_name
    else:
      # default the name to numeric representation in case it's not found
      name = "%s" % uid
    self.uidMap[uid] = name
    return name

# use a global variable to hold the cache so that we don't
# need a separate context-object/dict
nameCache = usernameCache()

# we need to get the pagesize at this point
PAGE_SIZE = os.sysconf("SC_PAGESIZE")

# utility class to aid in formatting
# will calculate the necessary amount of left-justification for each
# column based on the width of entries
# last entry will be unjustified
class JustifiedTable:

  def __init__(self):
    # this will keep the row data in string format
    self.rows = []
    # this will keep the maximum width of each column so far
    self.columnWidths = []

  def addRow(self, row):
    # start by converting all entries into strings
    # (we keep data in string format internally)
    row = map(str, row)
    # check if we have enough columnWidths for this row
    if len(self.columnWidths) < len(row):
      self.columnWidths += [0] * (len(row) - len(self.columnWidths))
    # update columnWidths if necessary
    for idx in range(len(row)):
      if self.columnWidths[idx] < len(row[idx]):
        self.columnWidths[idx] = len(row[idx])
    # add the row into data
    self.rows.append(row)

  def outputRow(self, idx):
    row = self.rows[idx]
    for idx in range(len(row)-1):
      if row[idx] != "None":
        print("%*s" % (self.columnWidths[idx], row[idx]), end=" ")
    print(row[-1])

  # we need to add optional header output every X lines
  # it is done with an empty line and repeating first row
  def output(self, maxLines=None):
    # always start with the header
    self.outputRow(0)
    for idx in range(1, len(self.rows)):
      self.outputRow(idx)
      if maxLines != None:
        if idx % maxLines == 0:
          print()
          self.outputRow(0)

# utility to read and parse a comma delimited file (meminfo)
def parseSplitFile(filename):
  f = open(filename, "rb")
  lines = f.readlines()
  del f

  lines = map(lambda x: x.strip().split(), lines)
  return lines

# utility to parse a file which contains one line with delim entries
def parseDelimFile(filename):
  f = open(filename, "rb")
  line = f.readline()
  del f

  return line.split()

# utility to parse a file which contains one line with delim numbers
def parseNumberFile(filename):
  f = open(filename, "rb")
  line = f.readline()
  del f

  return map(int, line.split())

# routine to get mem info as a hash
# specifically:
#   input is a sequence of "Label:", "Value", "kB"
#   output is a hash of "Label" -> int(Value)
# we also add these fields:
# "UserspaceFree": how much memory is available for userspace (discounted buffers+caches)
# "SwapUsed": how much of swap is currently in use
def getMemInfo():

  ret = {}

  lines = parseSplitFile("/proc/meminfo")
  for line in lines:
    label = line[0]
    # we skip over line that starts with 'total:' (2.4 kernel has
    # it at the start and we can't parse that)
    if line[0] == 'total:':
      continue
    # we only accept lines that have colons after labels
    if label.endswith(":"):
      ret[label[:-1]] = int(line[1])

  # after we've done with conversion, we add couple of our own fields
  ret["UserspaceFree"] = ret["MemFree"] + ret["Buffers"] + ret["Cached"]
  ret["SwapUsed"] = ret["SwapTotal"] - ret["SwapFree"]

  return ret

# a map from /proc/PID/status memory-related fields into column headers
# other fields that start with Vm will user lower-case columns
vmStatusMap = {
  'Peak' : 'VIRT-P',
  'Lck' : 'LCKD',
  'HWM' : 'HWRES',
  'Data' : 'DATA',
  'Stk' : 'STACK',
  'Exe' : 'EXE',
  'Lib' : 'LIB',
  'PTE' : 'PTE' }

# return a hash of 'COLUMN-NAME': value -entries for
# process specific memory info
def getProcessMemFromStatus(pid):

  ret = {}
  lines = parseSplitFile("/proc/%d/status" % pid)

  for line in lines:
    if line[0][:2] == 'Vm':
      vmLabel = line[0][2:-1]
      if vmLabel in vmStatusMap:
        v = int(line[1])
        # !AK a 4 gig limit? uh oh. update to 2013
        if v > 4*1024*1024:
          v = -1
        ret[vmStatusMap[vmLabel]] = v
  if len(ret) == 0:
    return None
  return ret

# utility to return info for given pid (int)
# will return None if process doesn't exist anymore
# otherwise a hash:
# "pid" -> int(pid)
# "uid" -> int(uid)
# "gid" -> int(gid)
# "vmsize" -> int(vmsize in kilobytes)
# "res" -> int(res in kilobytes)
# "shared" -> int(shared in kilobytes)
# "ures" -> int(unique res in kilobytes)
# "cmd" -> string(command)
# "minflt" -> int(number of minor faults)
# "majflt" -> int(number of major faults)
# "state" -> string(state-char)
# "threads" -> int(number of threads, including main thread)
# "utime" -> int(ticks (0.01 secs) spent in user)
# "stime" -> int(ticks spent in kernel)
# "cpu" -> int(last cpu which executed code for this process)
# "statusMem" -> hash of additional fields
def getProcessInfo(pid, kernelBootTicks=0):
  global PAGE_SIZE

  pageConv = PAGE_SIZE / 1024

  ret = None

  try:
    pinfo = {}

    # get process owner and group owner using stat
    stats = os.stat("/proc/%d" % pid)
    pinfo["uid"] = stats.st_uid
    pinfo["gid"] = stats.st_gid

    pmem = parseNumberFile("/proc/%d/statm" % pid)
    # size: total (VMSIZE)
    # resident: rss (total RES)
    # share: shared pages (SHARED)
    # we don't need the other entries
    del pmem[3:]
    pmem = map(lambda x: x*pageConv, pmem)

    # we ignore processes which seem to have zero vmsize (kernel threads)
    if pmem[0] == 0:
      return None
    pinfo["vmsize"] = pmem[0]
    pinfo["res"] = pmem[1]
    pinfo["shared"] = pmem[2]
    pinfo["ures"] = pmem[1] - pmem[2]

    # get status (this changes between kernel releases)
    psmem = getProcessMemFromStatus(pid)
    pinfo["statusMem"] = psmem

    pstat = parseDelimFile("/proc/%d/stat" % pid)
    # 1: filename of the executable in parentheses
    # 2: state
    # 9: minflt %lu: minor faults (completed without disk access)
    # 11: majflt %lu: major faults

    pinfo["cmd"] = pstat[1][1:-1]
    pinfo["state"] = pstat[2]
    pinfo["minflt"] = int(pstat[9])
    pinfo["majflt"] = int(pstat[11])
    pinfo["utime"] = int(pstat[13])
    pinfo["stime"] = int(pstat[14])
    pinfo["cpu"] = int(pstat[38])
    pinfo["existsFor"] = kernelBootTicks - int(pstat[21])
    # 13 = usertime (jiff)
    # 14 = kernel time (jiff)
    # 21 = start time (jiff)
    # 38 = last CPU
    # hah. these aren't actually in jiffies, but in USER_HZ
    # which has been defined as 100 always

    pinfo["pid"] = pid
    pinfo["ppid"] = int(pstat[3])

    # attempt to count the number of threads
    # note than on older linuxen there is no /proc/X/task/
    threadCount = 0
    try:
      if os.access("/proc/%d/task/" % pid, os.X_OK):
        threadCount = len(os.listdir("/proc/%d/task" % pid))
    except:
      pass
    pinfo["threads"] = threadCount

    ret = pinfo

  except:
    pass

  return ret

# utility to return process information (for all processes)
# this is basically where most of the work starts from
def getProcessInfos():
  # this will be the return structure
  # the key will be the pid
  pinfos = {}

  # start by getting kernel uptime
  kernelUptime, kernelIdleTime = parseDelimFile("/proc/uptime")
  kernelUptime = int(float(kernelUptime)*100)

  # we need to iterate over the names under /proc at first
  for n in os.listdir("/proc"):
    # we shortcut the process by attempting a PID conversion first
    # and statting only after that
    # (based on the fact that the only entries in /proc which are
    # integers are the process entries). so we don't do extra
    # open/read/closes on proc when not necessary
    try:
      pid = int(n)
    except:
      continue

    # at this point we know that n is a number
    # note that it might be so that the process doesn't exist anymore
    # this is why we just ignore it if it has gone AWOL.
    pinfo = getProcessInfo(pid, kernelUptime)
    if pinfo != None:
      pinfos[pid] = pinfo

  return pinfos

# utility to return human readable time
# three return formats:
# < hour: x:%.2y
# rest: h:%.2y:%.2z
def getTime(ticks):
  secsTotal = ticks / 100.0
  if secsTotal < 60:
    return "%ds" % secsTotal

  secs = secsTotal % 60
  secsTotal -= secs
  minutes = secsTotal / 60
  if minutes < 60:
    return "%dm%.2ds" % (minutes, secs)
  hours = minutes / 60
  minutes = minutes % 60
  return "%dh%.2dm%.2ds" % (hours, minutes, secs)

# routine that will tell when something started based on given value in ticks
# ticks is understood to mean "for" (ie, when something was started X ticks ago)
# the label is "started", so an absolute timestamp would be nice
# if difference to current clock is more than one day, we display the date
def getElapsed(ticks, now=time.time()):
  ticks /= 100 # conv to seconds
  if ticks < 60*60*24:
    return time.strftime("%H:%M:%S", time.localtime(now-ticks))
  else:
    return time.strftime("%Y-%m-%d", time.localtime(now-ticks))

# utility to get process info as a row suitable into tabling
# note that this might get a bit hairy wrt the extra memory fields
# we need to preserve order and insert "" if there are missing
# fields for this process.
#
# statMap:
# ordered list of field-names that we want to output
def getProcessRow(pinfo, statMap, withCpu=0):
  # PID UID URES SHR VIRT MINFLT MAJFLT S CMD"
  n = nameCache.getUID(pinfo["uid"])
  # number of threads is communicated via the process name field,
  # so we munge that in here
  threadStr = ""
  if pinfo["threads"] > 1:
    threadStr = " (%d T)" % pinfo["threads"]
  cpu = None
  if withCpu:
    cpu = pinfo["cpu"]

  mainInfo = [
    pinfo["pid"],
    n,
    pinfo["ures"],
    pinfo["shared"],
    pinfo["vmsize"] ]
  restInfo = [ pinfo["minflt"],
    pinfo["majflt"],
    cpu,
    getElapsed(pinfo["existsFor"]),
    pinfo["state"],
    pinfo["cmd"]+threadStr ]

  # generate the statusMem entries
  statusMem = pinfo["statusMem"]
  statusMemEntries = []
  for label in statMap:
    if statusMem.has_key(label):
      statusMemEntries.append(statusMem[label])
    else:
      statusMemEntries.append("")

  return mainInfo + statusMemEntries + restInfo

# utility to print a label:
# - print empty line
# - print text
# - print underscore for the line
def printLabel(s):
  print()
  print(s)
  print('-'*len(s))

# main routine that gathers and outputs the reports
def doIt():
  print("Report generated at %s" % time.strftime("%Y-%m-%d %H:%M:%S"))

  meminfo = getMemInfo()
  printLabel("System wide memory information:")
  print("RAM: %.2f MiB (%.2f free [%.2f%%])" % (
    float(meminfo["MemTotal"])/1024.0, float(meminfo["UserspaceFree"])/1024.0,
    (100*meminfo["UserspaceFree"]) / float(meminfo["MemTotal"])))
  if meminfo["SwapTotal"] > 0:
    print("Swap: %.2f MiB (%.2f free [%.2f%%])" % (
    float(meminfo["SwapTotal"])/1024.0, float(meminfo["SwapFree"])/1024.0,
    (100*meminfo["SwapFree"]) / float(meminfo["SwapTotal"]) ))
  else:
    print("Swap: None")

  # statMap is created as follows:
  # - we iterate over all process data and their statusMem-hash
  #   we insert the keys into statusMap-hash
  #   convert the statusMap into a list
  #   sort it
  statMap = {}

  printLabel("Process memory usage sorted by unique resident set size (in KiB):")
  pinfos = getProcessInfos()
  # we now need to organize the list of entries according to their ures
  # for this we'll create a list with two entries:
  # [ures, pid]
  # (since pid can be used to access the process from the pinfos-hash)
  plist = []
  maxCpu = 0
  for pid, v in pinfos.items():
    maxCpu = max(maxCpu, v["cpu"])
    plist.append((v["ures"], pid))
    statusMem = v["statusMem"]
    # add the keys from this process statusMem
    if len(statusMem) > 0:
      for k in statusMem.keys():
        statMap[k] = None
  # use two steps in order to work on older pythons (newer ones
  # can use reverse=True keyparam)
  plist.sort()
  plist.reverse()

  processTable = JustifiedTable()

  # prepare the statMap
  statMap = statMap.keys()
  statMap.sort()

  cpuHeader = None
  if maxCpu > 0:
    cpuHeader = "C#"

  mainHeader = ["PID", "UID", "URES", "SHR", "VIRT"]
  postHeader = ["MINFLT", "MAJFLT", cpuHeader, "Started", "S", "CMD (n threads)"]
  statHeader = map(lambda x: x.lower(), statMap)

  processTable.addRow(mainHeader + statHeader + postHeader)

  for dummy, pid in plist:
    row = getProcessRow(pinfos[pid], statMap, maxCpu > 0)
    processTable.addRow(row)

  processTable.output(25)

  # we also print out per UID report on memory usage
  users = {}
  for v in pinfos.items():
    pinfo = v[1]
    uid = pinfo["uid"]
    if users.has_key(uid):
      users[uid][0] += pinfo["ures"]
      users[uid][1] += 1
      users[uid][2] += pinfo["utime"]
      users[uid][3] += pinfo["stime"]
    else:
      # ures, count, total utime, total stime
      users[uid] = [pinfo["ures"], 1, pinfo["utime"], pinfo["stime"]]
  # now create a list of (ures, uid)
  ulist = []
  for uid, uitems in users.items():
    ures, ucount, utime, stime = uitems
    ulist.append((ures, ucount, utime, stime, uid))
  ulist.sort()
  ulist.reverse()
  # now we have a nice list of uids and totals
  printLabel("Memory usage per user:")
  userTable = JustifiedTable()
  userTable.addRow(("USER", "COUNT", "USER-TIME", "SYS-TIME", "MEM-TOTAL"))
  for ures, ucount, utime, stime, uid in ulist:
    userTable.addRow((nameCache.getUID(uid), ucount, getTime(utime), getTime(stime), "%.2f MiB" % (float(ures) /1024.0)))
  userTable.output(25)

  # next we make a table giving the memory totals keyed with process names
  pusage = {}
  for v in pinfos.items():
    pinfo = v[1]
    cmd = pinfo["cmd"]
    if pusage.has_key(cmd):
      pusage[cmd][0] += pinfo["ures"]
      pusage[cmd][1] += 1
      pusage[cmd][2] += pinfo["utime"]
      pusage[cmd][3] += pinfo["stime"]
    else:
      pusage[cmd] = [pinfo["ures"], 1, pinfo["utime"], pinfo["stime"]]
  # another array. this time we have (ures, cmd)
  plist = []
  for cmd, uitems in pusage.items():
    ures, pcount, utime, stime = uitems
    plist.append((ures, pcount, utime, stime, cmd))
  plist.sort()
  plist.reverse()

  printLabel("Memory usage by processes with same names:")
  pusageTable = JustifiedTable()
  pusageTable.addRow(("CMD", "COUNT", "USER-TIME", "SYS-TIME", "MEM-TOTAL"))
  rest = 0
  restCount = 0
  restUtime = 0
  restStime = 0
  for ures, pcount, utime, stime, cmd in plist:
    if ures < 1024: # lump all under 1MiB processes together
      rest += ures
      restCount += 1
      restUtime += utime
      restStime += stime
    else:
      pusageTable.addRow((cmd, pcount, getTime(utime), getTime(stime), "%.2f MiB" % (float(ures) /1024.0)))
  pusageTable.addRow(("Rest", restCount, getTime(restUtime), getTime(restStime), "%.2f MiB" % (float(rest) /1024.0)))
  pusageTable.output()

  if maxCpu > 0:
    print("\nProcess information per CPU (main-threads only):")
    # hmm. we should really take into account the threads
    # on each CPU. this is a misfeature then.
    cpuTable = JustifiedTable()
    cpuTable.addRow(("CPU", "Count", "USER-TIME", "SYS-TIME", "MEM-TOTAL"))

    cpuStats = {}
    for v in pinfos.items():
      pinfo = v[1]
      cpu = pinfo["cpu"]
      utime = pinfo["utime"]
      stime = pinfo["stime"]
      ures = pinfo["ures"]
      if cpuStats.has_key(cpu):
        cpuStats[cpu][1] += 1
        cpuStats[cpu][2] += utime
        cpuStats[cpu][3] += stime
        cpuStats[cpu][4] += ures
      else:
        cpuStats[cpu] = [cpu, 1, utime, stime, ures]
    cpuList = []
    for cpu, uitems in cpuStats.items():
      cpuList.append((uitems))
    cpuList.sort()
    for entry in cpuList:
      cpuTable.addRow((entry[0], entry[1], getTime(entry[2]), getTime(entry[3]), "%.2f MiB" % (float(entry[4]) / 1024.0)))
    cpuTable.output()

if __name__ == '__main__':
  # we protect against sigpipe in this way. the wrong way obviously
  # but was too lazy.
  # ./meminfo.py | head -5 caused some problems otherwise
  if DEBUG:
    doIt()
  else:
    try:
      doIt()
    except:
      pass
