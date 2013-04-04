#!/usr/bin/env python

# This script will capture information about the Zenoss master, hubs and collectors.  It will eventuallly output two 
#  files (only one implemented for now).  One file will be a report is reStructured Text of the environment and some
#  information about its health.  The second file will just contain hostnames and information about the boxes to allow 
#  for producing (in an automated fashion) an architecture diagram.

# Import Zenoss modules so this can run in the standard Python interpreter
print "Trying to connect to DMD"
import Globals, sys
from Products.ZenUtils.ZenScriptBase import ZenScriptBase
zenscript = ZenScriptBase(connect=True, noopts=1)
dmd = None
try:
    dmd = zenscript.dmd
    print "Connected to DMD"
except Exception, e:
    print "Connection to zenoss dmd failed: %s\n" % e
    sys.exit(1)
#


#  Need to accept a couple of arguments
#  File to write output to - example "/tmp/ZenossArchReport.txt"
#  Customer - example "Zenoss, Inc."
#  Title  - example "Internal IT Infrastructure"
import optparse
p = optparse.OptionParser()
#  File to write output to - example "/tmp/ZenossArchReport"
p.add_option("-f", "--file", action="store", dest="outfile")
p.set_defaults(outfile="/tmp/ZenossArchReport.txt")
#  Customer - example "Zenoss, Inc."
p.add_option("-c", "--customer", action="store", dest="cust_name")
p.set_defaults(cust_name="Enterprise Customer")
#  Title  - example "Internal IT Infrastructure"
p.add_option("-t", "--title", action="store", dest="title_text")
p.set_defaults(title_text="Architecture Review")

opts, args = p.parse_args()

outfile = opts.outfile + ".gz"
cust_name = opts.cust_name
title_text = opts.title_text

args = None

# Open file to write results to
import gzip
out = gzip.open(outfile,"w")

# Functions for later use
def silentCheck(cmd):
    import subprocess
    p = subprocess.Popen(cmd,
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout

_LOOPBACKNAMES = set(('localhost', 'localhost.localdomain', '127.0.0.1'))

def _discoverLocalhostNames():
    names = set()
    import subprocess
    # check the many variants of hostname
    for args in ("", "-i", "-I", "-a"):
        cmd = "hostname %s" % args
        p = subprocess.Popen(cmd,
             shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        for vals in stdout.lower().strip().split():
           names.add(vals)
    return names

_LOCALHOSTNAMES = _LOOPBACKNAMES.union(_discoverLocalhostNames())

def processCpuInfo(cpuinfo):
    cpuinfo.pop(-1)
    cpuinfo.pop(-1)
    cpuinfo.pop(-1)
    cpuinfo.pop(-1)
    cpuinfo.pop(-1)
    cpuinfo.pop(8)
    cpuinfo.pop(8)
    cpuinfo.pop(8)
    cpuinfo.pop(8)
    cpuinfo.pop(8)
    return cpuinfo

def processMemInfo(meminfo):
#    for i in range(0,22):
#        meminfo.pop(-1)
    return meminfo


# Produce output in reStructured Text

# Get title from arguments, print at top of page
out.write("=========================================================\n")
out.write(title_text + "\n")
out.write("=========================================================\n")
out.write("\n")

# Print Customer Name, current date/time as subtitle
out.write(cust_name + "\n")
out.write("---------------------------------------------------------\n")
out.write("\n")


# Section title - Master information
out.write("Master\n")
out.write("---------------------------------------------------------\n")
out.write("\n")

# Subsection - Host information (cpu, memory, etc.)
out.write("Host information\n")
out.write("=========================================================\n")
out.write("\n")

master_hostname =  list(_LOCALHOSTNAMES)
out.write("* Hostnames and IP addresses\n")
for hname in master_hostname:
   out.write("  - " + hname + "\n")

# Get cpu and memory information from master - eventually need to parse this out
master_info = {}
try:
    meminfo = open('/proc/meminfo').read().splitlines()
    master_info['meminfo'] = processMemInfo(meminfo)
    out.write("\n\n")
    cpuinfo = open('/proc/cpuinfo').read().splitlines()
    master_info['cpuinfo'] = processCpuInfo(cpuinfo)
    out.write("* CPU Information\n")
    for info in master_info['cpuinfo']:
        out.write("  - " + info + "\n")
    out.write("\n\n")
    out.write("* Memory Information\n")
    for info in master_info['meminfo']:
        out.write("  - " + info + "\n")
except Exception as ex:
    if not master_info.has_key('exceptions'):
        master_info['exceptions'] = ''
    master_info['exceptions'] += str(ex)
    print ex
out.write("\n")
	
# Subsection - Version information 

# Section - hubs
out.write("Hub(s)\n")
out.write("---------------------------------------------------------\n")
out.write("\n")

# Get all hubs - iterate through, making each a subsection
# For each hub, list all daemon processes, and whether they are running
hub_conf = {}
# hub_colls = {} 
for hub in dmd.Monitors.Hub.objectValues("HubConf"):
    hub_conf[hub.id] = {}
    hub_conf[hub.id]['config'] = {}
    hub_conf[hub.id]['collectors'] = {}
    hub_conf[hub.id]['config']['name'] = hub.hostname
    out.write(hub_conf[hub.id]['config']['name'] + "\n")
    out.write("=========================================================\n")
    if not hub_conf[hub.id]['config']['name']	== 'localhost':
        try:
            cpuinfo = hub.executeCommand("cat /proc/cpuinfo", "zenoss")[1].splitlines()
            meminfo = hub.executeCommand("cat /proc/meminfo", "zenoss")[1].splitlines()
            hub_conf[hub.id]['config']['cpuinfo'] = processCpuInfo(cpuinfo)
            hub_conf[hub.id]['config']['meminfo'] = processMemInfo(meminfo)
            out.write("* CPU Information\n")
            for info in hub_conf[hub.id]['config']['cpuinfo']:
                out.write("  - " + info + "\n")
            out.write("\n\n")
            out.write("* Memory Information\n")
            for info in hub_conf[hub.id]['config']['meminfo']:
                out.write("  - " + info + "\n")
            out.write("\n")
        except Exception as ex:
            if not hub_conf[hub.id]['config'].has_key('exceptions'):
                hub_conf[hub.id]['config']['exceptions'] = ''
            hub_conf[hub.id]['config']['exceptions'] += str(ex)
            print ex
    hub_conf[hub.id]['config']['daemons'] = {}
    out.write("\n")
    out.write("* Daemons\n")
    for d in hub.getZenossDaemonStates():
        dname = d['name']
        if not hub_conf[hub.id]['config']['daemons'].has_key(dname):
            if d.has_key('pid') and d['pid']:
                dpid = d['pid']
                hub_conf[hub.id]['config']['daemons'][dname] = {}
                hub_conf[hub.id]['config']['daemons'][dname]['running'] = 'Running'
                hub_conf[hub.id]['config']['daemons'][dname]['pid'] = dpid
                out.write("  - " + dname + ":  " +  "Running with PID:  " + dpid + "\n")
            else:
                hub_conf[hub.id]['config']['daemons'][dname] = {}
                hub_conf[hub.id]['config']['daemons'][dname]['running'] = 'Not Running'
                out.write("  - " + dname + ":  " +  "Not Running" + "\n")
    out.write("\n\n")
    out.write("* Collectors (on this hub)\n")
    for coll in hub.collectors():
        cname = coll.id
        hname = coll.hostname
        if not hub_conf[hub.id]['collectors'].has_key(cname):
            hub_conf[hub.id]['collectors'][cname] = hname
            out.write("  - " + cname + " on host:  " + hname + "\n")

out.write("\n")

# Section - collectors
out.write("Collector(s)\n")
out.write("---------------------------------------------------------\n")
out.write("\n")

#  This code iterates through to get all the information, so I just need to print it
collector_stats = {}
collector_conf = {}

for coll in dmd.Monitors.Performance.objectValues("PerformanceConf"):
    collector_conf[coll.id] = {}
    collector_conf[coll.id]['config'] = {}
    collector_conf[coll.id]['stats'] = {}
    collector_conf[coll.id]['config']['name'] = coll.hostname
    out.write(collector_conf[coll.id]['config']['name'] + "\n")
    out.write("=========================================================\n")
    if not collector_conf[coll.id]['config']['name']	== 'localhost':
        try:
            cpuinfo = coll.executeCommand("cat /proc/cpuinfo", "zenoss")[1].splitlines()
            meminfo = coll.executeCommand("cat /proc/meminfo", "zenoss")[1].splitlines()
            collector_conf[coll.id]['config']['cpuinfo'] = processCpuInfo(cpuinfo)
            collector_conf[coll.id]['config']['meminfo'] = processMemInfo(meminfo)
            out.write("* CPU Information\n")
            for info in collector_conf[coll.id]['config']['cpuinfo']:
                out.write("  - " + info + "\n")
            out.write("\n\n")
            out.write("* Memory Information\n")
            for info in collector_conf[coll.id]['config']['meminfo']:
                out.write("  - " + info + "\n")
            out.write("\n")
        except Exception as ex:
            if not collector_conf[coll.id]['config'].has_key('exceptions'):
                collector_conf[coll.id]['config']['exceptions'] = ''
            collector_conf[coll.id]['config']['exceptions'] += str(ex)
            print ex
    collector_conf[coll.id]['daemons'] = {}
    out.write("\n")
    out.write("* Daemons\n")
    for d in coll.getZenossDaemonStates():
        dname = d['name']
        if not collector_conf[coll.id]['daemons'].has_key(dname):
            if d.has_key('pid') and d['pid']:
                dpid = d['pid']
                collector_conf[coll.id]['daemons'][dname] = {}
                collector_conf[coll.id]['daemons'][dname]['running'] = 'Running'
                collector_conf[coll.id]['daemons'][dname]['pid'] = dpid
                out.write("  - " + dname + ":  " +  "Running with PID:  " + dpid + "\n")
            else:
                collector_conf[coll.id]['daemons'][dname] = {}
                collector_conf[coll.id]['daemons'][dname]['running'] = 'Not Running'
                out.write("  - " + dname + ":  " +  "Not Running" + "\n")
    for d in coll.devices():
        d = d.primaryAq()
        dc = d.deviceClass().primaryAq().getPrimaryId()[10:]
        if not collector_conf[coll.id]['stats'].has_key(dc):
          collector_conf[coll.id]['stats'][dc] = {'devices': 0, 'datapoints': 0}
        comps = d.getMonitoredComponents()
        datapoints = sum([comp.getRRDDataPoints() for comp in comps], []) + d.getRRDDataPoints()
        collector_conf[coll.id]['stats'][dc]['devices'] += 1
        collector_conf[coll.id]['stats'][dc]['datapoints'] += len(datapoints)
    out.write("\n\n")
    out.write("* Datapoints\n")
    for dclass in collector_conf[coll.id]['stats']:
        out.write("  - " + dclass + ":  Devices:  "+ str(collector_conf[coll.id]['stats'][dclass]['devices']))
        out.write(":  Datapoints:  " + str(collector_conf[coll.id]['stats'][dclass]['datapoints']) + "\n")
#	out.write("    + Class:  " + 
# Temporary print statements - need to format this information better
# print >>out, collector_conf
out.write("\n\n")
out.close()

