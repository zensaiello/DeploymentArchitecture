#!/usr/bin/env python

# This script will capture information about the Zenoss master, hubs and collectors.  It will eventuallly output two 
#  files (only one implemented for now).  One file will be a report is reStructured Text of the environment and some
#  information about its health.  The second file will just contain hostnames and information about the boxes to allow 
#  for producing (in an automated fashion) an architecture diagram.

# Import Zenoss modules so this can run in the standard Python interpreter
# Copyright 2012, Zenoss, Inc. and Michael Shannon

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
from Products.ZenUtils.Utils import convToUnits

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
import subprocess
import os
import re


#Some constants
cpuInfoNames = ['virtualization platform', 'model name', 'cpu speed', 'sockets', 'cores', 'hyperthreadcores', 'cache size']
memInfoNames = ['MemTotal', 'SwapTotal', 'MemFree', 'SwapFree']

# Functions for later use
def silentCheck(cmd):
    p = subprocess.Popen(cmd,
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout

_LOOPBACKNAMES = set(('localhost', 'localhost.localdomain', '127.0.0.1'))

def _discoverLocalhostNames():
    names = set()
    # check the many variants of hostname
    for args in ("", "-i", "-I", "-a", "-A", "-s"):
        cmd = "hostname %s" % args
        p = subprocess.Popen(cmd,
             shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        for vals in stdout.lower().strip().split():
           names.add(vals)
    return names

_LOCALHOSTNAMES = _LOOPBACKNAMES.union(_discoverLocalhostNames())

def processCpuInfo(cpuinfo):
    cpucheck = ['processor', 'model name', 'cpu MHz', 'cache size', 'virtualization platform']
    cpulist = {}
    cpusummary = {}
    cpusummary['sockets'] = 0
    cpusummary['cores'] = 0
    cpusummary['hyperthreadcores'] = 0
    cpusummary['socketlist'] = {}
    for cpuline in cpuinfo:
        if cpuline.count(':'):
            fieldname, value = cpuline.split(':')
            fieldname = fieldname.strip()
            fieldname = fieldname.strip('\t')
            if fieldname == 'virtualization platform':
                cpusummary['virtualization platform'] = value.strip()
            if fieldname == 'cpu cores':
                cpusummary['cores'] = int(value.strip())
            if fieldname == 'siblings':
                cpusummary['hyperthreadcores'] = int(value.strip())
            if fieldname == 'physical id':
                socket = int(value.strip())
                if not cpusummary['socketlist'].has_key(socket):
                    cpusummary['socketlist'][socket] = 1

            if cpucheck.count(fieldname):
                if fieldname=='processor':
                    proc_num = int(value.strip())
                    cpulist[proc_num] = {}
                else:
                    cpulist[proc_num][fieldname] = value.strip()
                    if fieldname == 'cpu MHz':
                        temp_value = float(value.strip()) * 1000 * 1000
                        final_value = convToUnits(temp_value, 1000, 'Hz')
                        cpulist[proc_num][fieldname] = final_value
                    if fieldname == 'cache size':
                        temp_value = int(value.strip('KB')) * 1024 
                        final_value = convToUnits(temp_value)
                        cpulist[proc_num][fieldname] = final_value
    cpusummary['sockets'] = len(cpusummary['socketlist'])
    del cpusummary['socketlist']
    if cpusummary['hyperthreadcores'] == cpusummary['cores']:
        cpusummary['hyperthreadcores'] = 'No hyperthreading (note:  may not be accurate for virtual guests)'
    cpusummary['model name'] = cpulist[0]['model name']
    cpusummary['cpu speed'] = cpulist[0]['cpu MHz']
    cpusummary['cache size'] = cpulist[0]['cache size']
    if not (cpusummary['virtualization platform'].lower().count("virtual") or cpusummary['virtualization platform'].lower().count("kvm")):
        del cpusummary['virtualization platform']
    return cpusummary
	
	
def processMemInfo(meminfo):
    memcheck = ['MemTotal', 'MemFree', 'SwapTotal', 'SwapFree']
    memlist = {}
    for memline in meminfo:
        if memline.count(':'):
            fieldname, value = memline.split(':')
            fieldname = fieldname.strip()
            fieldname = fieldname.strip('\t')
        if memcheck.count(fieldname):
            temp_value = int(value.strip('kB')) * 1024
            final_value = convToUnits(temp_value)
            memlist[fieldname] = final_value
    return memlist

def processMemcacheInfo(memcacheinfo):
    memccheck = ['limit_maxbytes', 'bytes', 'curr_connections', 'evictions']
    memclist = {}
    memcacheinfo.pop(0)
    for memcline in memcacheinfo:
        memcline.strip()
        fieldname, value = memcline.split()
        fieldname = fieldname.strip()
        fieldname = fieldname.strip('\t')
        if fieldname == 'limit_maxbytes':
            temp_value = int(value) 
            final_value = convToUnits(temp_value)
            memclist['Maximum Size'] = final_value
        if fieldname == 'bytes':
            temp_value = int(value) 
            final_value = convToUnits(temp_value)
            memclist['Current Size'] = final_value
        if fieldname == 'curr_connections':
            final_value = int(value) 
            memclist['Current Connections'] = final_value
        if fieldname == 'evictions':
            final_value = int(value) 
            memclist['Evictions'] = final_value
#    if memclist.has_key('Maximum Size') and memclist.has_key('Current Size'):
#        memclist['Utilization'] = memclist['Current Size'] / memclist['Maximum Size'] * 100
    return memclist


def executeDbSql(dbobj, sql):
    cmd = None
    env = os.environ.copy()
    if dbobj.dbtype == 'mysql':
        env['MYSQL_PWD'] = dbobj.dbparams.get('password')
        cmd = ['mysql', 
            '--batch', 
            '--skip-column-names', 
            '--user=%s' % dbobj.dbparams.get('user'), 
            '--host=%s' % dbobj.dbparams.get('host'), 
            '--port=%s' % str(dbobj.dbparams.get('port')), 
            '--database=%s' % dbobj.dbparams.get('db')] 
    elif dbobj.dbtype == 'postgresql': 
        env['PGPASSWORD'] = dbobj.dbparams.get('password') 
        cmd = ['psql', 
            '--quiet', 
            '--tuples-only', 
            '--username=%s' % dbobj.dbparams.get('user'), 
            '--host=%s' % dbobj.dbparams.get('host'), 
            '--port=%s' % dbobj.dbparams.get('port'), 
            dbobj.dbparams.get('db')] 
    if cmd: 
        p = subprocess.Popen(cmd, env=env, 
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
        try: 
            if sql: 
                stdout, stderr = p.communicate(sql) 
            rc = p.wait() 
            if rc: 
                raise subprocess.CalledProcessError(rc, cmd)
            else:
                return(stdout, stderr)			
        except KeyboardInterrupt: 
            subprocess.call('stty sane', shell=True) 
            p.kill() 

# Produce output in reStructured Text

# Get title from arguments, print at top of page
out.write("===================================================================================\n")
out.write(title_text + "\n")
out.write("===================================================================================\n")
out.write("\n")

# Print Customer Name, current date/time as subtitle
out.write(cust_name + "\n")
out.write("-----------------------------------------------------------------------------------\n")
out.write("\n")


# Section title - Master information
out.write("Master\n")
out.write("-----------------------------------------------------------------------------------\n")
out.write("\n")

# Subsection - Host information (cpu, memory, etc.)
out.write("Host information\n")
out.write("===================================================================================\n")
out.write("\n")

master_hostname =  list(_LOCALHOSTNAMES)
out.write("* Hostnames and IP addresses for this host\n\n")
master_hostname.sort()
for hname in master_hostname:
   out.write("  - " + hname + "\n")

# Get cpu and memory information from master - eventually need to parse this out
master_info = {}
try:
    meminfo = open('/proc/meminfo').read().splitlines()
    master_info['meminfo'] = processMemInfo(meminfo)
    out.write("\n\n")
    cpuinfo = open('/proc/cpuinfo').read().splitlines()
    cmd = "lshal | grep -i system.hardware.product | cut -d '=' -f 2 | cut -d ' ' -f 2"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if stdout.lower().find('virtual'):
        virtual_string = "virtualization platform\t:  " + stdout.replace("'","")
        cpuinfo.append(virtual_string)
    master_info['cpuinfo'] = processCpuInfo(cpuinfo)
    out.write("* CPU Information\n\n")
#    for info in master_info['cpuinfo']:
    for info in cpuInfoNames:
        if master_info['cpuinfo'].has_key(info):
            fieldname = info
            value = master_info['cpuinfo'][info]
            out.write("  - " + info.title() + ":  " + str(value) + "\n")
    out.write("\n\n")
    out.write("* Memory Information\n\n")
#    for info in master_info['meminfo']:
    for info in memInfoNames:
        if master_info['meminfo'].has_key(info):
            fieldname = info
            value = master_info['meminfo'][info]
            out.write("  - " + info + ":  " + str(value) + "\n")
except Exception as ex:
    if not master_info.has_key('exceptions'):
        master_info['exceptions'] = ''
    master_info['exceptions'] += str(ex)
    print ex

diskstats = {}
try:
    cmd = "df -hT /opt/zenoss"
#    cmd = "df -hT /dev/shm"

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    fstats = stdout.split()
    del fstats[0:8]

    fstemp = fstats[0]
    if "/" in fstemp:
        fsname = fstemp.split("/")[3]
    else:
        fsname = fstemp
    diskstats['name'] = fsname
    diskstats['type'] = fstats[1]
    diskstats['size'] = fstats[2]
    diskstats['used'] = fstats[3]
    diskstats['available'] = fstats[4]
    cmd = "iostat -xN " + fsname 

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ftemp = stdout.splitlines()
    del ftemp[0:2]
    ftemp1 = ftemp[0].split()
    num = ftemp1.index("%iowait")
    del ftemp[0]
    diskstats['iowait'] = ftemp[0].split()[num-1]
    del ftemp[0:2]
    ftemp1 = ftemp[0].split()
    num = ftemp1.index("%util")
    del ftemp[0]
    diskstats['diskutil'] = ftemp[0].split()[num]
    del ftemp[0]
    out.write("\n\n")
    out.write("* Filesystem Information - /opt/zenoss\n\n")
    for info in ['name', 'type', 'size', 'used', 'available', 'iowait', 'diskutil']:
        value = diskstats[info]
        out.write("  - " + info.title() + ":  " + str(value) + "\n")
	
	
except Exception as ex:
    print "Error getting filesystem information:  " + str(ex)
	
try:
    from Products.ZenUtils import GlobalConfig
    gc = GlobalConfig.getGlobalConfiguration()
    if 'zodb-cacheservers' in gc:
        cacheserver = gc.get('zodb-cacheservers')    
    else:
        cacheserver = gc.get('cacheservers')
    cmd = "memcached-tool " + cacheserver + " stats"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#    stdout = ''
#    stderr = ''
    stdout, stderr = p.communicate()
    memcinfo = processMemcacheInfo(stdout.splitlines())
    out.write("\n\n")
    out.write("* Memcached Information\n\n")
    for info in ['Maximum Size', 'Current Size', 'Current Connections', 'Evictions']:
        value = memcinfo[info]
        out.write("  - " + info + ":  " + str(value) + "\n")
except Exception as ex:
    print ex

out.write("\n")

# DB Information - can't get this on 4.1.1 or below, may need to try another way
try:
    from Products.ZenUtils import ZenDB
    zep_db = ZenDB.ZenDB('zep', useAdmin=True)
    db_params = zep_db.dbparams
    out.write("Database information\n")
    out.write("===================================================================================\n")
    out.write("\n")

    if master_hostname.count(db_params['host']):
        out.write(" * ZEP DB on Master\n\n")
    else:
        out.write(" * ZEP DB on " + db_params['host'] + "\n\n")
    zodb_db = ZenDB.ZenDB('zodb', useAdmin=True)
    db_params = zodb_db.dbparams
    if master_hostname.count(db_params['host']):
        out.write(" * ZODB on Master\n\n")
    else:
        out.write(" * ZODB on " + db_params['host'] + "\n\n")

except Exception as ex:
    print "Can't gather database statistics on this version"
		
try:
    dbsizes, stderr = executeDbSql(zep_db, "SELECT table_schema,round(SUM(data_length+index_length)/1024/1024,1) AS size_mb FROM information_schema.tables WHERE table_schema IN ('zodb','zodb_session','zenoss_zep') GROUP BY table_schema;")
    out.write(" * Database sizes (in MB)\n\n")
    for dbsize in dbsizes.splitlines():
        out.write("  - " + dbsize.replace('\t', ":  ") + "\n")
except Exception as ex:
#    out.write("Unable to determine database size\n")
    print ex

# Version and Zenpack Information - can't get this on 4.1.1 or below, may need to try another way, callHome data is not accessible on 4.1.1
try:
    out.write("\n\n")
    # Subsection - Version information 
    import json
    callHomeData = json.loads(dmd.callHome.metrics)
    out.write("Version information\n")
    out.write("===================================================================================\n")
    out.write("\n")
    out.write(" * Zenoss Version\n\n")
    out.write("  - " + callHomeData['Zenoss App Data']['Zenoss Version'] + "\n\n")
    out.write(" * OS Version\n\n")
    out.write("  - " + callHomeData['Host Data']['OS'] + "\n\n")
    out.write(" * RPMs\n\n")
    out.write("  - " + callHomeData['Zenoss Env Data']['RPM - zenoss'] + "\n")
    out.write("  - " + callHomeData['Zenoss Env Data']['RPM - zends'] + "\n")
    out.write("\n")



    # Subsection - Installed Zenpack information 
    out.write("Installed Zenpacks\n")
    out.write("===================================================================================\n")
    out.write("\n")

    for zenpack in callHomeData['Zenoss App Data']['Zenpack']:
        out.write(" - " + zenpack + "\n")

except Exception as ex:
    print ex
	
# Section - hubs
out.write("\n")
out.write("Hub(s)\n")
out.write("-----------------------------------------------------------------------------------\n")
out.write("\n")

# Get all hubs - iterate through, making each a subsection
# For each hub, list all daemon processes, and whether they are running
hub_conf = {}
# hub_colls = {} 
for hub in dmd.Monitors.Hub.objectValues("HubConf"):
    hub_conf[hub.id] = {}
    hub_conf[hub.id]['config'] = {}
    hub_conf[hub.id]['collectors'] = {}
    hub_conf[hub.id]['config']['hostname'] = hub.hostname
    hub_conf[hub.id]['config']['name'] = hub.id
    out.write("\n\n")
    out.write(hub_conf[hub.id]['config']['name'] + " running on host: " + hub_conf[hub.id]['config']['hostname']+ "\n")
    out.write("===================================================================================\n")
    if not master_hostname.count(hub_conf[hub.id]['config']['hostname']):
        try:
            cpuinfo = hub.executeCommand("cat /proc/cpuinfo", "zenoss")[1].splitlines()
            meminfo = hub.executeCommand("cat /proc/meminfo", "zenoss")[1].splitlines()
            virtual_string = hub.executeCommand("lshal | grep -i system.hardware.product | cut -d '=' -f 2 | cut -d ' ' -f 2", "zenoss")[1]
            virtual_string = "virtualization platform\t:  " + virtual_string.replace("'","")
            cpuinfo.append(virtual_string)
            hub_conf[hub.id]['config']['cpuinfo'] = processCpuInfo(cpuinfo)
            hub_conf[hub.id]['config']['meminfo'] = processMemInfo(meminfo)
            out.write("\n")
            out.write("* CPU Information\n\n")
            for info in cpuInfoNames: 
                if hub_conf[hub.id]['config']['cpuinfo'].has_key(info):
                    fieldname = info
                    value = hub_conf[hub.id]['config']['cpuinfo'][info]
                    out.write("  - " + info.title() + ":  " + str(value) + "\n")
            out.write("\n\n")
            out.write("* Memory Information\n\n")
            for info in hub_conf[hub.id]['config']['meminfo']:
                fieldname = info
                value = hub_conf[hub.id]['config']['meminfo'][info]
                out.write("  - " + info + ":  " + str(value) + "\n")
            out.write("\n")
        except Exception as ex:
            if not hub_conf[hub.id]['config'].has_key('exceptions'):
                hub_conf[hub.id]['config']['exceptions'] = ''
            hub_conf[hub.id]['config']['exceptions'] += str(ex)
            print ex
    hub_conf[hub.id]['config']['daemons'] = {}
    out.write("\n")
    out.write("* Daemons\n\n")
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
    out.write("* Collectors (on this hub)\n\n")
    for coll in hub.collectors():
        cname = coll.id
        hname = coll.hostname
        if not hub_conf[hub.id]['collectors'].has_key(cname):
            hub_conf[hub.id]['collectors'][cname] = hname
            out.write("  - " + cname + " on host:  " + hname + "\n")

out.write("\n")

# Section - collectors
out.write("\n")
out.write("Collector(s)\n")
out.write("-----------------------------------------------------------------------------------\n")
out.write("\n")

#  This code iterates through to get all the information, so I just need to print it
collector_stats = {}
collector_conf = {}

for coll in dmd.Monitors.Performance.objectValues("PerformanceConf"):
    collector_conf[coll.id] = {}
    collector_conf[coll.id]['config'] = {}
    collector_conf[coll.id]['stats'] = {}
    collector_conf[coll.id]['config']['name'] = coll.id
    collector_conf[coll.id]['config']['hostname'] = coll.hostname
    out.write("\n\n")
    out.write(collector_conf[coll.id]['config']['name'] + " running on host:  " + collector_conf[coll.id]['config']['hostname'] + "\n")
    out.write("===================================================================================\n")
    if not master_hostname.count(collector_conf[coll.id]['config']['hostname']):
        try:
            cpuinfo = coll.executeCommand("cat /proc/cpuinfo", "zenoss")[1].splitlines()
            meminfo = coll.executeCommand("cat /proc/meminfo", "zenoss")[1].splitlines()
            virtual_string = coll.executeCommand("lshal | grep -i system.hardware.product | cut -d '=' -f 2 | cut -d ' ' -f 2", "zenoss")[1]
            virtual_string = "virtualization platform\t:  " + virtual_string.replace("'","")
            cpuinfo.append(virtual_string)
            collector_conf[coll.id]['config']['cpuinfo'] = processCpuInfo(cpuinfo)
            collector_conf[coll.id]['config']['meminfo'] = processMemInfo(meminfo)
            out.write("* CPU Information\n\n")
            for info in cpuInfoNames: 
                if collector_conf[coll.id]['config']['cpuinfo'].has_key(info):
                    fieldname = info
                    value = collector_conf[coll.id]['config']['cpuinfo'][info]
                    out.write("  - " + info.title() + ":  " + str(value) + "\n")
            out.write("\n\n")
            out.write("* Memory Information\n\n")
            for info in collector_conf[coll.id]['config']['meminfo']:
                fieldname = info
                value = collector_conf[coll.id]['config']['meminfo'][info]
                out.write("  - " + info + ":  " + str(value) + "\n")
            out.write("\n")
        except Exception as ex:
            if not collector_conf[coll.id]['config'].has_key('exceptions'):
                collector_conf[coll.id]['config']['exceptions'] = ''
            collector_conf[coll.id]['config']['exceptions'] += str(ex)
            print ex
    collector_conf[coll.id]['daemons'] = {}
    out.write("\n")
    out.write("* Daemons\n\n")
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
    out.write("* Datapoints\n\n")
    totalDevices = 0
    totalDatapoints = 0
    for dclass in collector_conf[coll.id]['stats']:
        totalDevices += collector_conf[coll.id]['stats'][dclass]['devices']
        totalDatapoints += collector_conf[coll.id]['stats'][dclass]['datapoints']
        out.write("  - " + dclass + ":  Devices:  "+ str(collector_conf[coll.id]['stats'][dclass]['devices']))
        out.write(":  Datapoints:  " + str(collector_conf[coll.id]['stats'][dclass]['datapoints']) + "\n")
    out.write("  - Total:  Devices:  "+ str(totalDevices))
    out.write(":  Datapoints:  " + str(totalDatapoints) + "\n")
    
out.write("\n\n")
out.close()

# Putting this at the end for now, should move up closer to the master later

# Just trying some stuff out here - move up to appropriate sections and write 
#  out to the file, instead of printing to the console

# for callHomeMetric in callHomeData:
#    print
#    print callHomeMetric
#    print callHomeData[callHomeMetric]

# TODO: call iostat -x and grab the util column for all remote collectors, hubs and master.