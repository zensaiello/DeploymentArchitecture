#!/usr/bin/env python

# This script captures information about the Zenoss master, hubs and collectors.  It outputs a reStructured Text 
#  report of the environment and some information about its health.  


# Copyright 2013, Zenoss, Inc. and Michael Shannon

# Imports
#  Standard Python
import optparse
import gzip
import subprocess
import os
import re
import tarfile
import json
#  Zenoss specific
import Globals, sys
from Products.ZenUtils.Utils import convToUnits
from Products.ZenUtils.ZenScriptBase import ZenScriptBase
from Products.ZenUtils import GlobalConfig
try:
    from Products.ZenUtils import ZenDB
except Exception as ex:
    print "Can't access database in this version"


# Define some constants
#   Used to get output in desired order
cpuInfoNames = ['virtualization platform', 'model name', 'cpu speed', 'sockets', 'cores', 'hyperthreadcores', 'cache size']
memInfoNames = ['MemTotal', 'SwapTotal', 'MemFree', 'SwapFree']
memcachedNames = ['Maximum Size', 'Current Size', 'Current Connections', 'Evictions']

#  Need to accept a couple of arguments
#  File to write output to - example "/tmp/ZenossArchReport.txt"
#  Customer - example "Zenoss, Inc."
#  Title  - example "Internal IT Infrastructure"
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
outfile = opts.outfile
cust_name = opts.cust_name
title_text = opts.title_text
args = None
# Open file to write results to - should eventually figure out how to do a .tgz file, so I can add files to the archive
out = open(outfile + ".txt","w")
jsonout = open(outfile + ".json", "w")


# Connect to DMD
print "Trying to connect to DMD"
zenscript = ZenScriptBase(connect=True, noopts=1)
dmd = None
try:
    dmd = zenscript.dmd
    print "Connected to DMD"
except Exception, e:
    print "Connection to zenoss dmd failed: %s\n" % e
    sys.exit(1)

# Functions for later use

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


def processCpuInfo(cpuinfo):
    cpucheck = ['processor', 'model name', 'cpu MHz', 'cache size']
    cpulist = {}
    cpusummary = {}
    cpusummary['sockets'] = 0
    cpusummary['cores'] = 0
    cpusummary['hyperthreadcores'] = 0
    cpusummary['socketlist'] = {}
    cpusummary['corelist'] = {}
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
                if not socket in cpusummary['socketlist']:
                    cpusummary['socketlist'][socket] = 1
            if cpucheck.count(fieldname):
                if fieldname=='processor':
                    proc_num = int(value.strip())
                    cpulist[proc_num] = {}
                    cpusummary['corelist'][proc_num] = 1
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
    if cpusummary['cores'] == 0:
        cpusummary['cores'] = len(cpusummary['corelist'])
    del cpusummary['corelist']
    if cpusummary['hyperthreadcores'] == cpusummary['cores']:
        cpusummary['hyperthreadcores'] = 'No hyperthreading (note:  may not be accurate for virtual guests)'
    cpusummary['model name'] = cpulist[0]['model name']
    cpusummary['cpu speed'] = cpulist[0]['cpu MHz']
    cpusummary['cache size'] = cpulist[0]['cache size']
    if cpusummary['sockets'] == 0:
        del cpusummary['sockets']
    if cpusummary['hyperthreadcores'] == 0:
        del cpusummary['hyperthreadcores']
    if not (cpusummary['virtualization platform'].lower().count("virtual") or cpusummary['virtualization platform'].lower().count("kvm")):
        cpusummary['virtualization platform'] = 'Unable to detect'
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

def executeLocalCommand(cmd):
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        return stdout.splitlines()
    except Exception as ex:
        print ex.message

def executeRemoteCommand(cmd, remoteHost):
    try:
        stdout = remoteHost.executeCommand(cmd, "zenoss")[1].splitlines()
        return stdout
    except Exception as ex:
        print ex.message

def getDeviceClassStats(collector):
    # Need to fix - just copied over
    deviceClassStats = []
    totalDevices = 0
    totalDatapoints = 0
    for dclass in coll_info[coll.id]['stats']:
        totalDevices += coll_info[coll.id]['stats'][dclass]['devices']
        totalDatapoints += coll_info[coll.id]['stats'][dclass]['datapoints']
        # out.write("  - " + dclass + ":  Devices:  "+ str(coll_info[coll.id]['stats'][dclass]['devices']))
        # out.write(":  Datapoints:  " + str(coll_info[coll.id]['stats'][dclass]['datapoints']) + "\n")
    # out.write("  - Total:  Devices:  "+ str(totalDevices))
    # out.write(":  Datapoints:  " + str(totalDatapoints) + "\n")

def componentGen(dmd, comp_type):
    if comp_type=='HubConf':
        for component in dmd.Monitors.Hub.objectValues("HubConf"):
            yield component
    elif comp_type=='PerformanceConf':
        for component in dmd.Monitors.Performance.objectValues("PerformanceConf"):
            yield component
    else: 
        raise ValueError("Value must be one of HubConf or PerformanceConf")
   

def hubGen(dmd):
    for hub in dmd.Monitors.Hub.objectValues("HubConf"):
        yield hub

def collectorGen(dmd):
    for coll in dmd.Monitors.Hub.objectValues("HubConf"):
        yield hub


# Main part of program

# Produce output in reStructured Text

# Get title from arguments, print at top of page
out.write("=============================================================================================================================================================\n")
out.write(title_text.title() + "\n")
out.write("=============================================================================================================================================================\n")
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
out.write("=============================================================================================================================================================\n")
out.write("\n")

# Get hostnames and IP addresses for master and print
_LOOPBACKNAMES = set(('localhost', 'localhost.localdomain', '127.0.0.1'))
_LOCALHOSTNAMES = _LOOPBACKNAMES.union(_discoverLocalhostNames())
master_hostname =  list(_LOCALHOSTNAMES)
out.write("* Hostnames and IP addresses for this host\n\n")
master_hostname.sort()
for hname in master_hostname:
   out.write("  * " + hname + "\n")
out.write("\n\n")

# Try to get cpu information from master
master_info = {}
out.write("* CPU Information\n\n")
try:
    cpuinfo = executeLocalCommand("cat /proc/cpuinfo")
    try:
        virtual_string = executeLocalCommand("lshal | grep -i system.hardware.product | cut -d\"'\" -f2")[0].strip(':')
    except:
        virtual_string=""
    virtual_string = "virtualization platform\t:  " + virtual_string
    cpuinfo.append(virtual_string)
    master_info['cpuinfo'] = processCpuInfo(cpuinfo)
    for info in cpuInfoNames:
        if info in master_info['cpuinfo']:
            fieldname = info
            value = master_info['cpuinfo'][info]
            out.write("  * " + info.title() + ":  " + str(value) + "\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n\n")

# Get memory information from master
out.write("* Memory Information\n\n")
try:
    meminfo = executeLocalCommand("cat /proc/meminfo")
    master_info['meminfo'] = processMemInfo(meminfo)
    for info in memInfoNames:
        if info in master_info['meminfo']:
            fieldname = info
            value = master_info['meminfo'][info]
            out.write("  * " + info + ":  " + str(value) + "\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n\n")

# Try to get disk information for master
out.write("* Filesystem Information - /opt/zenoss\n\n")
try:
    master_info['diskstats'] = {}
    fstemp = executeLocalCommand("df -hT /opt/zenoss")
    fstatstmp = [fstemp1.split() for fstemp1 in fstemp]
    fstats = [val for subl in fstatstmp for val in subl]
    del fstats[0:8]
    fstemp = fstats[0]
    if "/" in fstemp:
        fsnametemp = fstemp.split("/")
        fsname = fsnametemp[len(fsnametemp)-1]
    else:
        fsname = fstemp
    master_info['diskstats']['name'] = fsname
    master_info['diskstats']['type'] = fstats[1]
    master_info['diskstats']['size'] = fstats[2]
    master_info['diskstats']['used'] = fstats[3]
    master_info['diskstats']['available'] = fstats[4]
    ftemp1 = executeLocalCommand("iostat -xN " + fsname)
    ftemp3 = [ftemp2.split() for ftemp2 in ftemp1]
    ftemp = [val for subl in ftemp3 for val in subl]
    num = ftemp.index('avg-cpu:') + 1
    del ftemp[0:num]
    num = ftemp.index('%iowait')
    num1 = ftemp.index('%idle') + 1
    master_info['diskstats']['iowait'] = ftemp[num+num1]
    master_info['diskstats']['diskutil'] = ftemp[len(ftemp) - 1]
    for info in ['name', 'type', 'size', 'used', 'available', 'iowait', 'diskutil']:
        value = master_info['diskstats'][info]
        out.write("  * " + info.title() + ":  " + str(value) + "\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n\n")

# Try to get memcached information
out.write("* Memcached Information\n\n")
try:
    master_info['memcached'] = {}
    gc = GlobalConfig.getGlobalConfiguration()
    if 'zodb-cacheservers' in gc:
        # In 4.2.X, config property is zodb-cacheservers
        cacheserver = gc.get('zodb-cacheservers')    
    else:
        # In 4.1.X, config property is cacheservers
        cacheserver = gc.get('cacheservers')
    cmd = "memcached-tool " + cacheserver + " stats"
    memcoutput = executeLocalCommand(cmd)
    memcinfo = processMemcacheInfo(memcoutput)
    for info in ['Maximum Size', 'Current Size', 'Current Connections', 'Evictions']:
        value = memcinfo[info]
        out.write("  * " + info + ":  " + str(value) + "\n")
        master_info['memcached'][info] = value
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n\n")

# Try to get database information (currently only works on 4.2.X)
out.write("Database information\n")
out.write("=============================================================================================================================================================\n")
out.write("\n")
try:
    master_info['database'] = {}
    master_info['database']['zep'] = {}
    master_info['database']['zodb'] = {}
    zep_db = ZenDB.ZenDB('zep', useAdmin=False)
    db_params = zep_db.dbparams
    if master_hostname.count(db_params['host']):
        out.write("* ZEP DB on Master\n\n\n")
        master_info['database']['zep']['host'] = 'master'
    else:
        out.write("* ZEP DB on " + db_params['host'] + "\n\n\n")
        master_info['database']['zep']['host'] = db_params['host']
    zodb_db = ZenDB.ZenDB('zodb', useAdmin=False)
    db_params = zodb_db.dbparams
    if master_hostname.count(db_params['host']):
        out.write("* ZODB on Master\n\n\n")
        master_info['database']['zodb']['host'] = 'master'
    else:
        out.write("* ZODB on " + db_params['host'] + "\n\n\n")
        master_info['database']['zodb']['host'] = db_params['host']
    dbsizes, stderr = executeDbSql(zep_db, "SELECT table_schema,round(SUM(data_length+index_length)/1024/1024,1) AS size_mb FROM information_schema.tables WHERE table_schema IN ('zodb','zodb_session','zenoss_zep') GROUP BY table_schema;")
    out.write("* Database sizes\n\n")
    master_info['database']['sizes'] = {}
    for dbsize in dbsizes.splitlines():
        dbname, dbsizeval = dbsize.split('\t')
        dbsizeval = int(float(dbsizeval) * 1024 * 1024)
        out.write("  * " + dbname + ":  " + convToUnits(dbsizeval) + "\n")
        master_info['database']['sizes'][dbname] = convToUnits(dbsizeval)
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n\n")

#Try to get version information (currently only works on 4.2.x)
out.write("Version information\n")
out.write("=============================================================================================================================================================\n")
out.write("\n")
try:
    master_info['versions'] = {}
    callHomeData = json.loads(dmd.callHome.metrics)
    out.write("* Zenoss Version\n\n")
    out.write("  * " + callHomeData['Zenoss App Data']['Zenoss Version'] + "\n\n\n")
    master_info['versions']['zenoss_version'] = callHomeData['Zenoss App Data']['Zenoss Version']
    out.write("* OS Version\n\n")
    out.write("  * " + callHomeData['Host Data']['OS'] + "\n\n\n")
    master_info['versions']['os_version'] = callHomeData['Host Data']['OS']
    out.write("* RPMs\n\n")
    out.write("  * " + callHomeData['Zenoss Env Data']['RPM - zenoss'] + "\n")
    out.write("  * " + callHomeData['Zenoss Env Data']['RPM - zends'] + "\n")
    master_info['versions']['zenoss_rpm'] = callHomeData['Zenoss Env Data']['RPM - zenoss']
    master_info['versions']['zends_rpm'] = callHomeData['Zenoss Env Data']['RPM - zends']
    out.write("\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n")

# Try to get the list of installed ZenPacks (currently only works on 4.2.x)
out.write("* Installed Zenpacks\n")
out.write("\n")
try:
    callHomeData = json.loads(dmd.callHome.metrics)
    master_info['zenpacks'] = []
    for zenpack in callHomeData['Zenoss App Data']['Zenpack']:
        out.write("  * " + zenpack + "\n")
        master_info['zenpacks'].append(zenpack)
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
out.write("\n\n")
# Write Master information to json file
jsonout.write(json.dumps(master_info))
jsonout.write("\n\n")


#####################################
# Section - hubs
out.write("\n")
out.write("Hub(s)\n")
out.write("-----------------------------------------------------------------------------------\n")

# Get all hubs - iterate through, making each a subsection

hub_info = {}
for comp in componentGen(dmd, "HubConf"):
    hub_info[comp.id] = {}
    hub_info[comp.id]['config'] = {}
    hub_info[comp.id]['collectors'] = {}
    hub_info[comp.id]['config']['hostname'] = comp.hostname
    hub_info[comp.id]['config']['name'] = comp.id
    out.write("\n\n")
    out.write(hub_info[comp.id]['config']['name'] + " running on host: " + hub_info[comp.id]['config']['hostname']+ "\n")
    out.write("=============================================================================================================================================================\n")
    # If hub is not running on the master, try to get physical and os stats
    if not master_hostname.count(hub_info[comp.id]['config']['hostname']):
#    if master_hostname.count(hub_info[comp.id]['config']['hostname']):
        # Try to get cpu information from hub
        out.write("* CPU Information\n\n")
        try:
            cpuinfo = executeRemoteCommand("cat /proc/cpuinfo", comp)
            try:
                virtual_string = executeRemoteCommand("lshal | grep -i system.hardware.product | cut -d\"'\" -f2", comp)[0].strip(':')
            except:
                virtual_string=""
            virtual_string = "virtualization platform\t:  " + virtual_string
            cpuinfo.append(virtual_string)
            hub_info[comp.id]['cpuinfo'] = processCpuInfo(cpuinfo)
            for info in cpuInfoNames:
                if info in hub_info[comp.id]['cpuinfo']:
                    fieldname = info
                    value = hub_info[comp.id]['cpuinfo'][info]
                    out.write("  * " + info.title() + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
        out.write("\n\n")

        # Get memory information from hub
        out.write("* Memory Information\n\n")
        try:
            meminfo = executeRemoteCommand("cat /proc/meminfo", comp)
            hub_info[comp.id]['meminfo'] = processMemInfo(meminfo)
            for info in memInfoNames:
                if info in hub_info[comp.id]['meminfo']:
                    fieldname = info
                    value = hub_info[comp.id]['meminfo'][info]
                    out.write("  * " + info + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
        out.write("\n\n")

        # Try to get disk information for hub
        out.write("* Filesystem Information - /opt/zenoss\n\n")
        try:
            hub_info[comp.id]['diskstats'] = {}
            fstemp = executeRemoteCommand("df -hT /opt/zenoss", comp)
            fstatstmp = [fstemp1.split() for fstemp1 in fstemp]
            fstats = [val for subl in fstatstmp for val in subl]
            del fstats[0:8]
            fstemp = fstats[0]
            if "/" in fstemp:
                fsnametemp = fstemp.split("/")
                fsname = fsnametemp[len(fsnametemp)-1]
            else:
                fsname = fstemp
            hub_info[comp.id]['diskstats']['name'] = fsname
            hub_info[comp.id]['diskstats']['type'] = fstats[1]
            hub_info[comp.id]['diskstats']['size'] = fstats[2]
            hub_info[comp.id]['diskstats']['used'] = fstats[3]
            hub_info[comp.id]['diskstats']['available'] = fstats[4]
            ftemp1 = executeRemoteCommand("iostat -xN " + fsname, comp)
            ftemp3 = [ftemp2.split() for ftemp2 in ftemp1]
            ftemp = [val for subl in ftemp3 for val in subl]
            num = ftemp.index('avg-cpu:') + 1
            del ftemp[0:num]
            num = ftemp.index('%iowait')
            num1 = ftemp.index('%idle') + 1
            hub_info[comp.id]['diskstats']['iowait'] = ftemp[num+num1]
            hub_info[comp.id]['diskstats']['diskutil'] = ftemp[len(ftemp) - 1]
            for info in ['name', 'type', 'size', 'used', 'available', 'iowait', 'diskutil']:
                value = hub_info[comp.id]['diskstats'][info]
                out.write("  * " + info.title() + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
        out.write("\n\n")
    # Get configured and running daemons for all hubs
    hub_info[comp.id]['config']['daemons'] = {}
    out.write("\n")
    out.write("* Daemons\n\n")
    for d in comp.getZenossDaemonStates():
        dname = d['name']
        if not dname in hub_info[comp.id]['config']['daemons']:
            if 'pid' in d and d['pid']:
                dpid = d['pid']
                hub_info[comp.id]['config']['daemons'][dname] = {}
                hub_info[comp.id]['config']['daemons'][dname]['running'] = 'Running'
                hub_info[comp.id]['config']['daemons'][dname]['pid'] = dpid
                out.write("  * " + dname + ":  " +  "Running with PID:  " + dpid + "\n")
            else:
                hub_info[comp.id]['config']['daemons'][dname] = {}
                hub_info[comp.id]['config']['daemons'][dname]['running'] = 'Not Running'
                out.write("  * " + dname + ":  " +  "Not Running" + "\n")
    out.write("\n\n")
    # Get configured collectors for all hubs
    out.write("* Collectors (on this hub)\n\n")
    for coll in comp.collectors():
        cname = coll.id
        hname = coll.hostname
        if not cname in hub_info[comp.id]['collectors']:
            hub_info[comp.id]['collectors'][cname] = hname
            out.write("  * " + cname + " on host:  " + hname + "\n")

# Write Hub information to json file
jsonout.write(json.dumps(hub_info))
jsonout.write("\n\n")


# Section - collectors
out.write("\n\n")
out.write("Collector(s)\n")
out.write("-----------------------------------------------------------------------------------\n")

# Get all collectors - iterate through, making each a subsection

coll_info = {}
for comp in componentGen(dmd, "PerformanceConf"):
    coll_info[comp.id] = {}
    coll_info[comp.id]['config'] = {}
    coll_info[comp.id]['collectors'] = {}
    coll_info[comp.id]['config']['hostname'] = comp.hostname
    coll_info[comp.id]['config']['name'] = comp.id
    out.write("\n\n")
    out.write(coll_info[comp.id]['config']['name'] + " running on host: " + coll_info[comp.id]['config']['hostname']+ "\n")
    out.write("=============================================================================================================================================================\n")
    out.write("\n")
    # If collector is not running on the master, try to get physical and os stats
    if not master_hostname.count(coll_info[comp.id]['config']['hostname']):
#    if master_hostname.count(coll_info[comp.id]['config']['hostname']):
        # Try to get cpu information from collector
        out.write("* CPU Information\n\n")
        try:
            cpuinfo = executeRemoteCommand("cat /proc/cpuinfo", comp)
            try:
                virtual_string = executeRemoteCommand("lshal | grep -i system.hardware.product | cut -d\"'\" -f2", comp)[0].strip(':')
            except:
                virtual_string=""
            virtual_string = "virtualization platform\t:  " + virtual_string
            cpuinfo.append(virtual_string)
            coll_info[comp.id]['cpuinfo'] = processCpuInfo(cpuinfo)
            for info in cpuInfoNames:
                if info in coll_info[comp.id]['cpuinfo']:
                    fieldname = info
                    value = coll_info[comp.id]['cpuinfo'][info]
                    out.write("  * " + info.title() + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
        out.write("\n\n")

        # Get memory information from collector
        out.write("* Memory Information\n\n")
        try:
            meminfo = executeRemoteCommand("cat /proc/meminfo", comp)
            coll_info[comp.id]['meminfo'] = processMemInfo(meminfo)
            for info in memInfoNames:
                if info in coll_info[comp.id]['meminfo']:
                    fieldname = info
                    value = coll_info[comp.id]['meminfo'][info]
                    out.write("  * " + info + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
        out.write("\n\n")

        # Try to get disk information for collector
        out.write("* Filesystem Information - /opt/zenoss\n\n")
        try:
            coll_info[comp.id]['diskstats'] = {}
            fstemp = executeRemoteCommand("df -hT /opt/zenoss/perf", comp)
            fstatstmp = [fstemp1.split() for fstemp1 in fstemp]
            fstats = [val for subl in fstatstmp for val in subl]
            del fstats[0:8]
            fstemp = fstats[0]
            if "/" in fstemp:
                fsnametemp = fstemp.split("/")
                fsname = fsnametemp[len(fsnametemp)-1]
            else:
                fsname = fstemp
            coll_info[comp.id]['diskstats']['name'] = fsname
            coll_info[comp.id]['diskstats']['type'] = fstats[1]
            coll_info[comp.id]['diskstats']['size'] = fstats[2]
            coll_info[comp.id]['diskstats']['used'] = fstats[3]
            coll_info[comp.id]['diskstats']['available'] = fstats[4]
            ftemp1 = executeRemoteCommand("iostat -xN " + fsname, comp)
            ftemp3 = [ftemp2.split() for ftemp2 in ftemp1]
            ftemp = [val for subl in ftemp3 for val in subl]
            num = ftemp.index('avg-cpu:') + 1
            del ftemp[0:num]
            num = ftemp.index('%iowait')
            num1 = ftemp.index('%idle') + 1
            coll_info[comp.id]['diskstats']['iowait'] = ftemp[num+num1]
            coll_info[comp.id]['diskstats']['diskutil'] = ftemp[len(ftemp) - 1]
            for info in ['name', 'type', 'size', 'used', 'available', 'iowait', 'diskutil']:
                value = coll_info[comp.id]['diskstats'][info]
                out.write("  * " + info.title() + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message )
        out.write("\n\n")
    # Get configured and running daemons for all collectors
    coll_info[comp.id]['config']['daemons'] = {}
    out.write("* Daemons\n\n")
    for d in comp.getZenossDaemonStates():
        dname = d['name']
        if not dname in coll_info[comp.id]['config']['daemons']:
            if 'pid' in d and d['pid']:
                dpid = d['pid']
                coll_info[comp.id]['config']['daemons'][dname] = {}
                coll_info[comp.id]['config']['daemons'][dname]['running'] = 'Running'
                coll_info[comp.id]['config']['daemons'][dname]['pid'] = dpid
                out.write("  * " + dname + ":  " +  "Running with PID:  " + dpid + "\n")
            else:
                coll_info[comp.id]['config']['daemons'][dname] = {}
                coll_info[comp.id]['config']['daemons'][dname]['running'] = 'Not Running'
                out.write("  * " + dname + ":  " +  "Not Running" + "\n")
 
    coll_info[comp.id]['stats'] = {}
    for d in comp.devices():
        d = d.primaryAq()
        dc = d.deviceClass().primaryAq().getPrimaryId()[10:]
        if not dc in coll_info[comp.id]['stats']:
          coll_info[comp.id]['stats'][dc] = {'devices': 0, 'datapoints': 0}
        components = d.getMonitoredComponents()
        datapoints = sum([component.getRRDDataPoints() for component in components], []) + d.getRRDDataPoints()
        coll_info[comp.id]['stats'][dc]['devices'] += 1
        coll_info[comp.id]['stats'][dc]['datapoints'] += len(datapoints)
    out.write("\n\n")
    out.write("* Datapoints\n\n")
    totalDevices = 0
    totalDatapoints = 0
    for dclass in coll_info[comp.id]['stats']:
        totalDevices += coll_info[comp.id]['stats'][dclass]['devices']
        totalDatapoints += coll_info[comp.id]['stats'][dclass]['datapoints']
        out.write("  * " + dclass + ":  Devices:  "+ str(coll_info[comp.id]['stats'][dclass]['devices']))
        out.write(":  Datapoints:  " + str(coll_info[comp.id]['stats'][dclass]['datapoints']) + "\n")
    out.write("  * Total:  Devices:  "+ str(totalDevices))
    out.write(":  Datapoints:  " + str(totalDatapoints) + "\n")



# Write collector information to json file
jsonout.write(json.dumps(coll_info))
jsonout.write("\n\n")


# Finished retrieving information; combine files in archive and delete original files.
out.close()
jsonout.close()

archive = tarfile.open(outfile + ".tgz", "w|gz")
archive.add(out.name)
archive.add(jsonout.name)
archive.close()
os.remove(out.name)
os.remove(jsonout.name)
