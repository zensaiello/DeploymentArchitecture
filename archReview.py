#!/usr/bin/env python

# This script captures information about the Zenoss master, hubs and collectors.  It outputs a reStructured Text
#  report of the environment and some information about its health.


# Copyright 2013, Zenoss, Inc. and Michael Shannon
print "Zenoss Architecture Review Script"

# Imports
#  Standard Python
import optparse
import gzip
import subprocess
import os
import re
import tarfile
import json
from glob import glob
#  Zenoss specific
import Globals
import sys
from Products.ZenUtils.Utils import convToUnits
from Products.ZenUtils.ZenScriptBase import ZenScriptBase
try:
    from Products.ZenUtils import GlobalConfig
except Exception as ex:
    print "Can't access global.conf in this version"
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
p.set_defaults(outfile="/tmp/ZenossArchReport")
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
# Open file to write results
out = open(outfile + ".txt", "w")
jsonout = open(outfile + ".json", "w")

# Connect to DMD
print "Trying to connect to DMD"
zenscript = ZenScriptBase(connect=True, noopts=1)
dmd = None
try:
    dmd = zenscript.dmd
    print "Connected to DMD.  Zenoss version found: %s" % dmd.version
except Exception, e:
    print "Connection to zenoss dmd failed: %s\n" % e
    sys.exit(1)

    
def _discoverLocalhostNames():
    names = set()
    # check the many variants of hostname
    for args in ("", "-i", "-I", "-a", "-A", "-s"):
        cmd = "hostname %s" % args
        p = subprocess.Popen(cmd,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
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
                if fieldname == 'processor':
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
                        final_value = convToUnits(temp_value, 1024, "B")
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
        if memline.count(':') == 1:
            fieldname, value = memline.split(':')
            fieldname = fieldname.strip()
            fieldname = fieldname.strip('\t')
            if memcheck.count(fieldname):
                temp_value = int(value.strip('kB')) * 1024
                final_value = convToUnits(temp_value, 1024, "B")
                memlist[fieldname] = final_value
    return memlist

def roundMemValue(memValue):
    memValue = str(int(round(float(memValue.strip('GB'))))) + 'GB'
    return memValue 

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
            final_value = convToUnits(temp_value, 1024, "B")
            memclist['Maximum Size'] = final_value
        if fieldname == 'bytes':
            temp_value = int(value)
            final_value = convToUnits(temp_value, 1024, "B")
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
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
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


def componentGen(dmd, comp_type):
    if comp_type == 'HubConf':
        for component in dmd.Monitors.Hub.objectValues("HubConf"):
            yield component
    elif comp_type == 'PerformanceConf':
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


def parseCpuPerfInfo(cpu_out):
    for cpu_perf_line in cpu_out:
        if cpu_perf_line.count('CPU') and not cpu_perf_line.count('CPU)'):
            cpu_temp = cpu_perf_line.split()
            if cpu_temp.count('%user'):
                cpu_user_indx = cpu_temp.index('%user') - 1
            elif cpu_temp.count('%usr'):
                cpu_user_indx = cpu_temp.index('%usr') - 1
            cpu_system_indx = cpu_temp.index('%sys') - 1
            cpu_idle_indx = cpu_temp.index('%idle') - 1
            if not (cpu_user_indx and cpu_system_indx and cpu_idle_indx):
                raise RuntimeError('Can not parse data\n' + cpu_out)
        if cpu_perf_line.count('Average:'):
            cpu_temp = cpu_perf_line.split()
            cpu_perf_info = {}
            cpu_perf_info['user'] = cpu_temp[cpu_user_indx]
            cpu_perf_info['system'] = cpu_temp[cpu_system_indx]
            cpu_perf_info['idle'] = cpu_temp[cpu_idle_indx]
    return cpu_perf_info

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

# Create data structure for master information
master_info = {}

# Get hostnames and IP addresses for master and print
_LOOPBACKNAMES = set(('localhost', 'localhost.localdomain', '127.0.0.1'))
_LOCALHOSTNAMES = _LOOPBACKNAMES.union( x.lower() for x in _discoverLocalhostNames())
master_hostname = list(_LOCALHOSTNAMES)
out.write("* Hostnames and IP addresses for this host\n\n")
master_hostname.sort()
master_info['hostnames'] = []
for hname in master_hostname:
    out.write("  * " + hname + "\n")
    master_info['hostnames'].append(hname)
out.write("\n\n")

# Get server key for master and print
out.write("* Server Key\n\n")
master_info['serverkey'] = dmd.uuid
out.write("  * " + master_info['serverkey'] + "\n")
out.write("\n\n")

# Try to get cpu information from master
out.write("* CPU Information\n\n")
try:
    cpuinfo = executeLocalCommand("cat /proc/cpuinfo")
    try:
        virtual_string = executeLocalCommand("lshal | grep -i system.hardware.product | cut -d\"'\" -f2")[0].strip(':')
    except:
        virtual_string = ""
    virtual_string = "virtualization platform\t:  " + virtual_string
    cpuinfo.append(virtual_string)
    master_info['cpuinfo'] = processCpuInfo(cpuinfo)
    for info in cpuInfoNames:
        if info in master_info['cpuinfo']:
            value = master_info['cpuinfo'][info]
            out.write("  * " + info.title() + ":  " + str(value) + "\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)

try:
    master_info['cpuinfo']['stats'] = {}
    cpu_out = executeLocalCommand("mpstat 30 1")
    master_info['cpuinfo']['stats']['average'] = parseCpuPerfInfo(cpu_out)
    out.write("  * Last 30s Performance:  User%:  " +
              master_info['cpuinfo']['stats']['average']['user'] + 
              "  System%:  " +
              master_info['cpuinfo']['stats']['average']['system'] + 
              "  Idle%:  " +
              master_info['cpuinfo']['stats']['average']['idle'] + "\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
out.write("\n\n")

# Get memory information from master
out.write("* Memory Information\n\n")
try:
    meminfo = executeLocalCommand("cat /proc/meminfo")
    master_info['meminfo'] = processMemInfo(meminfo)
    for info in memInfoNames:
        if info in master_info['meminfo']:
            value = master_info['meminfo'][info]
            out.write("  * " + info + ":  " + str(value) + "\n")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
out.write("\n\n")

# Try to get disk information for master
out.write("* Filesystem Information - /opt/zenoss\n\n")
try:
    master_info['diskstats'] = {}
    fstemp = executeLocalCommand("df -hT /opt/zenoss")
    while not fstemp[0].count('Filesystem') and not fstemp[0].count('Use%'):
        del fstemp[0]
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
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
    if master_hostname.count(db_params['host'].lower()):
        out.write("* ZEP DB on Master\n\n\n")
        master_info['database']['zep']['host'] = 'master'
    else:
        out.write("* ZEP DB on " + db_params['host'] + "\n\n\n")
        master_info['database']['zep']['host'] = db_params['host']
    zodb_db = ZenDB.ZenDB('zodb', useAdmin=False)
    db_params = zodb_db.dbparams
    if master_hostname.count(db_params['host'].lower()):
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
        out.write("  * " + dbname + ":  " + convToUnits(dbsizeval, 1000, "B") + "\n")
        master_info['database']['sizes'][dbname] = convToUnits(dbsizeval, 1000, "B")
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
out.write("\n\n")

out.write("Zenoss configuration information\n")
out.write("=============================================================================================================================================================\n")
out.write("\n")
master_info['configuration'] = {}

# Try to get the number of zopes configured on the master 
#  (We don't have any good way to detect off-box zopes)
out.write("* Configured Zope Instances\n")
out.write("\n")
try:
    zopecount = 0
    for filename in glob('/opt/zenoss/etc/zope/zope*.conf'):
        zopecount += 1
    out.write("  * " + str(zopecount) + " Zope instances\n")
    master_info['configuration']['zopeinstances'] = zopecount
except Exception as ex:
    out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
    hub_info[comp.id]['config']['name'] = comp.id
    hub_info[comp.id]['config']['hostname'] = comp.hostname
    out.write("\n\n")
    out.write(hub_info[comp.id]['config']['name'] + " running on host: " + hub_info[comp.id]['config']['hostname'] + "\n")
    out.write("=============================================================================================================================================================\n")
    # If hub is not running on the master, try to get physical and os stats
    if not master_hostname.count(hub_info[comp.id]['config']['hostname'].lower()):
#    if master_hostname.count(hub_info[comp.id]['config']['hostname'].lower()):
        # Try to get cpu information from hub
        out.write("* CPU Information\n\n")
        try:
            cpuinfo = executeRemoteCommand("cat /proc/cpuinfo", comp)
            try:
                virtual_string = executeRemoteCommand("lshal | grep -i system.hardware.product | cut -d\"'\" -f2", comp)[0].strip(':')
            except:
                virtual_string = ""
            virtual_string = "virtualization platform\t:  " + virtual_string
            cpuinfo.append(virtual_string)
            hub_info[comp.id]['cpuinfo'] = processCpuInfo(cpuinfo)
            for info in cpuInfoNames:
                if info in hub_info[comp.id]['cpuinfo']:
                    value = hub_info[comp.id]['cpuinfo'][info]
                    out.write("  * " + info.title() + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
        try:
            hub_info[comp.id]['cpuinfo']['stats'] = {}
            cpu_out = executeRemoteCommand("mpstat 30 1", comp)
            hub_info[comp.id]['cpuinfo']['stats']['average'] = parseCpuPerfInfo(cpu_out)
            out.write("  * Last 30s Performance:  User%:  " +
                      hub_info[comp.id]['cpuinfo']['stats']['average']['user'] + 
                      "  System%:  " +
                      hub_info[comp.id]['cpuinfo']['stats']['average']['system'] + 
                      "  Idle%:  " +
                      hub_info[comp.id]['cpuinfo']['stats']['average']['idle'] + "\n")
        except Exception as ex:
            print ex.message
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
        out.write("\n\n")

        # Get memory information from hub
        out.write("* Memory Information\n\n")
        try:
            meminfo = executeRemoteCommand("cat /proc/meminfo", comp)
            hub_info[comp.id]['meminfo'] = processMemInfo(meminfo)
            for info in memInfoNames:
                if info in hub_info[comp.id]['meminfo']:
                    value = hub_info[comp.id]['meminfo'][info]
                    out.write("  * " + info + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
        out.write("\n\n")

        # Try to get disk information for hub
        out.write("* Filesystem Information - /opt/zenoss\n\n")
        try:
            hub_info[comp.id]['diskstats'] = {}
            fstemp = executeRemoteCommand("df -hT /opt/zenoss", comp)
            while not fstemp[0].count('Filesystem') and not fstemp[0].count('Use%'):
                del fstemp[0]
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
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
                out.write("  * " + dname + ":  " + "Running with PID:  " + dpid + "\n")
            else:
                hub_info[comp.id]['config']['daemons'][dname] = {}
                hub_info[comp.id]['config']['daemons'][dname]['running'] = 'Not Running'
                out.write("  * " + dname + ":  " + "Not Running" + "\n")
    out.write("\n\n")
    # Try to get the number of hub workers and invalidation workers per hub
    out.write("* Hub Worker Configuration\n")
    out.write("\n")
    try:
        if comp.id == 'localhost':
            filename = '/opt/zenoss/etc/zenhub.conf'
        else:
            filename = '/opt/zenoss/etc/' + comp.id + '_zenhub.conf'
            if not os.path.exists(filename):
                filename = '/opt/zenoss/etc/zenhub.conf'
        zenconfig = GlobalConfig.ConfigLoader(filename)
        zenconfig.load()
        if zenconfig._config.has_key('workers'):
            workers = int(zenconfig._config.get('workers'))
        else:
            workers = 2
        if zenconfig._config.has_key('invalidationworkers'):
            iworkers = int(zenconfig._config.get('invalidationworkers'))
        else:
            iworkers = 1
        out.write("  * " + str(workers) + " Zenhub workers\n")
        out.write("  * " + str(iworkers) + " Zenhub invalidation workers\n")
        # hub_info[comp.id]['config'] = {}
        hub_info[comp.id]['config']['zenhubworkers'] = workers
        hub_info[comp.id]['config']['zenhubiworkers'] = iworkers
    except Exception as ex:
        out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
    out.write("\n\n")
    
    if hub_info[comp.id]['config']['daemons'].has_key('zeneventd'):
        out.write("* ZenEventd Worker Configuration\n")
        out.write("\n")
        try:
            if comp.id == 'localhost':
                filename = '/opt/zenoss/etc/zeneventd.conf'
            else:
                filename = '/opt/zenoss/etc/' + comp.id + '_zeneventd.conf'
                if not os.path.exists(filename):
                    filename = '/opt/zenoss/etc/zeneventd.conf'
            zenconfig = GlobalConfig.ConfigLoader(filename)
            zenconfig.load()
            if zenconfig._config.has_key('workers'):
                workers = int(zenconfig._config.get('workers'))
            else:
                workers = 2
            out.write("  * " + str(workers) + " ZenEventd workers\n")
            hub_info[comp.id]['config']['zeneventdworkers'] = workers
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)

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
    out.write(coll_info[comp.id]['config']['name'] + " running on host: " + coll_info[comp.id]['config']['hostname'] + "\n")
    out.write("=============================================================================================================================================================\n")
    out.write("\n")
    # If collector is not running on the master, try to get physical and os stats
    if not master_hostname.count(coll_info[comp.id]['config']['hostname'].lower()):
#    if master_hostname.count(coll_info[comp.id]['config']['hostname'].lower()):
        # Try to get cpu information from collector
        out.write("* CPU Information\n\n")
        try:
            cpuinfo = executeRemoteCommand("cat /proc/cpuinfo", comp)
            try:
                virtual_string = executeRemoteCommand("lshal | grep -i system.hardware.product | cut -d\"'\" -f2", comp)[0].strip(':')
            except:
                virtual_string = ""
            virtual_string = "virtualization platform\t:  " + virtual_string
            cpuinfo.append(virtual_string)
            coll_info[comp.id]['cpuinfo'] = processCpuInfo(cpuinfo)
            for info in cpuInfoNames:
                if info in coll_info[comp.id]['cpuinfo']:
                    value = coll_info[comp.id]['cpuinfo'][info]
                    out.write("  * " + info.title() + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
        try:
            coll_info[comp.id]['cpuinfo']['stats'] = {}
            cpu_out = executeRemoteCommand("mpstat 30 1", comp)
            coll_info[comp.id]['cpuinfo']['stats']['average'] = parseCpuPerfInfo(cpu_out)
            out.write("  * Last 30s Performance:  User%:  " +
                      coll_info[comp.id]['cpuinfo']['stats']['average']['user'] + 
                      "  System%:  " +
                      coll_info[comp.id]['cpuinfo']['stats']['average']['system'] + 
                      "  Idle%:  " +
                      coll_info[comp.id]['cpuinfo']['stats']['average']['idle'] + "\n")
        except Exception as ex:
            print ex.message
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
        out.write("\n\n")

        # Get memory information from collector
        out.write("* Memory Information\n\n")
        try:
            meminfo = executeRemoteCommand("cat /proc/meminfo", comp)
            coll_info[comp.id]['meminfo'] = processMemInfo(meminfo)
            for info in memInfoNames:
                if info in coll_info[comp.id]['meminfo']:
                    value = coll_info[comp.id]['meminfo'][info]
                    out.write("  * " + info + ":  " + str(value) + "\n")
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
        out.write("\n\n")

        # Try to get disk information for collector
        out.write("* Filesystem Information - /opt/zenoss\n\n")
        try:
            coll_info[comp.id]['diskstats'] = {}
            fstemp = executeRemoteCommand("df -hT /opt/zenoss/perf", comp)
            while not fstemp[0].count('Filesystem') and not fstemp[0].count('Use%'):
                del fstemp[0]
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
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)
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
                out.write("  * " + dname + ":  " + "Running with PID:  " + dpid + "\n")
            else:
                coll_info[comp.id]['config']['daemons'][dname] = {}
                coll_info[comp.id]['config']['daemons'][dname]['running'] = 'Not Running'
                out.write("  * " + dname + ":  " + "Not Running" + "\n")

    coll_info[comp.id]['stats'] = {}
    for d in comp.devices():
        d = d.primaryAq()
        try:
            dc = d.deviceClass().primaryAq().getPrimaryId()[10:]
        except AttributeError:
            fixscript = 'for dev in dmd.Devices.getSubDevices():\n   if dev.deviceClass() == None:\n      devclass = dev.getPrimaryParent().getPrimaryParent()\n      print "Re-Linking %s to %s" % (dev.id, devclass)\n      dev.deviceClass._add(devclass)\n      commit()'
            print 'There are broken relationships. Please run the following script in zendmd to fix them and re-run the script: \n %s' % fixscript
            sys.exit()
        if not dc in coll_info[comp.id]['stats']:
            coll_info[comp.id]['stats'][dc] = {'devices': 0, 'datapoints': 0}
        components = d.getMonitoredComponents()
        try: 
            datapoints = sum([component.getRRDDataPoints() for component in components], []) + d.getRRDDataPoints()
        except Exception as ex:
            d.getRRDDataPoints()
        coll_info[comp.id]['stats'][dc]['devices'] += 1
        coll_info[comp.id]['stats'][dc]['datapoints'] += len(datapoints)
    out.write("\n\n")
    out.write("* Datapoints\n\n")
    totalDevices = 0
    totalDatapoints = 0
    for dclass in coll_info[comp.id]['stats']:
        totalDevices += coll_info[comp.id]['stats'][dclass]['devices']
        totalDatapoints += coll_info[comp.id]['stats'][dclass]['datapoints']
        out.write("  * " + dclass + ":  Devices:  " + str(coll_info[comp.id]['stats'][dclass]['devices']))
        out.write(":  Datapoints:  " + str(coll_info[comp.id]['stats'][dclass]['datapoints']) + "\n")
    out.write("  * Total:  Devices:  " + str(totalDevices))
    out.write(":  Datapoints:  " + str(totalDatapoints) + "\n")
    coll_info[comp.id]['stats']['total'] = {'devices': 0, 'datapoints': 0}
    coll_info[comp.id]['stats']['total']['devices'] = totalDevices
    coll_info[comp.id]['stats']['total']['datapoints'] = totalDatapoints
    out.write("\n\n")
    
    if coll_info[comp.id]['config']['daemons'].has_key('zeneventd') or coll_info[comp.id]['config']['daemons'].has_key(comp.id + '_zeneventd'):
        out.write("* ZenEventd Worker Configuration\n")
        out.write("\n")
        try:
            if comp.id == 'localhost':
                filename = '/opt/zenoss/etc/zeneventd.conf'
            else:
                filename = '/opt/zenoss/etc/' + comp.id + '_zeneventd.conf'
                if not os.path.exists(filename):
                    filename = '/opt/zenoss/etc/zeneventd.conf'
            zenconfig = GlobalConfig.ConfigLoader(filename)
            zenconfig.load()
            if zenconfig._config.has_key('workers'):
                workers = int(zenconfig._config.get('workers'))
            else:
                workers = 2
            out.write("  * " + str(workers) + " ZenEventd workers\n")
            coll_info[comp.id]['config']['zeneventdworkers'] = workers
        except Exception as ex:
            out.write("    Unable to retrieve information for this section: %s\n" % ex.message)

out.write("\n\n")
out.write("Totals across all collectors\n")
out.write("=============================================================================================================================================================\n")
out.write("\n")
totalDevices = 0
totalDatapoints = 0
for comp in coll_info:
    totalDevices += coll_info[comp]['stats']['total']['devices']
    totalDatapoints += coll_info[comp]['stats']['total']['datapoints']
out.write("* Total:  Devices:  " + str(totalDevices))
out.write(":  Datapoints:  " + str(totalDatapoints) + "\n")
coll_info['totals'] = {}
coll_info['totals']['stats'] = {}
coll_info['totals']['stats']['total'] = {'devices': 0, 'datapoints': 0}
coll_info['totals']['stats']['total']['devices'] = totalDevices
coll_info['totals']['stats']['total']['datapoints'] = totalDatapoints
    
# Write collector information to json file
jsonout.write(json.dumps(coll_info))
jsonout.write("\n\n")

# Create summary page
outsummary = open(outfile + ".sum.txt", "w")
# Get title from arguments, print at top of page
outsummary.write("=============================================================================================================================================================\n")
outsummary.write(title_text.title() + "\n")
outsummary.write("=============================================================================================================================================================\n")
outsummary.write("\n")

# Print Customer Name, current date/time as subtitle
outsummary.write(cust_name + "\n")
outsummary.write("-----------------------------------------------------------------------------------\n")
outsummary.write("\n")


# Section title - Summary information
outsummary.write("Summary Information\n")
outsummary.write("-----------------------------------------------------------------------------------\n")
outsummary.write("\n")

outsummary.write("* Master\n\n")
outsummary.write("  * Master running on " + list(_discoverLocalhostNames())[0] + "\n\n")
if master_info['versions'].has_key('zenoss_version'):
    outsummary.write("   * " + str(master_info['versions']['zenoss_version']) + "\n")
if master_info['cpuinfo'].has_key('hyperthreadcores') and str(master_info['cpuinfo']['hyperthreadcores']).isdigit() > 0:
    outsummary.write("   * " + str(master_info['cpuinfo']['hyperthreadcores']) + " core(s)\n")
elif master_info['cpuinfo'].has_key('sockets'):
    outsummary.write("   * " + str(master_info['cpuinfo']['sockets'] * master_info['cpuinfo']['cores']) + " core(s)\n")
else:
    outsummary.write("   * " + str(master_info['cpuinfo']['cores']) + " core(s)\n")
outsummary.write("   * " + str(roundMemValue(master_info['meminfo']['MemTotal'])) + " memory\n")
outsummary.write("   * " + str(master_info['configuration']['zopeinstances']) + " Zope instances\n")
zevtdworkers = 0
for hub in hub_info:
    if hub_info[hub]['config'].has_key('zeneventdworkers'):
        zevtdworkers += hub_info[hub]['config']['zeneventdworkers']
for coll in coll_info:
    if coll != 'totals' and coll_info[coll]['config'].has_key('zeneventdworkers'):
        print coll, coll_info[coll]['config']['zeneventdworkers']
        zevtdworkers += coll_info[coll]['config']['zeneventdworkers']
outsummary.write("   * " + str(zevtdworkers) + " total ZenEventd workers\n")
outsummary.write("   * " + str(coll_info['totals']['stats']['total']['devices']) + " total devices\n")
outsummary.write("   * " + str(coll_info['totals']['stats']['total']['datapoints']) + " total datapoints\n")
outsummary.write("\n\n")

outsummary.write("* Hubs\n\n")
for hub in hub_info:
    if not master_hostname.count(hub_info[hub]['config']['hostname'].lower()):
        msg = " running on " + hub_info[hub]['config']['hostname']
    else:
        msg = " running on Master"
    outsummary.write("  * " + hub_info[hub]['config']['name'] + msg + "\n\n")
    if hub_info[hub].has_key('cpuinfo'):
        if hub_info[hub]['cpuinfo'].has_key('hyperthreadcores') and str(hub_info[hub]['cpuinfo']['hyperthreadcores']).isdigit() > 0:
            outsummary.write("   * " + str(hub_info[hub]['cpuinfo']['hyperthreadcores']) + " core(s)\n")
        elif hub_info[hub]['cpuinfo'].has_key('sockets'):
            outsummary.write("   * " + str(hub_info[hub]['cpuinfo']['sockets'] * hub_info[hub]['cpuinfo']['cores']) + " core(s)\n")
        else:
            outsummary.write("   * " + str(hub_info[hub]['cpuinfo']['cores']) + " core(s)\n")
        outsummary.write("   * " + str(roundMemValue(hub_info[hub]['meminfo']['MemTotal'])) + " memory\n")
    outsummary.write("   * " + str(hub_info[hub]['config']['zenhubworkers']) + " worker(s)\n")
    outsummary.write("   * " + str(hub_info[hub]['config']['zenhubiworkers']) + " invalidation worker(s)\n")
    outsummary.write("   * " + str(len(hub_info[hub]['collectors'])) + " collector(s)\n")
    outsummary.write("\n\n")

        
outsummary.write("* Collectors\n\n")
for coll in coll_info:
    if coll != 'totals':
        if not master_hostname.count(coll_info[coll]['config']['hostname'].lower()):
            msg = " running on " + coll_info[coll]['config']['hostname']
        else:
            msg = " running on Master"
        outsummary.write("  * " + coll_info[coll]['config']['name'] + msg + "\n\n")
        if coll_info[coll].has_key('cpuinfo'):
            if coll_info[coll]['cpuinfo'].has_key('hyperthreadcores') and str(coll_info[coll]['cpuinfo']['hyperthreadcores']).isdigit() > 0:
                outsummary.write("   * " + str(coll_info[coll]['cpuinfo']['hyperthreadcores']) + " core(s)\n")
            elif coll_info[coll]['cpuinfo'].has_key('sockets'):
                outsummary.write("   * " + str(coll_info[coll]['cpuinfo']['sockets'] * coll_info[coll]['cpuinfo']['cores']) + " core(s)\n")
            else:
                outsummary.write("   * " + str(coll_info[coll]['cpuinfo']['cores']) + " core(s)\n")
            outsummary.write("   * " + str(roundMemValue(coll_info[coll]['meminfo']['MemTotal'])) + " memory\n")
        outsummary.write("   * " + str(coll_info[coll]['stats']['total']['devices']) + " total devices\n")
        outsummary.write("   * " + str(coll_info[coll]['stats']['total']['datapoints']) + " total datapoints\n")
        outsummary.write("\n\n")

        
# Finished retrieving information; combine files in archive and delete original files.
out.close()
jsonout.close()
outsummary.close()

archive = tarfile.open(outfile + ".tgz", "w|gz")
archive.add(out.name, out.name.split('/').pop(), False)
archive.add(jsonout.name, jsonout.name.split('/').pop(), False)
archive.add(outsummary.name, outsummary.name.split('/').pop(), False)
archive.close()
print 'Output saved to:\n\t' + outfile + '.tgz'
os.remove(out.name)
os.remove(jsonout.name)
os.remove(outsummary.name)
