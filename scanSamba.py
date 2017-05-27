#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Samba (CVE-2017-7494) version scan by leixyou
        http://github.com/leixyou
        
    Tested on samba 4.3.11
 
"""

from sys import argv, exit
from argparse import ArgumentParser
import os
import sys
import time
import IPy
import netaddr
import pexpect
import re
def checkVsersion(version):
    version_format=version.split('.')
    flag=False
    if version_format[0]=='3' :
        if version_format[1]>'5':
            flag=True   
        elif version_format[1]=='5':
            if version_format[2]>='0':
                flag=True
    elif version_format[0]=='4':
        if version_format[1]=='5' and version_format[2]>'10':
            flag=True
        elif version_format[1]=='6' and version_format[2]<'4':
            flag=True
        elif version_format[1]=='4' and version_format[2]>'14':
            flag=True
        elif version_format[1]<'4':
            flag=True
        else:
            flag=False
    return flag



def fileClear(name):
    with open(name,'w') as f:
        f.flush()


def getSambaVersion(target,username=None,password=None):
    """Samba exploit"""

    ## Open the connection

    print("[+]getting the version of samba!",target)
    if username is None:
        smbLogin=pexpect.spawn('smbclient', args=['-L',target])
    else:
        smbLogin=pexpect.spawn('smbclient', args=['-L',target,'-U',username])
    smbLogin.logfile_send=sys.stdout
    
    tmp=open('./tmp.txt','w+')
    smbLogin.logfile_read=tmp
    index=smbLogin.expect(['password',pexpect.EOF,pexpect.TIMEOUT])
    
    if index==0:
        #time.sleep(0.5)
        if password is not None:
            smbLogin.sendline(password)
        else:
            smbLogin.sendline('')
        ret=smbLogin.expect(['samba.*','Error',pexpect.EOF,pexpect.TIMEOUT])
        #smbLogin.expect(["Server=[.* (\d+\.\d+\.\d+).*]",pexpect.EOF,pexpect.TIMEOUT])
        #print smbLogin.match.group(1)
        tmp.close()
        with open('./tmp.txt','r') as f:
            tmpstr=f.readlines()
            for x in tmpstr:
                version=re.search('Server=\[.* (\d+\.\d+\.\d+).*\]',x)
                if version is not None:
                    version_get=version.group(1)
                    
                    if version_get is not None:
                        if checkVsersion(version_get):
                            print 'ok!!!there is a vul version of sanmba' 
                            with open('./vlus.txt','a') as f:
                                f.writelines(target)
                                f.writelines('        ')
                                f.writelines(version_get)
                                f.writelines('\n')
                                f.close()
                                break
                else:
                    continue
        return True
    
    
  


if __name__ == "__main__":
    ap = ArgumentParser(description="mass samba scan  (CVE-2017-7494)by leiyou")
    ap.add_argument("-t", "--target", required=False, help="Target's hostname")
    ap.add_argument("-u", "--username", required=False, help="Samba username (optional")
    ap.add_argument("-p", "--password", required=False, help="Samba password (optional)")
    
    ap.add_argument("-m","--mass",required=False,help="mass ip anonymous checkVsersion")
    ap.add_argument('-f',"--file",required=False,help="The ip of a file")
    args = vars(ap.parse_args())

    # TODO : Add domain name as an argument

    fileClear('./tmp.txt')
    fileClear('./vlus.txt')
    print("[*] Starting  Getting!")
    #exploit(args["target"], port, args["user"], args["password"])
    if args['file'] is not None:
        with open(args['file'],'r') as fip:
            for x in fip.readlines():
                target=x.strip('\n')
                getSambaVersion(target,args['username'],args['password'])
    elif args['mass'] is not None:
        mass_ip=[]
        
        for x in IPy.IP(args['mass']):
            mass_ip.append(str(x))
            try:
                
                getSambaVersion(str(x) ,args["username"],args["password"])
            #except IOError:
                #exit("[!] Error")
            #except KeyboardInterrupt:
                #print("\n[*] Aborting the  Getting!")
            #except Exception,ex:
                #print "network error!"   
            except:
                print 'network error'
    elif args['target'] is not None:
        getSambaVersion(args["target"], args["username"], args["password"])
    else:
        print '*************************************************************************************'
        print '*****************************************bbs.yunxige.org********author:leixyou*******'
        print '*****************************************error usage!********************************'
        print '*************************************************************************************'
        print '********************USAGE:****python scanScamba.py --file ./ip.txt*******************'
        print '*************************OR***python scanScamba.py -m 192.168.111.0/24***************'
        print '*************************OR **python scanSamba.py -t 192.168.111.136*****************'
        print '*************************************************************************************'
