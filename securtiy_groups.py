#!/usr/bin/env python
import os
import json
from pprint import pprint
from collections import defaultdict


def get_ec2_instances():
    raw_ec2_instances = os.popen("aws ec2 describe-instances").read()
    ec2_instances = json.loads(raw_ec2_instances)
    return ec2_instances['Reservations']


def get_security_groups():
    raw_security_groups = os.popen("aws ec2 describe-security-groups").read()
    security_groups = json.loads(raw_security_groups)
    return security_groups['SecurityGroups']


def get_rds_instances():
    raw_rds_instances = os.popen("aws rds describe-db-instances").read()
    rds_instances = json.loads(raw_rds_instances)
    return rds_instances['DBInstances']


def get_load_balancers():
    raw_load_balancers = os.popen("aws elb describe-load-balancers").read()
    load_balancers = json.loads(raw_load_balancers)
    return load_balancers['LoadBalancerDescriptions']


def main():
    sg_elb = defaultdict(list)
    load_balancers = get_load_balancers()

    for elb in load_balancers:
        for gid in elb['SecurityGroups']:
            sg_elb[gid].append(elb)

    sg_rds = defaultdict(list)
    rds_instances = get_rds_instances()
    for db in rds_instances:
        for sg in db['VpcSecurityGroups']:
            gid = sg['VpcSecurityGroupId']
            sg_rds[gid].append(db)
    ec2_instances = get_ec2_instances()
    sg_ec2 = defaultdict(list)

    for r in ec2_instances:
        i = r['Instances'][0]
        for sg in i['SecurityGroups']:
            gid = sg['GroupId']
            sg_ec2[gid].append(i)
    #for sg_id, il in sg_ec2.items():
    #    print sg_id, len(il)

    security_groups = get_security_groups()
    for sg in security_groups:
        rules = {
            'inbound': [],
            'outbound': [],
            'sg': None
        }
        sg_id = sg['GroupId']
        nodes = sg_ec2[sg_id]
        rds = sg_rds[sg_id]
        elb = sg_elb[sg_id]
        #print 
        #print sg_id, len(nodes), len(rds), len(elb), sg['Description']

        #print "inbound"
        #print "--------"


        for inbound in sg['IpPermissions']:
            if 'IpProtocol' not in inbound:
                continue
            if inbound['IpRanges']:
                for cidrip in inbound['IpRanges']:
                    for n in nodes:
                        if 'PublicIpAddress' in n:
                            rules['inbound'].append(
                                "%13s:%-5s -> %13s:%s" % (
                                    cidrip['CidrIp'], inbound['FromPort'],
                                    n['PublicIpAddress'], inbound['ToPort']
                                )
                            )
                        if 'FromPort' in inbound:
                            rules['inbound'].append(
                                "%13s:%-5s -> %13s:%s" % (
                                    cidrip['CidrIp'], inbound['FromPort'],
                                    n['PrivateIpAddress'], inbound['ToPort']
                                )
                        )
                    for e in elb:
                        #if e['Scheme'] == 'internet-facing']:
                        rules['inbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                cidrip['CidrIp'], inbound['FromPort'],
                                e['LoadBalancerName'], inbound['ToPort']
                            )
                        )
            if inbound['UserIdGroupPairs']:
                u_sg_nodes = []
                for u_sg in inbound['UserIdGroupPairs']:
                    u_sg_id = u_sg['GroupId']
                    u_sg_nodes += sg_ec2[u_sg_id]

                for sg_n in u_sg_nodes:
                    for n in nodes:
                        rules['inbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                sg_n['PrivateIpAddress'], inbound['ToPort'],
                                n['PrivateIpAddress'],  inbound['FromPort'],
                            )
                        )
                    for r in rds:
                        rules['inbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                sg_n['PrivateIpAddress'], inbound['ToPort'],
                                r['DBInstanceIdentifier'], inbound['FromPort'],
                            )
                        )

        for outbound in sg['IpPermissionsEgress']:
            if 'IpProtocol' not in outbound:
                continue
            if outbound['IpProtocol'] == '-1':
                continue

            if outbound['IpRanges']:
                for cidrip in outbound['IpRanges']:
                    for n in nodes:
                        if 'PublicIpAddress' in n:
                            rules['outbound'].append(
                                "%13s:%-5s -> %13s:%s" % (
                                    n['PublicIpAddress'], outbound['ToPort'],
                                    cidrip['CidrIp'], outbound['FromPort']
                                )
                            )

                        rules['outbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                n['PrivateIpAddress'], outbound['ToPort'],
                                cidrip['CidrIp'], outbound['FromPort']
                            )
                        )
                    for e in elb:
                        #if e['Scheme'] == 'internet-facing']:
                        rules['outbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                e['LoadBalancerName'], inbound['ToPort'],
                                cidrip['CidrIp'], inbound['FromPort']
                            )
                        )

            if outbound['UserIdGroupPairs']:
                u_sg_nodes = []
                for u_sg in outbound['UserIdGroupPairs']:
                    u_sg_id = u_sg['GroupId']
                    u_sg_nodes += sg_ec2[u_sg_id]

                for sg_n in u_sg_nodes:
                    for n in nodes:
                        rules['outbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                sg_n['PrivateIpAddress'], outbound['ToPort'],
                                n['PrivateIpAddress'],  outbound['FromPort'],
                            )
                        )
                    for r in rds:
                        rules['outbound'].append(
                            "%13s:%-5s -> %13s:%s" % (
                                sg_n['PrivateIpAddress'], outbound['ToPort'],
                                r['DBInstanceIdentifier'], outbound['FromPort'],
                            )
                        )

            print
            print "Name: %s" % sg_id
            print "Desc: %s" % sg['Description']
            print "-----------------------"
            if rules['inbound']:
                print "inbound"
                print '\n'.join(rules['inbound'])
            if rules['outbound']:
                print "outbound"
                print '\n'.join(rules['outbound'])

if __name__ == '__main__':
    main()
