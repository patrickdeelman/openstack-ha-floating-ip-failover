#!/usr/bin/env python2
# Copyright (C) 2017 CloudVPS.
# Author: Remy van Elst, https://www.cloudvps.com
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

## Script to change the the floating IP using the notify-master
## keepalive state transition. Fail and Backup state transitions
## are not used. 
## This script uses command line parameters to dynamically get IP adresses
## Programmed to fit the Openstack 2 Cloud from CloudVPS

import ha-ip-failover

## commandline parameters
## keepalived $1 == "EXTERNAL_IP"
## keepalived $2 == "INTERNAL_IP"


def load_config(config_file):
  """Loads json formatted config file from specified location
  Example config:
  {
    "username": "AzureDiamond",
    "password": "hunter2",
    "tenant_id": "1234abcd...",
  }
  """
  try:
    config_data = json.loads(open(config_file).read())
    # Log everything except for password.
    syslog.debug("""Username: {0};
      Tenant ID: {1}""".format(
                              config_data["username"],
                              config_data["tenant_id"]))
    return config_data
  except Exception as e:
    syslog.error("Reading config file failed: {0}".format(e))
    errlog.error("Reading config file failed: {0}".format(e))
    sys.exit(1)


def usage():
  """ Print usage help information, since we're not fancy with argparse"""
  print("Usage: ")
  print("{0} EXTERNAL_IP INTERNAL_IP".format(sys.argv[0]))
  print("\nthis script must be called from keepalived")
  print("on keepalived notify master, attaches floating-ip to new instance")
  print("\nTo verify config:")
  print("{0} VERIFY".format(sys.argv[0]))
  sys.exit(1)

def main():
  """ Magic happens here"""
  for arg in sys.argv:
    syslog.debug(arg)
  instance_uuid = get_instance_uuid()

  # load configuration from file
  config_data = load_config(config_file)


  if(len(sys.argv) == 1):
    usage()

  if sys.argv[1] == "VERIFY":
    syslog.debug("Starting auth verify")
    verify_config(config_data, instance_uuid, keystone_url)
    sys.exit()

  # Keepalived notify-master takes any argument. This script needs just 2.
  if(len(sys.argv) != 2):
    usage()

  # get arguments into variables
  keepalived_external_ip = sys.argv[1]
  keepalived_internal_ip = sys.argv[2]


  ## Get the auth token and service catalog from keystone
  try:
    auth_request = get_auth_request(config_data["username"],
                                    config_data["password"],
                                    config_data["tenant_id"],
                                    keystone_url)
  except Exception as e:
    syslog.error("""ERROR: token creation failed: ({0})""".format(e)) 
    errlog.error("""ERROR: token creation failed: ({0})""".format(e)) 
    sys.exit(1)
  auth_token = auth_request.headers["X-Subject-Token"]
  syslog.debug(auth_token)

  ## get the compute and neutron api endpoint URL's from the catalogs
  compute_url = get_endpoint_url_from_auth_request(type="compute",
                                                   interface="public",
                                                   tenant_id=config_data["tenant_id"],
                                                   auth_request=auth_request)
  network_url = get_endpoint_url_from_auth_request(type="network",
                                                  interface="public",
                                                  tenant_id=config_data["tenant_id"],
                                                  auth_request=auth_request)

  # Get all the ports from neutron for this tenant.
  ## Neutron uses the tenant_id from the auth_token.
  ports_data = get_resource(auth_token, network_url,
                            "/v2.0/ports?fields=id&fields=device_id&fields=fixed_ips")
  instance_ports = get_network_ports_for_this_instance(instance_uuid, ports_data)

  ## get all the floating IP's for this tenant.
  floatingip_data = get_resource(auth_token, network_url, "/v2.0/floatingips")

  ## Since we only have a single IP, we don't need to loop.
  ## Just disassociate the IP and then associate them to the correct internal IP
  ## I removed the loop ;)
  internal_ip = keepalived_internal_ip
  floatingip = keepalived_external_ip
  internal_port_uuid = instance_ports[internal_ip]
  # openstack maps a floating IP as the outgoing ip for an instance
  # when a floating ip is deassigned, the outgoing ip changes to
  # the router ip. Which results in timeouts during these requests.
  # therefore we retry and are extra vigilant.
  try:
    deassign_floatingip(floatingip_uuid, network_url, auth_token) 
  except Exception as e:
    syslog.debug("Deassign floatingip {0} failed: {1}. Retrying".format(floatingip_uuid, e))
    try:
      deassign_floatingip(floatingip_uuid, network_url, auth_token) 
    except Exception as e:
      syslog.debug("Deassign floatingip {0} failed again: {1}.".format(floatingip_uuid, e))
  # do the deassign again just to be sure. When we're here in the code it means there is a
  # failover so make sure we try extra hard.
  try:
    deassign_floatingip(floatingip_uuid, network_url, auth_token) 
  except Exception as e:
    syslog.debug("Deassign floatingip {0} failed: {1}. Retrying".format(floatingip_uuid, e))
    try:
      deassign_floatingip(floatingip_uuid, network_url, auth_token) 
    except Exception as e:
      syslog.debug("Deassign floatingip {0} failed again: {1}.".format(floatingip_uuid, e))
   # same goes here, network and ip assignment changes, therefore retry. 
  try:
    assign_floatingip(floatingip_uuid, internal_port_uuid, 
                    network_url, auth_token)
  except Exception as e:
    syslog.debug("Assign floatingip {0} to port {1} failed, retrying: {2}.".format(floatingip_uuid, port_uuid, e))
    try:
      assign_floatingip(floatingip_uuid, internal_port_uuid, 
                      network_url, auth_token)
    except Exception as e:
      syslog.debug("Assign floatingip {0} to port {1} failed again: {2}.".format(floatingip_uuid, port_uuid, e))


## main
if __name__ == '__main__':
  ## Set up syslog
  syslog = logging.getLogger("syslog")
  syslog.setLevel(logging.DEBUG)
  logFormatter = logging.Formatter("[cloudvps] %(asctime)s [%(levelname)-5.5s]  %(message)s")
  ## always log a lot to syslog, so that when a failover fails (haha) we can debug why.
  fileHandler = logging.handlers.SysLogHandler(address = '/dev/log')
  fileHandler.setFormatter(logFormatter)
  syslog.addHandler(fileHandler)

  errlog = logging.getLogger("errlog")
  errlog.setLevel(logging.WARN)
  logFormatter = logging.Formatter("[cloudvps] %(asctime)s [%(levelname)-5.5s]  %(message)s")

  consoleHandler = logging.StreamHandler()
  consoleHandler.setFormatter(logFormatter)
  errlog.addHandler(consoleHandler)

  main()
