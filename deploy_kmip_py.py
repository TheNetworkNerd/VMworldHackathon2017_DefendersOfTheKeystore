#!/usr/bin/env python

"""Deploy up to 2 Hytrust KMIP Nodes, Put them in a cluster and then register the cluster
   (with cert-swap trust) to vCenter Server -- automagically.

Usage:
    deploy_kmip.py --psc=<fqdn> --sso_user=<user@domain.tld> --sso_pass=<password>
                --vcs=<fqdn> --clib=<name> --cluster=<name>
                --kmsname=<name> --kmsport=<port>
                --node1name=<name> --node1consolepw=<password> --node1ip=<ipaddress>
                --node1subnet=<subnetmask> --node1gw=<ipaddress> --node1dns=<ipaddress>
                --node1domain=<domain.tld> --secroot_pass=<password>
                --node2name=<name> --node2consolepw=<password> --node2ip=<ipaddress>
                --node2subnet=<subnetmask> --node2gw=<ipaddress> --node2dns=<ipaddress>
                --node2domain=<domain.tld> --node2clusterpw=<password> --wsdlurl=<fileurl>

"""

import re
import requests
import atexit
import sys
import time
import ssl
import string
import random
import json
import zipfile
import io
import docopt

from urllib.parse import urlparse
from com.vmware.cis_client import Session
from com.vmware.vapi.std_client import DynamicID
from com.vmware.vapi.std import errors_client
from vmware.vapi.lib.connect import get_requests_connector
from vmware.vapi.security.session import create_session_security_context
from vmware.vapi.security.sso import create_saml_bearer_security_context
from vmware.vapi.stdlib.client.factories import StubConfigurationFactory

from vsphere.common import sso
from vsphere.common.lookup_service_helper import LookupServiceHelper
from vsphere.common.service_manager_factory import ServiceManagerFactory
from pyVim.connect import SmartConnect

from pyVim import connect
from pyVmomi import vim, vmodl
from pyvmomi_tools.extensions import task

from com.vmware import content_client
from com.vmware.content import library_client
from com.vmware.content.library import item_client
from com.vmware.content.library_client import Item
from com.vmware.vcenter.ovf_client import LibraryItem

from vsphere.common.id_generator import generate_random_uuid
from samples.vsphere.common.vim.helpers.vim_utils import (
    get_obj, get_obj_by_moId, poweron_vm, poweroff_vm, delete_object)
from com.vmware.cis.tagging_client import (
    Category, CategoryModel, Tag, TagAssociation)
from vsphere.contentlibrary.lib.cls_api_client import ClsApiClient
from vsphere.contentlibrary.lib.cls_api_helper import ClsApiHelper

from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class DeployKMIP(object):

    class kmipSpec():
        name = None           # the name (and hostname) of the node
        consolepw = None      # the console password of the node
        secrootpw = None      # the 'secroot' user password on this node
        ip = None             # the IP address of the node
        subnet = None         # the subnet mask of the node
        gateway = None        # the gateway address of the node
        dns = None            # the DNS servers of the node
        domain = None         # the dns suffix of the node
        clusterpw = None      # the password to use when joining the cluster on secondary nodes
        port = 5696           # the port number to use in the node
        primary_node = False  # whether or not this node is the primary or a secondary

        def __init__(self, name=None, consolepw=None, secrootpw=None, ip=None,
                     subnet=None, gateway=None, dns=None, domain=None,
                     clusterpw=None, port=5676, primary=False):
            self.name = name
            self.consolepw = consolepw
            self.secrootpw = secrootpw
            self.ip = ip
            self.subnet = subnet
            self.gateway = gateway
            self.dns = dns
            self.domain = domain
            self.clusterpw = clusterpw
            self.port = port
            self.primary_node = primary

        def is_primary(self):
            return self.primary_node

    version = "0.1.0rc1"            # the version number of this application

    psc_address = None              # the fqdn or IP of the Platform Services Controller to login to
    sso_user = None                 # the username to use to login
    sso_pass = None                 # the password to use to login
    vcs = None                      # the VCS endpoint to connect to
    content_library_name = None     # the name of the content library that houses a hytrust OVF
    deploy_to_cluster = None        # the name of the cluster to deploy the KMIP nodes to
    kms_cluster_name = None         # the name to use for the Cluster in the KMIP nodes
    kms_port = 5696                 # the port number to use in the KMIP nodes
    secroot_pass = None             # the password of the secroot user
    user_wsdl_url = None            # the file:// uri path to the wsdl files in the sdk (lookupservice.wdsl, etc.)
    vcs_target = None               # the full lookup service target (computed)

    lookup_service_helper = None    # the LookupServiceHelper object instance
    service_manager = None          # an instance of the ServiceManager object
    stub_config = None              # the StubConfigurationFactory object instance
    web_svcs_host = None            # the web services host discovered from LookupService
    service_instance_stub = None    # the stub created from a ServiceInstance
    sm_client = None                # an instance of the ServiceManager Client
    sm_client_helper = None         # an instance of the ServiceManager Client Helper
    tag_category_svc = None         # an instance of the TagCategory service
    tag_svc = None                  # an instance of the Tag service
    tag_association = None
    vcs_cluster_obj = None          # an instance of the object representing a VCS Cluster
    kmip_cert_ca = None             # the Certificate Auhority certificate issued by the Hytrust Cluster
    kmip_cert_user = None           # the User certificate issued by the Hytrust Cluster

    selected_item = {}              # the information about which content library item is deployed
    kms_tag_id = None               # the ID of the kms server tag
    vm_tag_id = None                # the ID of the encrypted vm tag

    primary_node_spec = None        # an instance of the kmipSpec class to house the primary node info
    primary_node_id = None          # the ID of the primary node
    primary_node_obj = None         # an instance of the VM object representing the primary node (by moid)
    primary_node_ticket = None      # a WebKMS ticket to auth to the primary node
    primary_node_vm = None          # backup instance of the VM object representing the primary node (by uuid)

    secondary_node_spec = None      # an instance of the kmipSpec class to house the secondary node info
    secondary_node_id = None        # the ID of the secondary node
    secondary_node_obj = None       # an instance of the VM object representing the secondary node (by moid)
    secondary_node_ticket = None    # a WebKMS ticket to auth to the secondary node
    secondary_node_vm = None        # backup instance of the VM object representing the secondary node (by uuid)

    def __init__(self, **kwargs):
        try:
            # Parse arguments, use file docstring as a parameter definition
            arguments = docopt.docopt(__doc__, version=self.version)

            # Pull the arguments our into local variables.
            self.primary_node_spec = DeployKMIP.kmipSpec(name=arguments['--node1name'],
                                                         consolepw=arguments['--node1consolepw'],
                                                         secrootpw=arguments['--secroot_pass'],
                                                         ip=arguments['--node1ip'],
                                                         subnet=arguments['--node1subnet'],
                                                         gateway=arguments['--node1gw'],
                                                         dns=arguments['--node1dns'],
                                                         domain=arguments['--node1domain'],
                                                         clusterpw=None,
                                                         port=int(arguments['--kmsport']),
                                                         primary=True)

            self.secondary_node_spec = DeployKMIP.kmipSpec(name=arguments['--node2name'],
                                                           consolepw=arguments['--node2consolepw'],
                                                           secrootpw=arguments['--secroot_pass'],
                                                           ip=arguments['--node2ip'],
                                                           subnet=arguments['--node2subnet'],
                                                           gateway=arguments['--node2gw'],
                                                           dns=arguments['--node2dns'],
                                                           domain=arguments['--node2domain'],
                                                           clusterpw=arguments['--node2clusterpw'],
                                                           port=int(arguments['--kmsport']),
                                                           primary=False)

            self.psc_address = arguments['--psc']
            self.sso_user = arguments['--sso_user']
            self.sso_pass = arguments['--sso_pass']
            self.vcs = arguments['--vcs']
            self.content_library_name = arguments['--clib']
            self.deploy_to_cluster = arguments['--cluster']

            self.kms_cluster_name = arguments['--kmsname']
            self.user_wsdl_url = arguments['--wsdlurl']

            # Get the target vCenter Server (with embedded PSC)
            self.vcs_target = 'https://%s/lookupservice/sdk' % self.psc_address

        # Handle invalid options
        except docopt.DocoptExit as e:
            print(e)
            sys.exit()

    @staticmethod
    def wait_for_task(task, action_name='job', hide_result=False):
        """
        Waits and provides updates on a vSphere task
        """

        while task.info.state == vim.TaskInfo.State.running:
            time.sleep(2)

        if task.info.state == vim.TaskInfo.State.success:
            if task.info.result is not None and not hide_result:
                out = '%s completed successfully, result: %s' % (action_name, task.info.result)
                print(out)
            else:
                out = '%s completed successfully.' % action_name
                print(out)
        else:
            out = '%s did not complete successfully: %s' % (action_name, task.info.error)
            print(out)
            raise task.info.error

        return task.info.result

    def invoke_and_track(self, func, *args, **kw):
        try :
            task = func(*args, **kw)
            self.wait_for_task(task)
        except:
            raise

    def create_tag_category(self, name, description, cardinality):
        print("Creating Tag Category...")
        create_spec = self.tag_category_svc.CreateSpec()
        create_spec.name = name
        create_spec.description = description
        create_spec.cardinality = cardinality
        associable_types = set()
        create_spec.associable_types = associable_types
        return self.tag_category_svc.create(create_spec)

    def create_tag(self, name, description, category_id):
        """Creates a Tag"""
        create_spec = self.tag_svc.CreateSpec()
        create_spec.name = name
        create_spec.description = description
        create_spec.category_id = category_id
        return self.tag_svc.create(create_spec)

    def create_kms_tags(self, category_id):
        print("Creating KMS VM Tags...")
        return self.create_tag("HyTrust Key Management Server",
                               "This tag is assigned to HyTrust KMS Appliances",
                               category_id)

    def create_vm_tags(self, category_id):
        print("Creating VM Tags...")
        return self.create_tag("Encrypted VM",
                               "This tag is assigned to VMs with Encryption enabled",
                               category_id)

    def tag_vm(self, vm_id, tag_id):
        tag_attached = False
        dynamic_id = DynamicID(type='VirtualMachine', id=vm_id)
        self.tag_association.attach(tag_id=tag_id, object_id=dynamic_id)
        for tag_id in self.tag_association.list_attached_tags(dynamic_id):
            if tag_id == self.kms_tag_id:
                tag_attached = True
                break
        return tag_attached

    def encrypt_all_vms(self, vm_tag_id, si, session):
        content = self.service_instance_stub.RetrieveContent()
        for child in content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                datacenter = child
                vm_folder = datacenter.vmFolder
                vm_list = vm_folder.childEntity
                for vm in vm_list:
                    self.encrypt_vm(vm, vm_tag_id, session)

    def encrypt_vm(self, vm, tag_id, session, depth=1):
        maxdepth = 10

        # if this is a group it will have children. if it does, recurse into them
        # and then return
        if hasattr(vm, 'childEntity'):
            if depth > maxdepth:
                return
            vm_list = vm.childEntity
            for c in vm_list:
                self.encrypt_vm(c, tag_id, depth+1)
            return

        # if this is a vApp, it likely contains child VMs
        # (vApps can nest vApps, but it is hardly a common use case, so ignore that)
        if isinstance(vm, vim.VirtualApp):
            vm_list = vm.vm
            for c in vm_list:
                self.encrypt_vm(c, tag_id, depth+1)
            return

        # Don't encrypt the KMIP nodes
        summary = vm.summary
        if summary.config.name == self.primary_node_spec.name or summary.config.name == self.secondary_node_spec.name:
            return

        # Don't encrypt the vcs nodes
        if summary.guest.hostName == self.vcs:
            return

        print("Tagging VM ({0}) with 'Encrypted VM' tag...". format(summary.guest.hostName))
        self.tag_vm(vm._moId, tag_id)

        # TODO: Encrypt the VM by creating a CryptoSpec() and reconfiguring the VM

    def discover_environment(self, debug=False):
        # Connect to the lookup service to discover relevant information
        self.lookup_service_helper = LookupServiceHelper(
            wsdl_url=self.user_wsdl_url + '/lookupservice.wsdl',
            soap_url=self.vcs_target,
            skip_verification=True)
        self.lookup_service_helper.connect()

        # Print information obtained through the lookup service to the console
        if debug:
            print("SSO URL: " + str(self.lookup_service_helper.find_sso_url()))
            print("VAPI URL(s): " + str(self.lookup_service_helper.find_vapi_urls()))
            print("VIM URL: " + str(self.lookup_service_helper.find_vim_urls()))
            print("VIM PBM URL(s): " + str(self.lookup_service_helper.find_vim_pbm_urls()))
            print("MGMT Nodes: " + str(self.lookup_service_helper.find_mgmt_nodes()))
            print()
            print('Connecting to SSO Service : $s', str(self.lookup_service_helper.find_sso_url()))
            print(" - user: {}".format(self.sso_user))

        # Use the SsoAuthenticator utility class to retrieve
        # a bearer SAML token from the vCenter Single Sign-On service.
        print()
        print("Retrieving SAML Token ::")
        authenticator = sso.SsoAuthenticator(str(self.lookup_service_helper.find_sso_url()))
        saml_token = authenticator.get_bearer_saml_assertion(self.sso_user, self.sso_pass, delegatable=True)

        print(">>> SAML Token Successfully Retrieved!")

        print()
        print("Generating vSphere Authentication Session via SAML Token ::")
        # Create a session object in the client.
        session = requests.Session()

        # For development environment only, suppress server certificate checking.
        print()
        print("Suppressing Server Certificate Checking...")
        session.verify = False
        disable_warnings(InsecureRequestWarning)
        print(">>> Server Certificate Checking Suppressed!")

        # Create a connection for the session.
        print()
        print("Creating the VAPI connection object...")
        vapi_url = str(self.lookup_service_helper.find_vapi_urls()).split()[1]
        vapi_url = vapi_url[:-1]
        if debug:
            print(" --> Endpoint: " + vapi_url)
        connector = get_requests_connector(session=session, url=vapi_url)

        # Add SAML token security context to the connector.
        saml_token_context = create_saml_bearer_security_context(saml_token)
        connector.set_security_context(saml_token_context)

        # Create a stub configuration by using the SAML token security context.
        self.stub_config = StubConfigurationFactory.new_std_configuration(connector)

        # Create a Session stub with SAML token security context.
        session_stub = Session(self.stub_config)

        # Use the create operation to create an authenticated session.
        session_id = session_stub.create()
        if debug:
            print(" --> vSphere Automation Session ID: ", session_id)

        # Create a session ID security context.
        session_id_context = create_session_security_context(session_id)

        # Update the stub configuration with the session ID security context.
        self.stub_config.connector.set_security_context(session_id_context)

        print()
        print("Generating Web Services Session Info via Lookup Service...")
        vim_url = str(self.lookup_service_helper.find_vim_urls()).split()[1]
        vim_url = vim_url[:-1]
        if debug:
            print(" --> Endpoint: " + vim_url)

        # Extract the hostname from the endpoint URL.
        url_scheme, url_host, url_path, url_params, url_query, url_fragment = \
            urlparse(vim_url)
        pattern = '(?P<host>[^:/ ]+).?(?P<port>[0-9]*)'
        match = re.search(pattern, url_host)
        self.web_svcs_host = match.group('host')
        if debug:
            print(">>> Connecting to host: ", self.web_svcs_host)

    def retrieve_content_library_items(self, debug=False):
        print()
        print("Retrieving Content Libraries ::")
        print(">>> Searching for Library Name: ", self.content_library_name)

        # Create a FindSpec object to specify the search criteria.
        find_spec = content_client.Library.FindSpec()
        find_spec.name = self.content_library_name
        find_spec.type = content_client.LibraryModel.LibraryType.LOCAL

        # Invoke the find() function by using the FindSpec instance.
        library_stub = content_client.Library(self.stub_config)
        library_ids = library_stub.find(find_spec)
        libraries = library_stub.list()

        print()
        print("Listing all library identifiers:")
        for library_id in library_ids:
            library = library_stub.get(library_id)
            print(" --> Library ID {}: {}".format(library_id, library.name))

            print()
            print(
                ">>> Retrieving a list of Hytrust Library Items from Library: {} ({})".format(library.name, library_id))

            # List the items in a published library.
            item_stub = library_client.Item(self.stub_config)
            item_ids = item_stub.list(library_id)

            # List the files uploaded to each library item and print their names and sizes if they contain Hytrust.
            file_stub = item_client.File(self.stub_config)
            for item_id in item_ids:
                if not self.selected_item:
                    item = item_stub.get(item_id)
                    if 'hytrust' in item.name.lower():
                        file_infos = file_stub.list(item_id)
                        print("Library item :: \n - Name: {}\n - ID: {} has file(s):".format(item.name, item_id))
                        for file_info in file_infos:
                            print(" +-- File: {} with a size of {} byte(s)".format(file_info.name, file_info.size))

                        print()
                        deploy_this_ovf = input(" ----> Do you want to deploy this Item? [default: N] : ")
                        if (deploy_this_ovf.lower() == 'y') or (deploy_this_ovf.lower() == 'yes'):
                            self.selected_item = {"id": item_id, "name": item.name}
                            print(">>> You have selected [{}] for deployment...".format(self.selected_item["name"]))
                            break
                        else:
                            sys.exit()
                    else:
                        print(">>> No Hytrust OVF found! Exiting...")
                        sys.exit()

        return self.selected_item

    def build_tags(self, debug=False):
        print()
        print("Building the service manager for the deployment...")
        self.service_manager = ServiceManagerFactory.get_service_manager(self.web_svcs_host, self.sso_user,
                                                                         self.sso_pass, True)
        self.sm_client = ClsApiClient(self.service_manager)
        self.sm_client_helper = ClsApiHelper(self.sm_client, skip_verification=True)

        self.tag_category_svc = Category(self.service_manager.stub_config)
        self.tag_svc = Tag(self.service_manager.stub_config)
        self.tag_association = TagAssociation(self.service_manager.stub_config)

        print('Searching the existing categories user has access to...')
        categories = self.tag_category_svc.list()
        category_id = None
        if len(categories) > 0:
            for category in categories:
                cat = self.tag_category_svc.get(category)
                if cat.name == 'Encryption Tags':
                    category_id = cat.id
                    print("Tag Category already exists!")

        if not category_id:
            try:
                category_id = self.create_tag_category('Encryption Tags',
                                                       "This tag category contains tags regarding encryption automation",
                                                       CategoryModel.Cardinality.MULTIPLE)
            except errors_client.AlreadyExists as e:
                print(e)

        print(' --> Tag category Id: {0}'.format(category_id))
        print()

        tags = self.tag_svc.list()
        if len(tags) > 0:
            for tag in tags:
                tag_detail = self.tag_svc.get(tag)
                if tag_detail.name == 'Encrypted VM':
                    self.vm_tag_id = tag_detail.id
                    print(" --> Encrypted VM Tag already exists!")

                if tag_detail.name == 'HyTrust Key Management Server':
                    self.kms_tag_id = tag_detail.id
                    print(" --> KMS Server Tag already exists!")

        if not self.vm_tag_id:
            try:
                self.create_vm_tags(category_id)
            except errors_client.AlreadyExists as e:
                print(e)

        if not self.kms_tag_id:
            try:
                self.create_kms_tags(category_id)
            except errors_client.AlreadyExists as e:
                print(e)

    def deploy_kmip_node(self, spec, debug=False):
        # Check if we know about the deployment target yet
        if self.vcs_cluster_obj is None:
            # Find the cluster's resource pool moid
            print()
            print("Obtaining the cluster's resource pool moid...")
            self.vcs_cluster_obj = get_obj(self.service_manager.content,
                                  [vim.ClusterComputeResource], self.deploy_to_cluster)
            assert self.vcs_cluster_obj is not None
            if debug:
                print(" --> Cluster: {0}".format(self.vcs_cluster_obj))

        # Get a deployment target resource pool from the Cluster Object
        deployment_target = LibraryItem.DeploymentTarget(resource_pool_id=self.vcs_cluster_obj.resourcePool._GetMoId())
        if debug:
            print(" --> Resource Pool Moref: {0}".format(self.vcs_cluster_obj.resourcePool._GetMoId()))

        # Find lib item id from given item name
        find_spec = Item.FindSpec()
        find_spec.name = self.selected_item["name"]
        item_ids = self.sm_client.library_item_service.find(find_spec)
        assert (item_ids is not None and len(item_ids) > 0), ('No items found with name: {0}'
                                                              .format(self.selected_item["name"]))
        lib_item_id = item_ids[0]

        ovf_summary = self.sm_client.ovf_lib_item_service.filter(ovf_library_item_id=lib_item_id,
                                                                 target=deployment_target)
        print()
        print('Deploying OVF template: {0} to cluster: {1}...'.format(ovf_summary.name, self.deploy_to_cluster))

        # Build the deployment spec
        deployment_spec = LibraryItem.ResourcePoolDeploymentSpec(
            name=spec.name,
            annotation=ovf_summary.annotation,
            accept_all_eula=True,
            network_mappings=None,
            storage_mappings=None,
            storage_provisioning=None,
            storage_profile_id=None,
            locale=None,
            flags=None,
            additional_parameters=None,
            default_datastore_id=None)

        # Deploy the ovf template
        print("Deploying HyTrust OVF Template -- please wait...")
        print()
        result = self.sm_client.ovf_lib_item_service.deploy(lib_item_id,
                                                            deployment_target,
                                                            deployment_spec,
                                                            client_token=generate_random_uuid())

        # The type and ID of the target deployment is available in the deployment result.
        if result.succeeded:
            print('>>> Deployment successful.')
            if debug:
                print('Result resource: {0}, ID: {1}'.format(result.resource_id.type, result.resource_id.id))

            error = result.error
            #    if error is not None:
            #        for warning in error.warnings:
            #            print('OVF warning: {}'.format(warning.message))

            # Get the vm object
            if spec.is_primary():
                self.primary_node_id = result.resource_id.id
                self.primary_node_obj = get_obj_by_moId(self.service_manager.content,
                                                        [vim.VirtualMachine], self.primary_node_id)
                assert self.primary_node_obj is not None
                vm_obj = self.primary_node_obj
                vm_id = self.primary_node_id
            else:
                self.secondary_node_id = result.resource_id.id
                self.secondary_node_obj = get_obj_by_moId(self.service_manager.content,
                                                        [vim.VirtualMachine], self.secondary_node_id)
                assert self.secondary_node_obj is not None
                vm_obj = self.secondary_node_obj
                vm_id = self.secondary_node_id

            # Invoke the SmartConnect() method by supplying the host name, user name, and password.
            self.service_instance_stub = SmartConnect(host=self.web_svcs_host,
                                                      user=self.sso_user,
                                                      pwd=self.sso_pass)
            atexit.register(connect.Disconnect, self.service_instance_stub)
            content = self.service_instance_stub.RetrieveContent()
            if debug:
                print("VM UUID: {0}".format(vm_obj.summary.config.uuid))

            if spec.is_primary():
                self.primary_node_vm = content.searchIndex.FindByUuid(None, vm_obj.summary.config.uuid, True)
                vm = self.primary_node_vm
            else:
                self.secondary_node_vm = content.searchIndex.FindByUuid(None, vm_obj.summary.config.uuid, True)
                vm = self.secondary_node_vm

            print()
            print("Setting vApp Options on the VM...")
            vapp_spec_list = list()

            # Domain Name
            vapp_domainName = vim.vApp.PropertyInfo()
            vapp_domainName.key = 0
            vapp_domainName.value = spec.domain
            vapp_spec1 = vim.vApp.PropertySpec()
            vapp_spec1.info = vapp_domainName
            vapp_spec1.operation = 'edit'
            vapp_spec_list.append(vapp_spec1)

            # Netmask
            vapp_netmask = vim.vApp.PropertyInfo()
            vapp_netmask.key = 1
            vapp_netmask.value = spec.subnet
            vapp_spec2 = vim.vApp.PropertySpec()
            vapp_spec2.info = vapp_netmask
            vapp_spec2.operation = 'edit'
            vapp_spec_list.append(vapp_spec2)

            # KCMaster
            vapp_kcmaster = vim.vApp.PropertyInfo()
            vapp_kcmaster.key = 2
            if spec.is_primary():
                vapp_kcmaster.value = ''
            else:
                vapp_kcmaster.userConfigurable = True
                vapp_kcmaster.value = self.primary_node_spec.ip
            vapp_spec3 = vim.vApp.PropertySpec()
            vapp_spec3.info = vapp_kcmaster
            vapp_spec3.operation = 'edit'
            vapp_spec_list.append(vapp_spec3)

            # Console Password
            vapp_consolepw = vim.vApp.PropertyInfo()
            vapp_consolepw.key = 3
            vapp_consolepw.userConfigurable = True
            vapp_consolepw.value = spec.consolepw
            vapp_spec4 = vim.vApp.PropertySpec()
            vapp_spec4.info = vapp_consolepw
            vapp_spec4.operation = 'edit'
            vapp_spec_list.append(vapp_spec4)

            # HTKC Hostname
            vapp_htkcHostname = vim.vApp.PropertyInfo()
            vapp_htkcHostname.key = 4
            vapp_htkcHostname.value = spec.name
            vapp_spec5 = vim.vApp.PropertySpec()
            vapp_spec5.info = vapp_htkcHostname
            vapp_spec5.operation = 'edit'
            vapp_spec_list.append(vapp_spec5)

            # DNS Servers
            vapp_dns = vim.vApp.PropertyInfo()
            vapp_dns.key = 5
            vapp_dns.value = spec.dns
            vapp_spec6 = vim.vApp.PropertySpec()
            vapp_spec6.info = vapp_dns
            vapp_spec6.operation = 'edit'
            vapp_spec_list.append(vapp_spec6)

            # HTKC IP Address
            vapp_htkcIP = vim.vApp.PropertyInfo()
            vapp_htkcIP.key = 6
            vapp_htkcIP.value = spec.ip
            vapp_spec7 = vim.vApp.PropertySpec()
            vapp_spec7.info = vapp_htkcIP
            vapp_spec7.operation = 'edit'
            vapp_spec_list.append(vapp_spec7)

            # NTP Servers
            vapp_ntp = vim.vApp.PropertyInfo()
            vapp_ntp.key = 7
            vapp_ntp.value = '0.us.pool.ntp.org, 1.us.pool.ntp.org'
            vapp_spec8 = vim.vApp.PropertySpec()
            vapp_spec8.info = vapp_ntp
            vapp_spec8.operation = 'edit'
            vapp_spec_list.append(vapp_spec8)

            # Gateway
            vapp_gateway = vim.vApp.PropertyInfo()
            vapp_gateway.key = 8
            vapp_gateway.value = spec.gateway
            vapp_spec9 = vim.vApp.PropertySpec()
            vapp_spec9.info = vapp_gateway
            vapp_spec9.operation = 'edit'
            vapp_spec_list.append(vapp_spec9)

            # KC Cluster Password
            vapp_kcpw = vim.vApp.PropertyInfo()
            vapp_kcpw.key = 9
            vapp_kcpw.userConfigurable = True
            vapp_kcpw.value = spec.clusterpw
            vapp_spec10 = vim.vApp.PropertySpec()
            vapp_spec10.info = vapp_kcpw
            vapp_spec10.operation = 'edit'
            vapp_spec_list.append(vapp_spec10)

            # Make the modifications
            config_spec = vim.vm.ConfigSpec()
            config_spec.vAppConfig = vim.vApp.VmConfigSpec()
            config_spec.vAppConfig.property = vapp_spec_list
            reconfig_task = vm.ReconfigVM_Task(config_spec)
            task.wait_for_task(reconfig_task)
            print("Successfully modified VM:[{0}] properties".format(spec.name))

            # Add the KMS tag to the VM
            print()
            print('Tagging the KMS VM :: {0}...'.format(spec.name))
            kms_tag_attached = self.tag_vm(vm_id, self.kms_tag_id)
            assert kms_tag_attached
            if debug:
                print('Tagged KMS vm: {0}'.format(vm_id))

            # Power on the VM and wait for the power on operation to be completed
            print()
            print("Powering on the KMS Server: {0} ...".format(spec.name))
            poweron_vm(self.service_manager.content, vm_obj)

            while vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
                print("Waiting for VM [{0}] to power on...".format(spec.name))
                time.sleep(3)

            # Get a WebKMS ticket so we can manipulate the console if we need to
            if spec.is_primary():
                self.primary_node_ticket = vm.AcquireTicket("webmks")
                ticket = self.primary_node_ticket
            else:
                self.secondary_node_ticket = vm.AcquireTicket("webmks")
                ticket = self.secondary_node_ticket
            print("WebMKS Ticket: {0}".format(ticket))
            print("WMKS URL: wss://{0}:{1}/ticket/{2}".format(ticket.host,
                                                              ticket.port,
                                                              ticket.ticket))
        else:
            print('Deployment failed.')
            for error in result.error.errors:
                print('OVF error: {}'.format(error.message))

    def config_kmip_node(self, spec, debug=False):
        # Disable cert verification
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE

        # Login to the API (secroot account)
        print("Logging into HyTrust Node [{0}]...".format(spec.name))
        s = requests.session()
        login_body = json.dumps({u'username': u'secroot', u'password': u'secroot'})
        login_headers = {'content-type': 'application/json'}
        r = s.post("https://{0}/v4/kc/login/".format(spec.ip),
                   data=login_body,
                   headers=login_headers,
                   verify=False)
        print(r.json())
        token = r.json()['access_token']
        print("HyTrust Node [{0}] : Access Token: {1}".format(spec.name, token))

        # Change 'secroot' password
        print("Changing 'secroot' password on HyTrust Node [{0}]...".format(spec.name))
        pwchange_body = json.dumps({u'username': u'secroot', u'password': spec.secrootpw})
        pwchange_headers = {'content-type': 'application/json', u'Auth-Token': token}
        r = s.post("https://{0}/v4/login_edit/".format(spec.ip),
                   data=pwchange_body,
                   headers=pwchange_headers,
                   verify=False)
        print(r.json())

        # Changing the 'secroot' password invalidates the token. Re-login required...
        # Login to the API (secroot account)
        print("Logging into HyTrust Node [{0}]...".format(spec.name))
        s = requests.session()
        login_body = json.dumps({u'username': u'secroot', u'password': spec.secrootpw})
        login_headers = {'content-type': 'application/json'}
        r = s.post("https://{0}/v4/kc/login/".format(spec.ip),
                   data=login_body,
                   headers=login_headers,
                   verify=False)
        print(r.json())
        token = r.json()['access_token']
        print("HyTrust Node [{0}] : Access Token: {1}".format(spec.name, token))

        # Enable KMIP Server
        print("Enabling KMIP Server on HyTrust Node [{0}]...".format(spec.name))
        kmip_body = json.dumps({u'cluster': u'ENABLED',
                                u'host': spec.ip,
                                u'loglevel': u'ALL',
                                u'nbio': u'0',
                                u'port': spec.port,
                                u'protocol': u'0x1',
                                u'reconnect': u'0',
                                u'state': u'ENABLED',
                                u'timeout': u'0',
                                'verify': u'yes'})
        kmip_headers = {'content-type': 'application/json', u'Auth-Token': token}
        r = s.patch("https://{0}/v4/system_settings/kmipsrv_info/".format(spec.ip),
                    data=kmip_body,
                    headers=kmip_headers,
                    verify=False)
        print(r.json())
        print("HyTrust Node [{0}] : KMIP Server Enabled...".format(spec.name))

        # Create a new user to access vSphere (no password)
        kmip_user = 'kms' + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        create_user_body = {u'expire': u'365',
                            u'username': kmip_user}
        create_user_headers = {u'content-type': u'application/x-www-form-urlencoded', u'Auth-Token': token}
        print("Creating a new KMIP user account: {0}".format(kmip_user))
        r = s.post("https://{0}/v4/kmipsrv_user/{1}/".format(spec.ip, kmip_user),
                   data=create_user_body,
                   headers=create_user_headers,
                   verify=False)
        print("Create User Result: {0}".format(r.json()))

        # Get the user certificate
        print("Download the User and CA Certificates to Memory from Hytrust...")
        print("URL :: https://{0}/v4/kmipsrv-certs/{1}/?access_token={2}".format(spec.ip,
                                                                                 kmip_user,
                                                                                 token))
        r = s.get("https://{0}/v4/kmipsrv-certs/{1}/?access_token={2}".format(spec.ip,
                                                                              kmip_user,
                                                                              token),
                  verify=False)
        certZip = zipfile.ZipFile(io.BytesIO(r.content))
        cert_names = {name: certZip.read(name) for name in certZip.namelist()}
        self.kmip_cert_user = certZip.open('{0}.pem'.format(kmip_user)).read().decode("utf-8")
        self.kmip_cert_ca = certZip.open('cacert.pem').read().decode("utf-8")
        if debug:
            print("{0}.pem --------------\n{1}".format(kmip_user, self.kmip_cert_user))
            print('- - - -')
            print("cacert.pem --------------\n{0}".format(self.kmip_cert_ca))

        return {'token': token, 'session': s}

    def authorize_secondary_node(self, spec, session_info=None, debug=False):

        print("DEBUG :: {0}".format(session_info))
        print("DEBUG :: https://{0}/v4/domains/?access_token={1}".format(spec.ip, session_info['token']))

        # Get a list of the domains (there should only be one) so we can poll the details
        r = session_info['session'].get("https://{0}/v4/domains/?access_token={1}".
                                        format(spec.ip, session_info['token']),
                                        verify=False)
        domain_list = r.json()['domains']
        domain_id = domain_list[0]['id']
        if debug:
            print()
            print("DEBUG ::  Retrieved Domain ID: {0}".format(domain_id))

        # Poll until it's joined
        node2joined = False
        while not node2joined:
            if debug:
                print("\nDEBUG ::  Polling for node-join via: https://{0}/v4/domains/{1}/?access_token={2}".
                      format(spec.ip, domain_id, session_info['token']))

            try:
                r = session_info['session'].get("https://{0}/v4/domains/{1}/?access_token={2}".
                                                format(spec.ip, domain_id, session_info['token']),
                                                verify=False)
                server_list = r.json()['servers']
            except requests.exceptions.ConnectionError as e:
                # Connection lost, try and reconnect
                print()
                print("ERROR :: CONNECTION LOST: \n {0}".format(e))
                print("Reconnecting to HyTrust Node [{0}]...".format(spec.name))
                session_info['session'] = requests.session()
                login_body = json.dumps({u'username': u'secroot', u'password': spec.secrootpw})
                login_headers = {'content-type': 'application/json'}
                r = session_info['session'].post("https://{0}/v4/kc/login/".format(spec.ip),
                                                 data=login_body,
                                                 headers=login_headers,
                                                 verify=False)
                print(r.json())
                session_info['token'] = r.json()['access_token']
                print("HyTrust Node [{0}] : Access Token: {1}".format(spec.name, session_info['token']))
                print()

                continue

            # Check to see if our second node is in there...
            if len(server_list) > 1:
                # If it is, authenticate it
                authenticate_node_body = {u'operation': u'authenticate',
                                          u'passphrase': spec.clusterpw}
                authenticate_node_headers = {u'content-type': u'application/x-www-form-urlencoded',
                                             u'Auth-Token': session_info['token']}
                print("Authenticating Node Cluster-join: {0}".format(spec.name))
                r = session_info['session'].post("https://{0}/v4/servers/{1}/operation/".
                                                 format(spec.ip, server_list[1]['id']),
                                                 data=authenticate_node_body,
                                                 headers=authenticate_node_headers,
                                                 verify=False)
                print(">>> Node [{0}] authenticated to cluster...".format(spec.name))
                print()
                node2joined = True
            else:
                # If not, wait 2 seconds and try again...
                print("-----> Server count currently: {0}".format(len(server_list)))
                print("\n >>> Waiting for 5 seconds...")
                time.sleep(5)

    def register2vcenter(self, debug=False):

        # Disable cert verification
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE

        # VCenter ---------------------------------------------
        # Invoke the SmartConnect() method by supplying the host name, user name, and password.
        service_instance_stub = SmartConnect(host=self.web_svcs_host,
                                             user=self.sso_user,
                                             pwd=self.sso_pass,
                                             port=443,
                                             sslContext=context)
        atexit.register(connect.Disconnect, service_instance_stub)
        content = service_instance_stub.RetrieveContent()

        # Add KMS Cluster to vCenter (vSphere API - Web Services SDK)
        print("Starting to add Key Management Server: {0}".format(self.primary_node_spec.name))
        kms_server_info = vim.encryption.KmipServerInfo()
        kms_server_info.name = self.primary_node_spec.name
        kms_server_info.address = self.primary_node_spec.ip
        kms_server_info.port = self.primary_node_spec.port

        # Set KMS Cluster Name
        provider_id = vim.encryption.KeyProviderId()
        provider_id.id = self.kms_cluster_name

        kmip_spec = vim.encryption.KmipServerSpec()
        kmip_spec.info = kms_server_info
        kmip_spec.clusterId = provider_id

        print("Registering KMS Cluster to vCenter Server...")
        crypto_manager = service_instance_stub.content.cryptoManager
        crypto_manager.RegisterKmipServer(kmip_spec)

        print("Establishing trust between vCenter Server and the Key Management Server: {0}".
              format(self.primary_node_spec.name))
        if debug:
            print("DEBUG :: CA Certificate: \n{0}".format(self.kmip_cert_ca))
            print("DEBUG :: User Certificate: \n{0}".format(self.kmip_cert_user))

        crypto_manager.UploadClientCert(provider_id, self.kmip_cert_user, self.kmip_cert_user)
        crypto_manager.UploadKmipServerCert(provider_id, self.kmip_cert_ca)

        print("Marking [{0}] as default KMIP server...".format(self.primary_node_spec.name))
        crypto_manager.MarkDefault(provider_id)

        print("Verifying KMS registration...")
        # TODO: Actually verify that it has worked and nothing went wrong... (though it never has)

if __name__ == '__main__':

        # Instantiate the class
        kmip = DeployKMIP()

        # Use the Lookup Service to learn about the environment
        kmip.discover_environment(True)

        # Find the content library item to deploy
        kmip.retrieve_content_library_items(True)

        # Build the tags (in case we want to use them in the future)
        kmip.build_tags(True)

        # Deploy the primary KMIP node
        kmip.deploy_kmip_node(kmip.primary_node_spec, True)
        input("Please complete the wizard in the KMS VM console of [{0}] by answering 'No' -- then "
              "return to this window and press ENTER to continue...".format(kmip.primary_node_spec.name))

        print()
        deploy_backup_node = input("Do you wish to deploy another cluster node? [y/n] ")
        if deploy_backup_node.lower() == 'y' or deploy_backup_node.lower() == 'yes':

            # Deploy the secondary KMIP node
            kmip.deploy_kmip_node(kmip.secondary_node_spec, True)

        # Configure Hytrust on the Primary Node
        session_info = kmip.config_kmip_node(kmip.primary_node_spec, True)

        if deploy_backup_node.lower() == 'y' or deploy_backup_node.lower() == 'yes':
            print('\n\n')
            print("Please wait for the second node to boot and join the cluster...")
            kmip.authorize_secondary_node(kmip.primary_node_spec, session_info, True)

        # Register the KMIP Cluster to vCenter and Trust it
        kmip.register2vcenter(True)

        print()
        print("CONGRATULATIONS!!---------------\n"
              "You've successfully deployed up to a 2-node Hytrust KeyControl Cluster, registered that \n"
              "KMIP Cluster with vCenter and did a certificate trust key-swap. All that's left to do is to power \n"
              "down a VM, Apply the VM Encryption Storage Policy to it and start it back up!\n"
              "\n"
              "You're welcome. Buy a random geek a beer!!!\n"
              "\n"
              "- The Defenders of the Keystore\n")
