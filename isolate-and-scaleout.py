"""
Auto isolete script
"""
import sys

target_name = str(sys.argv[1])
print "target_name: " + target_name

import azure.mgmt.resource
import azure.mgmt.compute
import azure.mgmt.network
import automationassets
from msrestazure.azure_cloud import AZURE_PUBLIC_CLOUD

def get_automation_runas_credential(runas_connection, resource_url, authority_url ):
    """ Returns credentials to authenticate against Azure resoruce manager """
    from OpenSSL import crypto
    from msrestazure import azure_active_directory
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    pks12_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pks12_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    authority_full_url = (authority_url + '/' + tenant_id)
    context = adal.AuthenticationContext(authority_full_url)
    return azure_active_directory.AdalAuthentication(
        lambda: context.acquire_token_with_client_certificate(
            resource_url,
            application_id,
            pem_pkey,
            thumbprint)
    )


# Authenticate to Azure using the Azure Automation RunAs service principal
runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
resource_url = AZURE_PUBLIC_CLOUD.endpoints.active_directory_resource_id
authority_url = AZURE_PUBLIC_CLOUD.endpoints.active_directory
resourceManager_url = AZURE_PUBLIC_CLOUD.endpoints.resource_manager
azure_credential = get_automation_runas_credential(runas_connection, resource_url, authority_url)

# Intialize the resource management client with the RunAs credential and subscription
resource_client = azure.mgmt.resource.ResourceManagementClient(
    credentials=azure_credential,
    subscription_id=str(runas_connection["SubscriptionId"]),
    api_version="2017-05-10",
    base_url=resourceManager_url)

compute_client = azure.mgmt.compute.ComputeManagementClient(
    credentials=azure_credential,
    subscription_id=str(runas_connection["SubscriptionId"]),
    api_version="2016-04-30-preview",
    base_url=resourceManager_url)

network_client = azure.mgmt.network.NetworkManagementClient(
    credentials=azure_credential,
    subscription_id=str(runas_connection["SubscriptionId"]),
    api_version="2017-03-01",
    base_url=resourceManager_url)

# Get list of resource groups and print them out
resources = resource_client.resources.list()
for resource in resources:
    if u"Microsoft.Compute/virtualMachineScaleSets" == resource.type.encode('utf-8'):
        #print "resource: "
        #print resource.serialize()
        resource_name = resource.id.encode('utf-8').split("/")[4]
        vmss_name = resource.id.encode('utf-8').split("/")[8]
        vms = compute_client.virtual_machine_scale_set_vms.list(resource_name, vmss_name)
        for vm in vms:
            computer_name = vm.serialize()['properties']['osProfile']['computerName']
            network_interfaces = vm.serialize()['properties']['networkProfile']['networkInterfaces']
            if target_name == computer_name:
                #print "vm serialize: "
                #print vm.serialize()
                
                # get private ip
                target_private_ip = ""
                vmss_nics = network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces(resource_name, vmss_name)
                niclist = [nic.serialize() for nic in vmss_nics]
                for nic in niclist:
                    #print "nic: "
                    #print nic
                    nic_instance_id = nic['properties']['virtualMachine']['id'].split("/")[-1]
                    if nic_instance_id == vm.instance_id:
                        ipconf = nic['properties']['ipConfigurations']
                        for ip in ipconf:
                            target_private_ip = ip['properties']['privateIPAddress']
                
                # get security group
                target_security_group = "" #"basicNsgds2sentinel-rg-vnet-nic01"
                vmss_nsgs = network_client.network_security_groups.list(resource_name)
                for nsg in vmss_nsgs:
                    tmp_security_group = ""
                    #print "nsg: "
                    #print nsg.serialize()
                    tmp_security_group = nsg.serialize()['id'].split("/")[-1]
                    for ni in nsg.network_interfaces:
                        #print "nsg network_interfaces: "
                        #print ni
                        if ni.id.split("/")[-3] == vm.instance_id:
                            target_security_group = tmp_security_group
                            break

                # set isolate rule
                if (target_private_ip != "" and target_security_group != ""):
                    async_security_rule = network_client.security_rules.create_or_update(
                        resource_name,
                        "basicNsgds2sentinel-rg-vnet-nic01",
                        "isolated",
                        {
                            'access':azure.mgmt.network.v2017_03_01.models.SecurityRuleAccess.deny,
                            'description':'New Test security rule',
                            'destination_address_prefix':'*',
                            'destination_port_range':'*',
                            'direction':azure.mgmt.network.v2017_03_01.models.SecurityRuleDirection.outbound,
                            'priority':100,
                            'protocol':azure.mgmt.network.v2017_03_01.models.SecurityRuleProtocol.asterisk,
                            'source_address_prefix': target_private_ip,
                            'source_port_range':'*',})
                    security_rule = async_security_rule.result()
                    print "isolated"

                    # scale out
                    vmss_obj = compute_client.virtual_machine_scale_sets.get(
                        resource_name,
                        vmss_name,
                    )

                    vmss_obj_serialized = vmss_obj.serialize()
                    vmss_obj_serialized['sku']['capacity'] += 1

                    async_capacity = compute_client.virtual_machine_scale_sets.create_or_update(
                        resource_name,
                        vmss_name,
                        {
                            'location': vmss_obj_serialized['location'],
                            'sku': vmss_obj_serialized['sku'],
                        }
                    )
                    capacity = async_capacity.result()
                    print "scale out(capacity): " + vmss_obj_serialized['sku']['capacity'] - 1 + " -> " + vmss_obj_serialized['sku']['capacity']

        

