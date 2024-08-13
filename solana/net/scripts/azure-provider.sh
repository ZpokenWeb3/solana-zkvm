# |source| this file
#
# Utilities for working with Azure instances
#

# Default zone
cloud_DefaultZone() {
  echo "westus"
}

cloud_DefaultCustomMemoryGB() {
  : # Not implemented
}

cloud_RestartPreemptedInstances() {
  : # Not implemented
}

#
# __cloud_GetConfigValueFromInstanceName
# Return a piece of configuration information about an instance
# Provide the exact name of an instance and the configuration key, and the corresponding value will be returned
#
# example:
#   This will return the name of the resource group of the instance named
#   __cloud_GetConfigValueFromInstanceName some-instance-name resourceGroup

cloud_GetConfigValueFromInstanceName() {
  query="[?name=='$1']"
  key="[$2]"
  config_value=$(az vm list -d -o tsv --query "$query.$key")
}

cloud_GetResourceGroupFromInstanceName() {
  resourceGroup=$(az vm list -o tsv --query "[?name=='$1'].[resourceGroup]")
}
cloud_GetIdFromInstanceName() {
  id=$(az vm list -o tsv --query "[?name=='$1'].[id]")
}

#
# __cloud_FindInstances
#
# Find instances matching the specified pattern.
#
# For each matching instance, an entry in the `instances` array will be added with the
# following information about the instance:
#   "name:public IP:private IP:location"
#
# filter   - The instances to filter on
#
# examples:
#   $ __cloud_FindInstances prefix some-machine-prefix
#   $ __cloud_FindInstances name exact-machine-name
#
#  Examples of plain-text filter command
#
#  This will return an exact match for a machine named pgnode
#  az vm list -d --query "[?name=='pgnode'].[name,publicIps,privateIps,location]"
#
#  This will return a match for any machine with prefix pgnode, ex: pgnode and pgnode2
#  az vm list -d --query "[?starts_with(name,'pgnode')].[name,publicIps,privateIps,location]"
__cloud_FindInstances() {
  case $1 in
    prefix)
      query="[?starts_with(name,'$2')]"
      ;;
    name)
      query="[?name=='$2']"
      ;;
    *)
      echo "Unknown filter command: $1"
      ;;
  esac

  keys="[name,publicIps,privateIps,location]"

  instances=()
  while read -r name publicIp privateIp location; do
    instances+=("$name:$publicIp:$privateIp:$location")
  done < <(az vm list -d -o tsv --query "$query.$keys")
  echo "${instances[*]}"
}

#
# cloud_FindInstances [namePrefix]
#
# Find instances with names matching the specified prefix
#
# For each matching instance, an entry in the `instances` array will be added with the
# following information about the instance:
#   "name:public IP:private IP:location"
#
# namePrefix - The instance name prefix to look for
#
# examples:
#   $ cloud_FindInstances all-machines-with-a-common-machine-prefix
#
cloud_FindInstances() {
  __cloud_FindInstances prefix "$1"
}

#
# cloud_FindInstance [name]
#
# Find an instance with a name matching the exact pattern.
#
# For each matching instance, an entry in the `instances` array will be added with the
# following information about the instance:
#   "name:public IP:private IP:location"
#
# name - The instance name to look for
#
# examples:
#   $ cloud_FindInstance exact-machine-name
#
cloud_FindInstance() {
  __cloud_FindInstances name "$1"
}

#
# cloud_Initialize [networkName]
#
# Perform one-time initialization that may be required for the given testnet.
#
# networkName   - unique name of this testnet
#
# This function will be called before |cloud_CreateInstances|
cloud_Initialize() {
  declare resourceGroup="$1"
  declare location="$2"
  declare nsgName=${resourceGroup}-nsg

  # Check if resource group exists.  If not, create it.
  (
    set -x
    numGroup=$(az group list --query "length([?name=='$resourceGroup'])")
    if [[ $numGroup -eq 0 ]]; then
      echo Resource Group "$resourceGroup" does not exist.  Creating it now.
      az group create --name "$resourceGroup" --location "$location"
    else
      echo Resource group "$resourceGroup" already exists.
      az group show --name "$resourceGroup"
    fi

    az network nsg create --name "$nsgName" --resource-group "$resourceGroup"
  )

  create_nsg_rule() {
    ruleName="$1"
    ports="$2"
    access="$3"
    protocol="$4"
    priority="$5"
    (
      set -x
      az network nsg rule create -g "${resourceGroup}" --nsg-name "${nsgName}" -n "${ruleName}" \
                                 --priority "${priority}" --source-address-prefixes "*" --source-port-ranges "*" \
                                 --destination-address-prefixes "*" --destination-port-ranges "${ports}" --access "${access}" \
                                 --protocol "${protocol}"
    )
  }

  create_nsg_rule "InboundTCP" "8000-10000" "Allow" "Tcp" 1000
  create_nsg_rule "InboundUDP" "8000-10000" "Allow" "Udp" 1001
  create_nsg_rule "InboundHTTP" "80" "Allow" "Tcp" 1002
  create_nsg_rule "InboundNetworkExplorerAPI" "3001" "Allow" "Tcp" 1003
  create_nsg_rule "InboundDrone" "9900" "Allow" "Tcp" 1004
  create_nsg_rule "InboundJsonRpc" "8899-8900" "Allow" "Tcp" 1005
  create_nsg_rule "InboundRsync" "873" "Allow" "Tcp" 1006
  create_nsg_rule "InboundStun" "3478" "Allow" "Udp" 1007
  create_nsg_rule "InboundSSH" "22" "Allow" "Tcp" 1008
}

#
# cloud_CreateInstances [networkName] [namePrefix] [numNodes]
#                       [enableGpu] [machineType] [zone]
#                       [bootDiskSize] [startupScript] [address]
#                       [bootDiskType] [additionalDiskSize] [preemptible]
#
# Creates one more identical instances.
#
# networkName   - unique name of this testnet
# namePrefix    - unique string to prefix all the instance names with
# numNodes      - number of instances to create
# enableGpu     - Optionally enable GPU, use the value "true" to enable
#                 eg, request 4 K80 GPUs with "count=4,type=nvidia-tesla-k80"
# machineType   - GCE machine type.  Note that this may also include an
#                 `--accelerator=` or other |gcloud compute instances create|
#                 options
# zone          - cloud zone
# bootDiskSize  - Optional size of the boot disk in GB
# startupScript - Optional startup script to execute when the instance boots
# address       - Optional name of the GCE static IP address to attach to the
#                 instance.  Requires that |numNodes| = 1 and that addressName
#                 has been provisioned in the GCE region that is hosting `$zone`
# bootDiskType  - Optional specify SSD or HDD boot disk
# additionalDiskSize - Optional specify size of additional storage volume
# preemptible   - Optionally request a preemptible instance ("true")
#
# Tip: use cloud_FindInstances to locate the instances once this function
#      returns
cloud_CreateInstances() {
  declare networkName="$1"
  declare namePrefix="$2"
  declare numNodes="$3"
  declare enableGpu="$4"
  declare machineType="$5"
  declare zone="$6"
  declare optionalBootDiskSize="$7"
  declare optionalStartupScript="$8"
  declare optionalAddress="$9"
  declare optionalBootDiskType="${10}"

  declare -a nodes
  if [[ $numNodes = 1 ]]; then
    nodes=("$namePrefix")
  else
    for node in $(seq -f "${namePrefix}%0${#numNodes}g" 1 "$numNodes"); do
      nodes+=("$node")
    done
  fi
  nsgName=${networkName}-nsg

  declare -a args
  args=(
    --resource-group "$networkName"
    --tags testnet
    --image UbuntuLTS
    --size "$machineType"
    --ssh-key-values "$(cat "${sshPrivateKey}".pub)"
    --location "$zone"
    --nsg "$nsgName"
  )

  if [[ -n $optionalBootDiskSize ]]; then
    args+=(
      --os-disk-size-gb "$optionalBootDiskSize"
    )
  fi
  if [[ -n $optionalStartupScript ]]; then
    args+=(
      --custom-data "$optionalStartupScript"
    )
  fi

  if [[ -n $optionalBootDiskType ]]; then
    args+=(
      --storage-sku "$optionalBootDiskType"
    )
  else
    args+=(
      --storage-sku StandardSSD_LRS
    )
  fi

  if [[ -n $optionalAddress ]]; then
    [[ $numNodes = 1 ]] || {
      echo "Error: address may not be supplied when provisioning multiple nodes: $optionalAddress"
      exit 1
    }
    args+=(
      --public-ip-address "$optionalAddress"
    )
  fi

  (
    set -x

    # For node in numNodes, create VM and put the creation process in the background with --no-wait
    for nodeName in "${nodes[@]}"; do
      az vm create --name "$nodeName" "${args[@]}" --no-wait
    done
    for nodeName in "${nodes[@]}"; do
      az vm wait --created --name "$nodeName" --resource-group "$networkName" --verbose --timeout 600
    done

    # If GPU is to be enabled, install the appropriate extension
    if $enableGpu; then
      for nodeName in "${nodes[@]}"; do
        az vm extension set \
        --resource-group "$networkName" \
        --vm-name "$nodeName" \
        --name NvidiaGpuDriverLinux \
        --publisher Microsoft.HpcCompute \
        --version 1.2 \
        --no-wait
      done

      # Wait until all nodes have GPU extension installed
      for nodeName in "${nodes[@]}"; do
        az vm wait --updated --name "$nodeName" --resource-group "$networkName" --verbose --timeout 600
      done
    fi
  )
}

#
# cloud_DeleteInstances
#
# Deletes all the instances listed in the `instances` array
#
cloud_DeleteInstances() {
  if [[ ${#instances[0]} -eq 0 ]]; then
    echo No instances to delete
    return
  fi

  declare names=("${instances[@]/:*/}")
  (
    set -x
    id_list=()

    # Build a space delimited list of all resource IDs to delete
    for instance in "${names[@]}"; do
      cloud_GetIdFromInstanceName "$instance"
      id_list+=("$id")
    done

    # Delete all instances in the id_list and return once they are all deleted
    az vm delete --ids "${id_list[@]}" --yes --verbose --no-wait
  )
}

#
# cloud_WaitForInstanceReady [instanceName] [instanceIp] [instanceZone] [timeout]
#
# Return once the newly created VM instance is responding.  This function is cloud-provider specific.
#
cloud_WaitForInstanceReady() {
  declare instanceName="$1"
#  declare instanceIp="$2"  # unused
#  declare instanceZone="$3"  # unused
  declare timeout="$4"

  cloud_GetResourceGroupFromInstanceName "$instanceName"
  az vm wait -g "$resourceGroup" -n "$instanceName" --created  --interval 10 --timeout "$timeout"
}

#
# cloud_FetchFile [instanceName] [publicIp] [remoteFile] [localFile]
#
# Fetch a file from the given instance.  This function uses a cloud-specific
# mechanism to fetch the file
#
cloud_FetchFile() {
  declare instanceName="$1"
  declare publicIp="$2"
  declare remoteFile="$3"
  declare localFile="$4"

  cloud_GetConfigValueFromInstanceName "$instanceName" osProfile.adminUsername
  scp "${config_value}@${publicIp}:${remoteFile}" "$localFile"
}

#
# cloud_CreateAndAttachPersistentDisk
#
# Not yet implemented for this cloud provider
cloud_CreateAndAttachPersistentDisk() {
  echo "ERROR: cloud_CreateAndAttachPersistentDisk is not yet implemented for azure"
  exit 1
}

#
# cloud_StatusAll
#
# Not yet implemented for this cloud provider
cloud_StatusAll() {
  echo "ERROR: cloud_StatusAll is not yet implemented for azure"
}
