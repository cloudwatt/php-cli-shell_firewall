<?php
/**
  * /!\ La balise de fermeture de PHP '?>' supprime le saut de ligne qui la suit immédiatement
  * Un double saut de ligne est le workaround le plus simple à mettre en place
  */

	namespace App\Firewall;

	use App\Firewall\Core;
?>

<?php
	if($this->updateMode === $this->UPDATE_MODE_REPLACE)
	{
?>

delete applications
delete security policies
<?php
		foreach($this->zones as $zone)
		{
			if(preg_match('#^__.*__$#i', $zone)) {
				continue;
			}
?>
delete security zones security-zone <?php echo $zone; ?> address-book
<?php
		}
	}

	foreach($this->applications as $protocol)
	{
		if($protocol['protocol'] === 'ip')
		{
?>

set applications application <?php echo $protocol['name']; ?> term TCP protocol tcp;
set applications application <?php echo $protocol['name']; ?> term UDP protocol udp;
set applications application <?php echo $protocol['name']; ?> term ICMP protocol icmp;
<?php
		}
		else
		{
?>

set applications application <?php echo $protocol['name']; ?> protocol <?php echo $protocol['protocol']; ?>
<?php
		}

		if(array_key_exists('options', $protocol))
		{
			switch($protocol['protocol'])
			{
				case 'icmp':
				case 'icmp4':
				case 'icmp6':
				{
					if(array_key_exists('type', $protocol['options']))
					{
						$icmpType = ($protocol['protocol'] === 'icmp6') ? ('icmp6-type') : ('icmp-type');
?>

set applications application <?php echo $protocol['name']; ?> <?php echo $icmpType.' '.$protocol['options']['type']; ?>
<?php
						if(array_key_exists('code', $protocol['options']))
						{
							$icmpCode = ($protocol['protocol'] === 'icmp6') ? ('icmp6-code') : ('icmp-code');
?>

set applications application <?php echo $protocol['name']; ?> <?php echo $icmpCode.' '.$protocol['options']['code']; ?>
<?php
						}
					}

					break;
				}
				default:
				{
?>

set applications application <?php echo $protocol['name']; ?> destination-port <?php echo $protocol['options']; ?>
<?php
				}
			}
		}
	}

	foreach($this->addressBook as $zone => $addresses)
	{
		foreach($addresses as $items)
		{
			// IPv4 & IPv6
			foreach($items as $address)
			{
				if(array_key_exists('__doNotCreateAdd__', $address) && $address['__doNotCreateAdd__']) {
					continue;
				}

				switch($address['type'])
				{
					case Core\Api_Host::OBJECT_TYPE:
					case Core\Api_Subnet::OBJECT_TYPE: {
						break;
					}
					case Core\Api_Network::OBJECT_TYPE: {
						$address['address'] = 'range-address '.implode(' to ', $address['address']);
						break;
					}
					default: {
						throw new Exception("Unknown address type '".$address['type']."'", E_USER_ERROR);
					}
				}
?>

set security zones security-zone <?php echo $zone; ?> address-book address <?php echo $address['name'].' '.$address['address']; ?>
<?php
			}
		}
	}
?>

<?php
	foreach($this->accessLists as $accessList)
	{
?>

<?php
		if($this->updateMode === $this->UPDATE_MODE_MERGE)
		{
?>

delete security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?>
<?php
		}

		if($accessList['description'] !== '')
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> description <?php echo '"'.$accessList['description'].'"'; ?>
<?php
		}

		foreach($accessList['srcAdds'] as $srcAdd)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> match source-address <?php echo $srcAdd; ?>
<?php
		}

		foreach($accessList['dstAdds'] as $dstAdd)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> match destination-address <?php echo $dstAdd; ?>
<?php
		}

		foreach($accessList['protoApps'] as $protoApp)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> match application <?php echo $protoApp; ?>
<?php
		}

		if($accessList['action'] === true)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then permit
<?php
		}
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then log session-init
set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then log session-close
set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then count
<?php
		if($accessList['state'] === true)
		{
?>

activate security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?>
<?php
		}
		else {
?>

deactivate security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?>
<?php
		}
?>


<?php
	}
?>